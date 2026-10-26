package audit_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/audit"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
)

// testKey stands in for the HKDF-derived audit chain key.
var testKey = []byte("0123456789abcdef0123456789abcdef")

func newRepo(t *testing.T) (*audit.Repo, storage.Store) {
	t.Helper()
	dsn := storagetest.DSN(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := storage.Open(ctx, storage.Options{DSN: dsn})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return audit.NewRepo(s.DB(), testKey), s
}

func TestAppendChainsFromEmptyRoot(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	ctx := context.Background()

	e1, err := r.Append(ctx, "request.accepted", "alice@example.com", "", map[string]any{"k": "v"})
	if err != nil {
		t.Fatalf("first Append: %v", err)
	}
	if e1.PrevHash != "" {
		t.Errorf("first PrevHash = %q, want empty", e1.PrevHash)
	}
	if len(e1.EntryHash) != 64 {
		t.Errorf("EntryHash length = %d, want 64", len(e1.EntryHash))
	}

	e2, err := r.Append(ctx, "request.accepted", "bob@example.com", "", nil)
	if err != nil {
		t.Fatalf("second Append: %v", err)
	}
	if e2.PrevHash != e1.EntryHash {
		t.Errorf("PrevHash linkage broken: %q vs %q", e2.PrevHash, e1.EntryHash)
	}
}

func TestAppendRejectsEmptyEventType(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	if _, err := r.Append(context.Background(), "", "a", "", nil); err == nil {
		t.Fatal("expected error for empty event_type")
	}
}

func TestVerifyChainOnIntactLog(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_, err := r.Append(ctx, audit.EventTokenIssued, "user", "tok", map[string]any{"i": i})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	bad, err := r.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if bad != 0 {
		t.Fatalf("chain reported bad row at %d, want 0 (intact)", bad)
	}
}

func TestVerifyChainDetectsTamper(t *testing.T) {
	t.Parallel()
	r, s := newRepo(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := r.Append(ctx, "evt", "actor", "target", map[string]any{"i": i}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	// Forge a row in the middle.
	if _, err := s.DB().ExecContext(ctx,
		storage.Rebind(s.DB(), "UPDATE audit_log SET target = ? WHERE sequence_no = ?"), "TAMPERED", 2); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	bad, err := r.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if bad != 2 {
		t.Fatalf("VerifyChain bad row = %d, want 2 (the tampered one)", bad)
	}
}

func TestCountReturnsRowCount(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		_, _ = r.Append(ctx, "evt", "", "", nil)
	}
	n, err := r.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 4 {
		t.Fatalf("Count = %d, want 4", n)
	}
}

func TestVerifyChainUnderConcurrentAppends(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	ctx := context.Background()
	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.Append(ctx, "evt", "actor", "", map[string]any{"i": i}); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("Append: %v", err)
	}
	bad, err := r.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if bad != 0 {
		t.Fatalf("chain reported bad row at %d after concurrent appends, want 0", bad)
	}
}

// Rows written before Append truncated occurred_at to microseconds carry
// full nanoseconds in SQLite's TEXT column, and their hash covers them.
// They must keep verifying alongside rows written today.
func TestVerifyChainAcceptsLegacyNanosecondRows(t *testing.T) {
	t.Parallel()
	r, s := newRepo(t)
	if storage.IsPostgres(s.DB()) {
		t.Skip("legacy nanosecond rows only ever existed on SQLite")
	}
	ctx := context.Background()
	occurred := time.Date(2026, 5, 1, 12, 0, 0, 123456789, time.UTC)
	details := "{}"
	canonical := occurred.Format(time.RFC3339Nano) + "\nevt\nactor\n\n" + details
	sum := sha256.Sum256([]byte("\n" + canonical))
	if _, err := s.DB().ExecContext(ctx,
		`INSERT INTO audit_log (occurred_at, event_type, actor, target, details_json, prev_hash, entry_hash)
		 VALUES (?, 'evt', 'actor', NULL, ?, '', ?)`,
		occurred, details, hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	// Migration 0014 records the pre-existing rows as legacy; the server
	// then seals the anchor at startup.
	if _, err := s.DB().ExecContext(ctx,
		`UPDATE audit_head SET legacy_until = (SELECT MAX(sequence_no) FROM audit_log)`); err != nil {
		t.Fatalf("set legacy_until: %v", err)
	}
	if err := r.SealAnchor(ctx, true); err != nil {
		t.Fatalf("SealAnchor: %v", err)
	}
	if _, err := r.Append(ctx, "evt", "actor", "", nil); err != nil {
		t.Fatalf("Append: %v", err)
	}
	bad, err := r.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if bad != 0 {
		t.Fatalf("chain reported bad row at %d, want 0 (legacy row + new row)", bad)
	}
}
