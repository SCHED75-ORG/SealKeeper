package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/audit"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
)

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
	return audit.NewRepo(s.DB()), s
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
	if _, err := s.DB().ExecContext(ctx, "UPDATE audit_log SET target = ? WHERE sequence_no = ?", "TAMPERED", 2); err != nil {
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
