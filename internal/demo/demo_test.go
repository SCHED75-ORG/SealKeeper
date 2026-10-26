package demo_test

import (
	"context"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/audit"
	"github.com/sched75/sealkeeper/internal/demo"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
)

func openStore(t *testing.T) storage.Store {
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
	return s
}

func TestResetOnceWipesAdminState(t *testing.T) {
	t.Parallel()
	s := openStore(t)
	db := s.DB()
	ctx := context.Background()

	// Seed a row in each table that the resetter should wipe. We don't
	// care about referential integrity here — we just want non-empty
	// rows to assert against after the reset.
	if _, err := db.ExecContext(ctx, `INSERT INTO domains (name) VALUES ('example.com')`); err != nil {
		t.Fatalf("seed domains: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO captured_mail (to_addr, subject, body) VALUES ('x@y.test','s','b')`); err != nil {
		t.Fatalf("seed captured_mail: %v", err)
	}

	r := demo.NewResetter(db, nil, time.Hour)
	r.ResetOnce(ctx)

	for _, table := range []string{"domains", "captured_mail"} {
		var n int64
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%s left with %d rows after reset", table, n)
		}
	}
}

// The reset wipes audit_log; the head anchor must be reset with it, or the
// next integrity check reports the wipe as a truncated tail.
func TestResetOnceLeavesAuditChainIntact(t *testing.T) {
	t.Parallel()
	s := openStore(t)
	ctx := context.Background()
	ar := audit.NewRepo(s.DB(), make([]byte, audit.KeySize))
	for i := 0; i < 3; i++ {
		if _, err := ar.Append(ctx, "domain.created", "admin@localhost", "", nil); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	demo.NewResetter(s.DB(), nil, time.Hour).ResetOnce(ctx)
	if bad, err := ar.VerifyChain(ctx); err != nil || bad != 0 {
		t.Fatalf("after reset: VerifyChain = %d, %v; want intact", bad, err)
	}
	if _, err := ar.Append(ctx, "admin.login", "admin@localhost", "", nil); err != nil {
		t.Fatalf("Append after reset: %v", err)
	}
	if bad, err := ar.VerifyChain(ctx); err != nil || bad != 0 {
		t.Fatalf("after reset + append: VerifyChain = %d, %v; want intact", bad, err)
	}
}

func TestRunHonoursContextCancel(t *testing.T) {
	t.Parallel()
	s := openStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	r := demo.NewResetter(s.DB(), nil, 10*time.Millisecond)
	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()
	time.Sleep(35 * time.Millisecond) // let a couple of ticks fire
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}
