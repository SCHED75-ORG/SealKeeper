package demo_test

import (
	"context"
	"testing"
	"time"

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
