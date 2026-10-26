package storage

import (
	"context"
	"testing"
	"time"

	"github.com/pressly/goose/v3"

	"github.com/sched75/sealkeeper/internal/storage/storagetest"
)

// Regression (revealtokens): rows written before 0017 carried the raw
// reveal token. The upgrade must not leave one behind, on either dialect,
// and the lookup column must hold digests from then on.
func TestMigration0017DropsClearRevealTokens(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), storagetest.SetupTimeout)
	defer cancel()
	st, err := Open(ctx, Options{DSN: storagetest.DSN(t)})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s := st.(*sqlStore)
	migrations, err := migrationsSub(s.dialect)
	if err != nil {
		t.Fatal(err)
	}
	gd, err := gooseDialectFor(s.dialect)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(gd, s.db, migrations)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(ctx, 15); err != nil {
		t.Fatalf("UpTo 15: %v", err)
	}
	const raw = "G3l_uEXn3ts6UWPQJgKL9GYOkoR6yTntMILn5pAskbo"
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, Rebind(s.db,
		`INSERT INTO request_tokens (token, email, domain, issued_at, expires_at) VALUES (?, ?, ?, ?, ?)`),
		raw, "user@example.test", "example.test", now, now.Add(time.Hour)); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}
	if err := st.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM request_tokens`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d pre-0017 request_tokens rows survived the upgrade", n)
	}
	if _, err := s.db.ExecContext(ctx, `SELECT token_hash FROM request_tokens`); err != nil {
		t.Fatalf("token_hash column missing after 0017: %v", err)
	}
}
