package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sched75/sealkeeper/internal/admin"
	"github.com/sched75/sealkeeper/internal/audit"
)

// SK-26: when no active admin is left, `sealkeeper admin enable` is the
// way back in.
func TestAdminEnableRecoversZeroActiveAdmins(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SK_MODE", "eval")
	t.Setenv("SK_MASTER_SECRET", base64.StdEncoding.EncodeToString(key))
	t.Setenv("SK_DATABASE_URL", "sqlite://"+filepath.ToSlash(filepath.Join(t.TempDir(), "sk.db")))

	ctx := context.Background()
	repo, cleanup, err := openAdminRepo(ctx)
	if err != nil {
		t.Fatalf("openAdminRepo: %v", err)
	}
	defer cleanup()
	a, err := repo.Create(ctx, "ops@example.test", "supersecret-12chars")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Simulate the state the old racy guard could leave behind.
	if _, err := repo.DB().ExecContext(ctx, `UPDATE admins SET disabled_at = CURRENT_TIMESTAMP`); err != nil {
		t.Fatalf("disable all: %v", err)
	}

	if code := runAdminEnable([]string{"--email", "ops@example.test"}); code != 0 {
		t.Fatalf("runAdminEnable exit = %d, want 0", code)
	}
	got, err := repo.FindByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Disabled {
		t.Error("admin still disabled after `admin enable`")
	}
	if code := runAdminEnable([]string{"--email", "nobody@example.test"}); code != 1 {
		t.Errorf("unknown email exit = %d, want 1", code)
	}
	if code := runAdminEnable(nil); code != 2 {
		t.Errorf("missing --email exit = %d, want 2", code)
	}
}

// Generated bootstrap / reset-password passwords go through
// ResetForBootstrap, which enforces the operator policy: every draw must
// clear it. Before the redraw loop, about 0.3% of draws lacked a third
// character class and made `admin reset-password` fail.
func TestRandomPasswordAlwaysClearsPolicy(t *testing.T) {
	t.Parallel()
	for i := 0; i < 3000; i++ {
		pwd, err := randomPassword(20)
		if err != nil {
			t.Fatalf("randomPassword: %v", err)
		}
		if len(pwd) != 20 {
			t.Fatalf("len = %d, want 20", len(pwd))
		}
		if err := admin.ValidateAdminPassword(pwd); err != nil {
			t.Fatalf("draw %d %v", i, err)
		}
	}
}

// auditEvents returns "event|actor|target|details" for every audit row,
// oldest first, and fails the test unless the keyed chain still verifies.
func auditEvents(t *testing.T, db *sql.DB, secret string) []string {
	t.Helper()
	ctx := context.Background()
	key, err := audit.DeriveKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	if broken, err := audit.NewRepo(db, key).VerifyChain(ctx); err != nil || broken != 0 {
		t.Fatalf("VerifyChain = %d, %v; want intact keyed chain", broken, err)
	}
	rows, err := db.QueryContext(ctx, `SELECT event_type, COALESCE(actor, ''), COALESCE(target, ''), details_json FROM audit_log ORDER BY sequence_no`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var evt, actor, target, details string
		if err := rows.Scan(&evt, &actor, &target, &details); err != nil {
			t.Fatal(err)
		}
		out = append(out, evt+"|"+actor+"|"+target+"|"+details)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func countEvents(events []string, prefix string) int {
	n := 0
	for _, e := range events {
		if strings.HasPrefix(e, prefix) {
			n++
		}
	}
	return n
}

// Out-of-band CLI actions (docker exec) must land in the keyed audit
// chain: an unaudited reset-password was an invisible credential reset.
func TestCLIStateChangesAreAudited(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	secret := base64.StdEncoding.EncodeToString(key)
	t.Setenv("SK_MODE", "production")
	t.Setenv("SK_BASE_URL", "https://sk.example.test")
	t.Setenv("SK_MASTER_SECRET", secret)
	t.Setenv("SK_DATABASE_URL", "sqlite://"+filepath.ToSlash(filepath.Join(t.TempDir(), "sk.db")))

	if code := runMigrate([]string{"up"}); code != 0 {
		t.Fatalf("migrate up exit = %d", code)
	}
	ctx := context.Background()
	repo, cleanup, err := openAdminRepo(ctx)
	if err != nil {
		t.Fatalf("openAdminRepo: %v", err)
	}
	defer cleanup()
	events := auditEvents(t, repo.DB(), secret)
	if countEvents(events, "schema.migrated|cli|") != 1 {
		t.Fatalf("migrate up not audited: %q", events)
	}
	// A no-op migrate changes nothing and records nothing.
	if code := runMigrate([]string{"up"}); code != 0 {
		t.Fatalf("second migrate up exit = %d", code)
	}
	if n := countEvents(auditEvents(t, repo.DB(), secret), "schema.migrated|"); n != 1 {
		t.Fatalf("no-op migrate audited: %d schema.migrated rows", n)
	}

	if _, err := repo.Create(ctx, "ops@example.test", "supersecret-12chars"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	const pwd = "Zq8!vN3#kR7@wT2$mX5&"
	if code := runAdminResetPassword([]string{"--email", "ops@example.test", "--password", pwd}); code != 0 {
		t.Fatalf("reset-password exit = %d", code)
	}
	events = auditEvents(t, repo.DB(), secret)
	if countEvents(events, "admin.password_reset|cli|ops@example.test|") != 1 {
		t.Fatalf("reset-password not audited: %q", events)
	}
	for _, e := range events {
		if strings.Contains(e, pwd) {
			t.Fatalf("password leaked into audit row %q", e)
		}
	}
}

// The serve-time bootstrap admin is a credential mint: audit it once.
func TestBootstrapAdminIsAudited(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	secret := base64.StdEncoding.EncodeToString(key)
	t.Setenv("SK_MODE", "eval")
	t.Setenv("SK_MASTER_SECRET", secret)
	t.Setenv("SK_DATABASE_URL", "sqlite://"+filepath.ToSlash(filepath.Join(t.TempDir(), "sk.db")))
	ctx := context.Background()
	repo, cleanup, err := openAdminRepo(ctx)
	if err != nil {
		t.Fatalf("openAdminRepo: %v", err)
	}
	defer cleanup()
	ak, err := audit.DeriveKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for i := 0; i < 2; i++ {
		if err := bootstrapAdminIfNeeded(ctx, repo, audit.NewRepo(repo.DB(), ak), logger, true); err != nil {
			t.Fatalf("bootstrap: %v", err)
		}
	}
	events := auditEvents(t, repo.DB(), secret)
	if countEvents(events, "admin.bootstrapped|system|admin@localhost|") != 1 {
		t.Fatalf("bootstrap admin not audited exactly once: %q", events)
	}
}
