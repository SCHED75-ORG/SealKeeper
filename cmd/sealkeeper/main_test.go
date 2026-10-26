package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/sched75/sealkeeper/internal/admin"
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
