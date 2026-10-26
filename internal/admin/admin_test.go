package admin_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/admin"
	"github.com/sched75/sealkeeper/internal/cryptobox"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/totp"
)

func newRepo(t *testing.T) *admin.Repo {
	t.Helper()
	dir := t.TempDir()
	dsn := "sqlite://" + filepath.ToSlash(filepath.Join(dir, "a.db"))
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

	// admin.NewRepo requires a cryptobox.Box — even though the management
	// tests in this file never exercise TOTP encryption, the constructor
	// asserts non-nil so we mint a throwaway 32-byte key here.
	keyBuf := make([]byte, 32)
	if _, err := rand.Read(keyBuf); err != nil {
		t.Fatalf("rand: %v", err)
	}
	box, err := cryptobox.New(base64.StdEncoding.EncodeToString(keyBuf))
	if err != nil {
		t.Fatalf("cryptobox.New: %v", err)
	}
	return admin.NewRepo(s.DB(), box)
}

func TestCreateRejectsInvalidEmail(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	_, err := r.Create(context.Background(), "not-an-email", "supersecret-12chars")
	if !errors.Is(err, admin.ErrInvalidEmail) {
		t.Fatalf("err = %v, want ErrInvalidEmail", err)
	}
}

func TestCreateRejectsDuplicate(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	if _, err := r.Create(ctx, "ops@example.test", "supersecret-12chars"); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	_, err := r.Create(ctx, "OPS@example.test", "supersecret-12chars")
	if !errors.Is(err, admin.ErrAlreadyExists) {
		t.Fatalf("dup Create err = %v, want ErrAlreadyExists", err)
	}
}

func TestChangeEmail(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	a, err := r.Create(ctx, "old@example.test", "supersecret-12chars")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := r.ChangeEmail(ctx, a.ID, "new@example.test"); err != nil {
		t.Fatalf("ChangeEmail: %v", err)
	}
	got, err := r.FindByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Email != "new@example.test" {
		t.Errorf("Email = %q, want new@example.test", got.Email)
	}
	if err := r.ChangeEmail(ctx, a.ID, "not-an-email"); !errors.Is(err, admin.ErrInvalidEmail) {
		t.Errorf("ChangeEmail invalid err = %v, want ErrInvalidEmail", err)
	}
	if err := r.ChangeEmail(ctx, 999_999, "anyone@example.test"); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("ChangeEmail missing id err = %v, want ErrNotFound", err)
	}
}

func TestChangeEmailRejectsDuplicate(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	a, _ := r.Create(ctx, "first@example.test", "supersecret-12chars")
	if _, err := r.Create(ctx, "second@example.test", "supersecret-12chars"); err != nil {
		t.Fatalf("Create second: %v", err)
	}
	if err := r.ChangeEmail(ctx, a.ID, "second@example.test"); !errors.Is(err, admin.ErrAlreadyExists) {
		t.Errorf("ChangeEmail dup err = %v, want ErrAlreadyExists", err)
	}
}

func TestSetDisabledLastActiveGuard(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	a, _ := r.Create(ctx, "only@example.test", "supersecret-12chars")

	if err := r.SetDisabled(ctx, a.ID, true); !errors.Is(err, admin.ErrLastActiveAdmin) {
		t.Fatalf("first SetDisabled err = %v, want ErrLastActiveAdmin", err)
	}
	// Add a second admin then disable the first — should succeed.
	if _, err := r.Create(ctx, "second@example.test", "supersecret-12chars"); err != nil {
		t.Fatalf("Create second: %v", err)
	}
	if err := r.SetDisabled(ctx, a.ID, true); err != nil {
		t.Fatalf("SetDisabled with backup: %v", err)
	}
}

func TestDeleteLastActiveGuard(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	a, _ := r.Create(ctx, "alone@example.test", "supersecret-12chars")
	if err := r.Delete(ctx, a.ID); !errors.Is(err, admin.ErrLastActiveAdmin) {
		t.Errorf("Delete last active err = %v, want ErrLastActiveAdmin", err)
	}
}

func TestListReturnsCreatedAdmins(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	for _, e := range []string{"one@example.test", "two@example.test", "three@example.test"} {
		if _, err := r.Create(ctx, e, "supersecret-12chars"); err != nil {
			t.Fatalf("Create %s: %v", e, err)
		}
	}
	list, err := r.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 3 {
		t.Errorf("List = %d rows, want 3", len(list))
	}
}

// enrolledAdmin creates an admin with a TOTP secret on a frozen clock and
// returns the repo, the secret and a 6-digit code Verify rejects at that
// instant.
func enrolledAdmin(t *testing.T, email, password string) (*admin.Repo, totp.Secret, string) {
	t.Helper()
	at := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	r := newRepo(t).WithClock(func() time.Time { return at })
	ctx := context.Background()
	a, err := r.Create(ctx, email, password)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	secret, err := totp.NewSecret()
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	if err := r.EnrollTOTP(ctx, a.ID, secret, []string{"aaaa-bbbb"}); err != nil {
		t.Fatalf("EnrollTOTP: %v", err)
	}
	for n := 0; n < 1_000_000; n++ {
		code := fmt.Sprintf("%06d", n)
		if ok, _ := totp.Verify(secret, code, at); !ok {
			return r, secret, code
		}
	}
	t.Fatal("no rejected code found")
	return nil, "", ""
}

// Regression: a correct password used to reset the failure counter before
// the TOTP check, so wrong TOTP codes never reached MaxFailedAttempts.
func TestAuthenticateWrongTOTPLocksAccount(t *testing.T) {
	t.Parallel()
	const email, pw = "ops@example.test", "supersecret-12chars"
	r, _, bad := enrolledAdmin(t, email, pw)
	ctx := context.Background()
	for i := 0; i < admin.MaxFailedAttempts; i++ {
		if _, err := r.Authenticate(ctx, email, pw, bad); !errors.Is(err, admin.ErrInvalidCreds) {
			t.Fatalf("attempt %d: err = %v, want ErrInvalidCreds", i+1, err)
		}
	}
	if _, err := r.Authenticate(ctx, email, pw, bad); !errors.Is(err, admin.ErrAccountLocked) {
		t.Fatalf("after %d wrong TOTP codes: err = %v, want ErrAccountLocked", admin.MaxFailedAttempts, err)
	}
}

// Regression: a correct password with an empty TOTP field must not reset
// the counter either, or an attacker interleaves blank submissions.
func TestAuthenticateBlankTOTPDoesNotResetCounter(t *testing.T) {
	t.Parallel()
	const email, pw = "ops@example.test", "supersecret-12chars"
	r, _, bad := enrolledAdmin(t, email, pw)
	ctx := context.Background()
	for i := 0; i < admin.MaxFailedAttempts; i++ {
		if _, err := r.Authenticate(ctx, email, pw, ""); !errors.Is(err, admin.ErrTOTPRequired) {
			t.Fatalf("blank attempt: err = %v, want ErrTOTPRequired", err)
		}
		if _, err := r.Authenticate(ctx, email, pw, bad); err != nil && !errors.Is(err, admin.ErrInvalidCreds) && !errors.Is(err, admin.ErrAccountLocked) {
			t.Fatalf("attempt %d: unexpected err %v", i+1, err)
		}
	}
	if _, err := r.Authenticate(ctx, email, pw, bad); !errors.Is(err, admin.ErrAccountLocked) {
		t.Fatalf("err = %v, want ErrAccountLocked", err)
	}
}

func TestAuthenticateSuccessResetsCounter(t *testing.T) {
	t.Parallel()
	const email, pw = "ops@example.test", "supersecret-12chars"
	r, secret, bad := enrolledAdmin(t, email, pw)
	ctx := context.Background()
	for i := 0; i < admin.MaxFailedAttempts-1; i++ {
		_, _ = r.Authenticate(ctx, email, pw, bad)
	}
	good, err := totp.Generate(secret, time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := r.Authenticate(ctx, email, pw, good); err != nil {
		t.Fatalf("valid login: %v", err)
	}
	// Counter cleared: MaxFailedAttempts-1 more failures must not lock.
	for i := 0; i < admin.MaxFailedAttempts-1; i++ {
		if _, err := r.Authenticate(ctx, email, pw, bad); !errors.Is(err, admin.ErrInvalidCreds) {
			t.Fatalf("attempt %d after success: err = %v, want ErrInvalidCreds", i+1, err)
		}
	}
}
