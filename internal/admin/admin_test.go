package admin_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/admin"
	"github.com/sched75/sealkeeper/internal/cryptobox"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
	"github.com/sched75/sealkeeper/internal/totp"
)

func newRepo(t *testing.T) *admin.Repo {
	t.Helper()
	dsn := storagetest.DSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), storagetest.SetupTimeout)
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

// The login handler drops any email over MaxEmailBytes unread, so no
// account may be created or renamed past it.
func TestEmailCappedAtMaxEmailBytes(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	at := "@example.test"
	fits := strings.Repeat("a", admin.MaxEmailBytes-len(at)) + at
	a, err := r.Create(ctx, fits, "supersecret-12chars")
	if err != nil {
		t.Fatalf("Create %d-byte email: %v", len(fits), err)
	}
	over := "b" + fits
	if _, err := r.Create(ctx, over, "supersecret-12chars"); !errors.Is(err, admin.ErrInvalidEmail) {
		t.Errorf("Create %d-byte email err = %v, want ErrInvalidEmail", len(over), err)
	}
	if err := r.ChangeEmail(ctx, a.ID, over); !errors.Is(err, admin.ErrInvalidEmail) {
		t.Errorf("ChangeEmail %d-byte email err = %v, want ErrInvalidEmail", len(over), err)
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

func TestLastActiveGuardMissingAdmin(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	if _, err := r.Create(ctx, "keep@example.test", "supersecret-12chars"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := r.SetDisabled(ctx, 9999, true); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("SetDisabled(missing) = %v, want ErrNotFound", err)
	}
	if err := r.Delete(ctx, 9999); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("Delete(missing) = %v, want ErrNotFound", err)
	}
}

// SK-26: two admins disabling or deleting each other at the same moment
// must not both succeed. Before the guard was atomic, every round ended
// with zero active admins.
func TestLastActiveGuardIsAtomic(t *testing.T) {
	t.Parallel()
	ops := map[string]func(r *admin.Repo, ctx context.Context, id int64) error{
		"disable": func(r *admin.Repo, ctx context.Context, id int64) error { return r.SetDisabled(ctx, id, true) },
		"delete":  func(r *admin.Repo, ctx context.Context, id int64) error { return r.Delete(ctx, id) },
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := newRepo(t)
			ctx := context.Background()
			ids := make([]int64, 2)
			for k := range ids {
				a, err := r.Create(ctx, fmt.Sprintf("%s%d@example.test", name, k), "supersecret-12chars")
				if err != nil {
					t.Fatalf("Create: %v", err)
				}
				ids[k] = a.ID
			}
			for round := 0; round < 25; round++ {
				start := make(chan struct{})
				errs := make([]error, 2)
				var wg sync.WaitGroup
				for k := range ids {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						errs[k] = op(r, ctx, ids[k])
					}()
				}
				close(start)
				wg.Wait()

				active, err := r.ActiveCount(ctx)
				if err != nil {
					t.Fatalf("ActiveCount: %v", err)
				}
				if active != 1 {
					t.Fatalf("round %d: active = %d after errs %v, want 1", round, active, errs)
				}
				ok := 0
				for k, e := range errs {
					switch {
					case e == nil:
						ok++
						// Restore two active admins for the next round.
						if name == "disable" {
							if err := r.SetDisabled(ctx, ids[k], false); err != nil {
								t.Fatalf("re-enable: %v", err)
							}
						} else {
							a, err := r.Create(ctx, fmt.Sprintf("%s-r%d@example.test", name, round), "supersecret-12chars")
							if err != nil {
								t.Fatalf("Create: %v", err)
							}
							ids[k] = a.ID
						}
					case !errors.Is(e, admin.ErrLastActiveAdmin):
						t.Fatalf("round %d: unexpected error %v", round, e)
					}
				}
				if ok != 1 {
					t.Fatalf("round %d: %d operations succeeded, want exactly 1", round, ok)
				}
			}
		})
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
	codes := []string{"", bad}
	for i := 0; i < 2*admin.MaxFailedAttempts; i++ {
		_, err := r.Authenticate(ctx, email, pw, codes[i%2])
		if errors.Is(err, admin.ErrAccountLocked) {
			if i < admin.MaxFailedAttempts {
				t.Fatalf("locked after only %d attempts", i)
			}
			return
		}
	}
	t.Fatal("interleaving blank and wrong TOTP codes never locked the account")
}

// Regression: the lock was checked on a snapshot and the counter bumped
// after verification, so a concurrent burst got ~57 guesses evaluated
// instead of MaxFailedAttempts.
func TestAuthenticateConcurrentBurstEvaluatesAtMostMax(t *testing.T) {
	t.Parallel()
	const email, pw = "ops@example.test", "supersecret-12chars"
	r, _, bad := enrolledAdmin(t, email, pw)
	ctx := context.Background()
	const burst = 40
	errs := make(chan error, burst)
	var wg sync.WaitGroup
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.Authenticate(ctx, email, pw, bad)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	evaluated := 0
	for err := range errs {
		if errors.Is(err, admin.ErrInvalidCreds) {
			evaluated++
		}
	}
	if evaluated > admin.MaxFailedAttempts {
		t.Fatalf("%d guesses evaluated in a burst, want <= %d", evaluated, admin.MaxFailedAttempts)
	}
	if _, err := r.Authenticate(ctx, email, pw, bad); !errors.Is(err, admin.ErrAccountLocked) {
		t.Fatalf("after the burst: err = %v, want ErrAccountLocked", err)
	}
}

func TestAuthenticateLockExpires(t *testing.T) {
	t.Parallel()
	const email, pw = "ops@example.test", "supersecret-12chars"
	r, secret, bad := enrolledAdmin(t, email, pw)
	ctx := context.Background()
	for i := 0; i < admin.MaxFailedAttempts; i++ {
		_, _ = r.Authenticate(ctx, email, pw, bad)
	}
	if _, err := r.Authenticate(ctx, email, pw, bad); !errors.Is(err, admin.ErrAccountLocked) {
		t.Fatalf("err = %v, want ErrAccountLocked", err)
	}
	later := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC).Add(admin.LockoutDuration + time.Minute)
	r2 := r.WithClock(func() time.Time { return later })
	good, err := totp.Generate(secret, later)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := r2.Authenticate(ctx, email, pw, good); err != nil {
		t.Fatalf("login after lock expiry: %v", err)
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

// Regression: a valid TOTP code was accepted again for its whole ±30 s
// window, so an observed or intercepted code could be replayed.
func TestAuthenticateRejectsReplayedTOTP(t *testing.T) {
	t.Parallel()
	const email, pw = "ops@example.test", "supersecret-12chars"
	r, secret, _ := enrolledAdmin(t, email, pw)
	ctx := context.Background()
	at := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	code, err := totp.Generate(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Authenticate(ctx, email, pw, code); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := r.Authenticate(ctx, email, pw, code); !errors.Is(err, admin.ErrInvalidCreds) {
		t.Fatalf("replay: err = %v, want ErrInvalidCreds", err)
	}
	// An earlier-step code that is still inside the drift window is refused too.
	prev, _ := totp.Generate(secret, at.Add(-30*time.Second))
	if _, err := r.Authenticate(ctx, email, pw, prev); !errors.Is(err, admin.ErrInvalidCreds) {
		t.Fatalf("older step after a newer one: err = %v, want ErrInvalidCreds", err)
	}
	next, _ := totp.Generate(secret, at.Add(30*time.Second))
	r2 := r.WithClock(func() time.Time { return at.Add(30 * time.Second) })
	if _, err := r2.Authenticate(ctx, email, pw, next); err != nil {
		t.Fatalf("next step: %v", err)
	}
}

// Regression: recovery codes were shown at enrolment but no login path
// accepted them. They now replace a TOTP code once each.
func TestAuthenticateAcceptsRecoveryCodeOnce(t *testing.T) {
	t.Parallel()
	const email, pw = "ops@example.test", "supersecret-12chars"
	r, _, _ := enrolledAdmin(t, email, pw)
	ctx := context.Background()
	a, err := r.FindByEmail(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.EnrollTOTP(ctx, a.ID, "JBSWY3DPEHPK3PXP", []string{"AB3K9-7M2VX", "ZZZZZ-YYYYY"}); err != nil {
		t.Fatal(err)
	}
	res, err := r.Authenticate(ctx, email, pw, "ab3k9-7m2vx")
	if err != nil || !res.UsedRecoveryCode {
		t.Fatalf("recovery login: res=%+v err=%v", res, err)
	}
	if _, err := r.Authenticate(ctx, email, pw, "AB3K9-7M2VX"); !errors.Is(err, admin.ErrInvalidCreds) {
		t.Fatalf("reused recovery code: err = %v, want ErrInvalidCreds", err)
	}
}

// Regression: the setup wizard enrolled whatever totp_secret and
// recovery_codes the browser posted. They now travel sealed and bound to
// the admin and session.
func TestSetupBlobIsBoundAndTamperProof(t *testing.T) {
	t.Parallel()
	r, _, _ := enrolledAdmin(t, "ops@example.test", "supersecret-12chars")
	blob, err := r.SealSetup(7, "sess-a", "JBSWY3DPEHPK3PXP", []string{"AB3K9-7M2VX"})
	if err != nil {
		t.Fatal(err)
	}
	if sec, codes, err := r.OpenSetup(7, "sess-a", blob); err != nil || sec != "JBSWY3DPEHPK3PXP" || len(codes) != 1 {
		t.Fatalf("OpenSetup = %q %v %v", sec, codes, err)
	}
	if _, _, err := r.OpenSetup(7, "sess-b", blob); err == nil {
		t.Error("blob accepted for another session")
	}
	if _, _, err := r.OpenSetup(8, "sess-a", blob); err == nil {
		t.Error("blob accepted for another admin")
	}
	if _, _, err := r.OpenSetup(7, "sess-a", blob[:len(blob)-2]+"AA"); err == nil {
		t.Error("tampered blob accepted")
	}
}

// Regression: admin_sessions stored the bearer token verbatim, so a DB dump
// or backup yielded working session cookies.
func TestSessionTokenStoredHashed(t *testing.T) {
	t.Parallel()
	r, _, _ := enrolledAdmin(t, "ops@example.test", "supersecret-12chars")
	ctx := context.Background()
	a, _ := r.FindByEmail(ctx, "ops@example.test")
	sess, err := r.CreateSession(ctx, a.ID, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var stored, csrf string
	if err := r.DB().QueryRowContext(ctx, "SELECT token, csrf_token FROM admin_sessions").Scan(&stored, &csrf); err != nil {
		t.Fatal(err)
	}
	if stored == sess.Token || csrf == sess.CSRFToken || strings.Contains(stored, sess.Token) {
		t.Fatalf("session secrets stored in clear: token=%q csrf=%q", stored, csrf)
	}
	got, _, err := r.LookupSession(ctx, sess.Token)
	if err != nil || got.CSRFToken != sess.CSRFToken {
		t.Fatalf("LookupSession = %+v, %v", got, err)
	}
	if _, _, err := r.LookupSession(ctx, stored); err == nil {
		t.Fatal("the stored hash works as a session token")
	}
}

func TestRevokeOtherSessionsAndDisable(t *testing.T) {
	t.Parallel()
	r, _, _ := enrolledAdmin(t, "ops@example.test", "supersecret-12chars")
	ctx := context.Background()
	if _, err := r.Create(ctx, "second@example.test", "supersecret-12chars"); err != nil {
		t.Fatal(err)
	}
	a, _ := r.FindByEmail(ctx, "ops@example.test")
	keep, _ := r.CreateSession(ctx, a.ID, "", "")
	stolen, _ := r.CreateSession(ctx, a.ID, "", "")
	if err := r.RevokeOtherSessions(ctx, a.ID, keep.Token); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.LookupSession(ctx, keep.Token); err != nil {
		t.Fatalf("kept session revoked: %v", err)
	}
	if _, _, err := r.LookupSession(ctx, stolen.Token); err == nil {
		t.Fatal("other session survived RevokeOtherSessions")
	}
	// Regression: disable only suspended sessions; re-enabling revived them.
	if err := r.SetDisabled(ctx, a.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := r.SetDisabled(ctx, a.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.LookupSession(ctx, keep.Token); err == nil {
		t.Fatal("session revived after disable + re-enable")
	}
}

func TestVerifyPasswordCountsFailures(t *testing.T) {
	t.Parallel()
	r, _, _ := enrolledAdmin(t, "ops@example.test", "supersecret-12chars")
	ctx := context.Background()
	a, _ := r.FindByEmail(ctx, "ops@example.test")
	if err := r.VerifyPassword(ctx, a.ID, "supersecret-12chars"); err != nil {
		t.Fatalf("correct password: %v", err)
	}
	var last error
	for i := 0; i <= admin.MaxFailedAttempts; i++ {
		last = r.VerifyPassword(ctx, a.ID, "wrong")
	}
	if !errors.Is(last, admin.ErrAccountLocked) {
		t.Fatalf("after repeated step-up failures: %v, want ErrAccountLocked", last)
	}
}

// Regression: the step-up check never cleared an expired lockout, so a
// lock started at /admin/login refused every sensitive action of an
// already logged-in admin until they signed in again.
func TestVerifyPasswordLockExpires(t *testing.T) {
	t.Parallel()
	const email, pw = "ops@example.test", "supersecret-12chars"
	r, _, bad := enrolledAdmin(t, email, pw)
	ctx := context.Background()
	a, err := r.FindByEmail(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < admin.MaxFailedAttempts; i++ {
		if _, err := r.Authenticate(ctx, email, "wrong-password", bad); !errors.Is(err, admin.ErrInvalidCreds) {
			t.Fatalf("attempt %d: err = %v, want ErrInvalidCreds", i+1, err)
		}
	}
	at := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC) // enrolledAdmin's clock
	during := r.WithClock(func() time.Time { return at.Add(admin.LockoutDuration - time.Minute) })
	if err := during.VerifyPassword(ctx, a.ID, pw); !errors.Is(err, admin.ErrAccountLocked) {
		t.Fatalf("during lockout: err = %v, want ErrAccountLocked", err)
	}
	after := r.WithClock(func() time.Time { return at.Add(admin.LockoutDuration + time.Minute) })
	if err := after.VerifyPassword(ctx, a.ID, pw); err != nil {
		t.Fatalf("after lockout expiry: err = %v, want nil", err)
	}
	// The new cycle still counts failures: the lock comes back.
	var last error
	for i := 0; i <= admin.MaxFailedAttempts; i++ {
		last = after.VerifyPassword(ctx, a.ID, "wrong")
	}
	if !errors.Is(last, admin.ErrAccountLocked) {
		t.Fatalf("new cycle failures: %v, want ErrAccountLocked", last)
	}
}

// Regression: a disabled account answered ErrAccountDisabled before the
// password was checked, so any password revealed that the email exists.
func TestAuthenticateDisabledNeedsPassword(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	const pw = "supersecret-12chars"
	if _, err := r.Create(ctx, "keeper@example.test", pw); err != nil {
		t.Fatal(err)
	}
	a, err := r.Create(ctx, "off@example.test", pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SetDisabled(ctx, a.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Authenticate(ctx, "off@example.test", "wrong-guess", ""); !errors.Is(err, admin.ErrInvalidCreds) {
		t.Fatalf("wrong password: err = %v, want ErrInvalidCreds", err)
	}
	if _, err := r.Authenticate(ctx, "off@example.test", pw, ""); !errors.Is(err, admin.ErrAccountDisabled) {
		t.Fatalf("right password: err = %v, want ErrAccountDisabled", err)
	}
}
