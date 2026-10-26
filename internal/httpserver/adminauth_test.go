package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/admin"
	"github.com/sched75/sealkeeper/internal/cryptobox"
	"github.com/sched75/sealkeeper/internal/ratelimit"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
	"github.com/sched75/sealkeeper/internal/totp"
)

// newAdminServer wires a Server to a fresh database with one admin.
func newAdminServer(t *testing.T) (*Server, *admin.Repo) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), storagetest.SetupTimeout)
	defer cancel()
	st, err := storage.Open(ctx, storage.Options{DSN: storagetest.DSN(t)})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	if err := st.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	box, err := cryptobox.New(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	repo := admin.NewRepo(st.DB(), box)
	s := newClientIPServer(t)
	s.SetAdmin(repo, "test")
	return s, repo
}

func postLogin(s *Server, remote, email, password string) *httptest.ResponseRecorder {
	form := url.Values{"csrf_token": {"tok"}, "email": {email}, "password": {password}}
	r := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: cookieLoginCSRF, Value: "tok"})
	r.RemoteAddr = remote
	w := httptest.NewRecorder()
	s.handleAdminLoginPost(w, r)
	return w
}

func TestAdminLoginRateLimitedPerIP(t *testing.T) {
	t.Parallel()
	s, _ := newAdminServer(t)
	s.loginLimiter = ratelimit.New(2, time.Hour)
	for i := 0; i < 2; i++ {
		if loc := postLogin(s, "203.0.113.9:1", "nobody@example.test", "x").Header().Get("Location"); strings.Contains(loc, "rate_limited") {
			t.Fatalf("attempt %d rate limited too early", i+1)
		}
	}
	if loc := postLogin(s, "203.0.113.9:1", "nobody@example.test", "x").Header().Get("Location"); !strings.Contains(loc, "err=rate_limited") {
		t.Fatalf("3rd attempt Location = %q, want err=rate_limited", loc)
	}
	if loc := postLogin(s, "198.51.100.1:1", "nobody@example.test", "x").Header().Get("Location"); strings.Contains(loc, "rate_limited") {
		t.Fatal("another IP was rate limited")
	}
}

func TestRateLimitKeyFoldsSubaddress(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"ciso+a@example.org": "ciso@example.org",
		"ciso@example.org":   "ciso@example.org",
		"+x@example.org":     "+x@example.org",
	} {
		if got := rateLimitKey(in); got != want {
			t.Errorf("rateLimitKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSameOriginPOST(t *testing.T) {
	t.Parallel()
	h := sameOriginPOST(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	cases := []struct {
		name, method, site, origin string
		want                       int
	}{
		{"same-origin fetch", http.MethodPost, "same-origin", "http://sk.test", http.StatusNoContent},
		{"sibling subdomain", http.MethodPost, "same-site", "http://wiki.sk.test", http.StatusForbidden},
		{"cross-site", http.MethodPost, "cross-site", "https://evil.test", http.StatusForbidden},
		{"origin only, foreign", http.MethodPost, "", "https://evil.test", http.StatusForbidden},
		{"no headers (curl)", http.MethodPost, "", "", http.StatusNoContent},
		{"no-referrer form post", http.MethodPost, "same-origin", "null", http.StatusNoContent},
		{"cross-site GET", http.MethodGet, "cross-site", "", http.StatusNoContent},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, "http://sk.test/admin/domains/add", nil)
		if c.site != "" {
			r.Header.Set("Sec-Fetch-Site", c.site)
		}
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s: status %d, want %d", c.name, w.Code, c.want)
		}
	}
}

// Regression: checkSessionCSRF compared the csrf cookie with the form
// field, so a value planted in the cookie by a sibling subdomain (or an
// absent cookie with an empty field) passed.
func TestSessionCSRFBoundToSession(t *testing.T) {
	t.Parallel()
	s, repo := newAdminServer(t)
	ctx := context.Background()
	a, err := repo.Create(ctx, "ops@example.test", "supersecret-12chars")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := repo.CreateSession(ctx, a.ID, "", "")
	if err != nil {
		t.Fatal(err)
	}
	try := func(cookie, field string) bool {
		form := url.Values{"csrf_token": {field}}
		r := httptest.NewRequest(http.MethodPost, "/admin/domains/add", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: cookieAdminCSRF, Value: cookie})
		}
		r = r.WithContext(context.WithValue(context.WithValue(r.Context(), ctxKeyAdmin, a), ctxKeySession, sess))
		return s.checkSessionCSRF(r)
	}
	if !try("", sess.CSRFToken) {
		t.Error("the session's own token was refused")
	}
	if try("planted", "planted") {
		t.Error("planted cookie/field pair accepted")
	}
	if try("", "") {
		t.Error("empty token accepted")
	}
}

// Regression: the login slug told an existing admin email apart from an
// unknown one. Wrong passwords against a real account ended in err=locked
// once its attempts were spent, and a disabled account answered
// err=disabled before any password check, while an unknown email always got
// err=bad_creds. Without the password, every account must look alike.
func TestAdminLoginSlugDoesNotEnumerateAdmins(t *testing.T) {
	t.Parallel()
	s, repo := newAdminServer(t)
	s.loginLimiter = ratelimit.New(1000, time.Hour)
	ctx := context.Background()
	const pw = "supersecret-12chars"
	if _, err := repo.Create(ctx, "real@example.test", pw); err != nil {
		t.Fatal(err)
	}
	off, err := repo.Create(ctx, "off@example.test", pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.SetDisabled(ctx, off.ID, true); err != nil {
		t.Fatal(err)
	}
	slug := func(w *httptest.ResponseRecorder) string {
		u, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		return u.Query().Get("err")
	}
	for _, email := range []string{"real@example.test", "off@example.test", "ghost@example.test"} {
		for i := 0; i <= admin.MaxFailedAttempts+1; i++ {
			if got := slug(postLogin(s, "203.0.113.9:1", email, "wrong-guess")); got != "bad_creds" {
				t.Fatalf("%s attempt %d: err=%q, want bad_creds", email, i+1, got)
			}
		}
	}
}

// Regression: with the TOTP field left empty, a correct password answered
// err=totp_required and a wrong one err=bad_creds, so the password of a
// TOTP-only admin could be confirmed without the second factor. Both must
// now get the same answer.
func TestAdminLoginBlankTOTPDoesNotConfirmPassword(t *testing.T) {
	t.Parallel()
	s, repo := newAdminServer(t)
	s.loginLimiter = ratelimit.New(1000, time.Hour)
	ctx := context.Background()
	const pw = "supersecret-12chars"
	a, err := repo.Create(ctx, "ops@example.test", pw)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := totp.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	codes, err := totp.NewRecoveryCodes(2)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.EnrollTOTP(ctx, a.ID, secret, codes); err != nil {
		t.Fatal(err)
	}
	wrong := postLogin(s, "203.0.113.9:1", a.Email, "not-the-password").Header().Get("Location")
	right := postLogin(s, "203.0.113.9:1", a.Email, pw).Header().Get("Location")
	if !strings.Contains(wrong, "err=bad_creds") {
		t.Fatalf("wrong password Location = %q, want err=bad_creds", wrong)
	}
	if right != wrong {
		t.Fatalf("correct password, blank TOTP: Location = %q, want the wrong-password answer %q", right, wrong)
	}
}
