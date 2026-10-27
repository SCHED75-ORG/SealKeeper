package httpserver

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/admin"
	"github.com/sched75/sealkeeper/internal/config"
	"github.com/sched75/sealkeeper/internal/ratelimit"
	"github.com/sched75/sealkeeper/internal/webauthn"
)

// countingBody records how many bytes a handler pulled from the request.
type countingBody struct {
	r io.Reader
	n int
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func (c *countingBody) Close() error { return nil }

// unauthPOST sends body to path through the router with the login CSRF
// pair set (the field must be in body) and reports the bytes consumed.
func unauthPOST(h http.Handler, path, contentType string, body []byte, cookies ...*http.Cookie) (*httptest.ResponseRecorder, int) {
	cb := &countingBody{r: bytes.NewReader(body)}
	r := httptest.NewRequest(http.MethodPost, path, nil)
	r.Body = cb
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Type", contentType)
	r.AddCookie(&http.Cookie{Name: cookieLoginCSRF, Value: "tok"})
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w, cb.n
}

func maxAuditField(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n sql.NullInt64
	if err := db.QueryRowContext(context.Background(),
		`SELECT MAX(n) FROM (SELECT LENGTH(COALESCE(actor, '')) AS n FROM audit_log
		 UNION ALL SELECT LENGTH(COALESCE(target, '')) FROM audit_log) x`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return int(n.Int64)
}

// An unauthenticated login POST must not let an attacker write megabytes
// into the hash-chained audit log or the Location header: the body is
// capped before ParseForm and the email field at an RFC 5321 address.
func TestAdminLoginCapsBodyAndEmail(t *testing.T) {
	t.Parallel()
	s, _, db := newModeServer(t, config.ModeProduction, false)
	h := s.Router()
	form := func(email string) []byte {
		return []byte(url.Values{"csrf_token": {"tok"}, "email": {email}, "password": {"x"}}.Encode())
	}

	// Megabyte body: refused before it is buffered.
	huge := strings.Repeat("a", 1<<20) + "@x.test"
	w, read := unauthPOST(h, "/admin/login", "application/x-www-form-urlencoded", form(huge))
	if read > adminLoginMaxBodyBytes+1 {
		t.Errorf("huge body: handler read %d bytes, cap %d", read, adminLoginMaxBodyBytes)
	}
	if loc := w.Header().Get("Location"); len(loc) > 512 {
		t.Errorf("huge body: Location is %d bytes", len(loc))
	}

	// An overlong email that fits the body cap: audited truncated, never
	// echoed into the redirect.
	long := strings.Repeat("b", 1000) + "@x.test"
	w, _ = unauthPOST(h, "/admin/login", "application/x-www-form-urlencoded", form(long))
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "err=bad_creds") || strings.Contains(loc, "bbbb") {
		t.Errorf("overlong email: Location = %q, want bad_creds without echo", loc)
	}

	// The rate-limited branch audits before Authenticate: same cap.
	s.loginLimiter = ratelimit.New(1, time.Hour)
	_, _ = unauthPOST(h, "/admin/login", "application/x-www-form-urlencoded", form(long))
	if w, _ := unauthPOST(h, "/admin/login", "application/x-www-form-urlencoded", form(long)); !strings.Contains(w.Header().Get("Location"), "err=rate_limited") {
		t.Errorf("rate limited: Location = %q", w.Header().Get("Location"))
	}

	if n := maxAuditField(t, db); n > admin.MaxEmailBytes {
		t.Fatalf("largest audit actor/target = %d bytes, want <= %d", n, admin.MaxEmailBytes)
	}
}

// The other unauthenticated admin POSTs cap their bodies too.
func TestAdminUnauthPOSTsCapBody(t *testing.T) {
	t.Parallel()
	s, wa, repo, db := newWebauthnServer(t)
	sess := adminSessionFor(t, repo, db)
	h := s.Router()
	pad := strings.Repeat("p", 1<<20)
	formBody := []byte("pad=" + pad + "&csrf_token=tok")

	pending, _, err := s.loginPending.Issue(sess.AdminID)
	if err != nil {
		t.Fatal(err)
	}
	step := &http.Cookie{Name: cookieAdminLoginStep, Value: pending}
	for _, path := range []string{"/admin/login/webauthn/begin", "/admin/login/webauthn/cancel"} {
		if _, read := unauthPOST(h, path, "application/x-www-form-urlencoded", formBody, step); read > adminLoginMaxBodyBytes+1 {
			t.Errorf("%s read %d bytes, cap %d", path, read, adminLoginMaxBodyBytes)
		}
	}

	// Finish: reach FinishLogin with a genuine enrolled key and challenge,
	// then hand it a megabyte JSON body.
	k := newWAKey(t)
	w := adminPOST(h, sess, "/admin/security/begin", url.Values{
		"friendly_name": {"yubikey"}, "current_password": {"supersecret-12chars"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("begin: status %d", w.Code)
	}
	if w := enrolFinish(h, sess, k.attestation(t, challengeFromOptions(t, w.Body.Bytes())), responseCookies(w)...); w.Code != http.StatusOK {
		t.Fatalf("enrol: status %d (%s)", w.Code, w.Body.String())
	}
	pending, _, err = s.loginPending.Issue(sess.AdminID)
	if err != nil {
		t.Fatal(err)
	}
	_, session, err := wa.BeginLogin(context.Background(), webauthn.AdminIdentity{ID: sess.AdminID, Email: "ops@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/admin/login/webauthn/finish?csrf_token=tok", nil)
	cb := &countingBody{r: strings.NewReader(`{"id":"` + pad + `"}`)}
	r.Body = cb
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: cookieLoginCSRF, Value: "tok"})
	r.AddCookie(&http.Cookie{Name: cookieAdminLoginStep, Value: pending})
	r.AddCookie(&http.Cookie{Name: cookieAdminLoginAssertion, Value: s.sealCeremony(session, "login", pending)})
	fw := httptest.NewRecorder()
	h.ServeHTTP(fw, r)
	if fw.Code != http.StatusUnauthorized {
		t.Errorf("finish: status %d, want 401", fw.Code)
	}
	if cb.n > adminWebauthnMaxBodyBytes+1 {
		t.Errorf("finish read %d bytes, cap %d", cb.n, adminWebauthnMaxBodyBytes)
	}

	// Logout: the session's CSRF token sits after a megabyte of padding.
	logout := []byte("pad=" + pad + "&csrf_token=" + url.QueryEscape(sess.CSRFToken))
	_, read := unauthPOST(h, "/admin/logout", "application/x-www-form-urlencoded", logout,
		&http.Cookie{Name: cookieAdminSession, Value: sess.Token})
	if read > adminLoginMaxBodyBytes+1 {
		t.Errorf("logout read %d bytes, cap %d", read, adminLoginMaxBodyBytes)
	}
}
