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
)

// newAdminServer wires a Server to a fresh database with one admin.
func newAdminServer(t *testing.T) (*Server, *admin.Repo) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
