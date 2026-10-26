package httpserver

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sched75/sealkeeper/internal/config"
)

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.BaseURL = "https://sk.example.test"
	s := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h := s.Router()
	for _, path := range []string{"/", "/healthz", "/does-not-exist"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		hd := w.Header()
		csp := hd.Get("Content-Security-Policy")
		if !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
			t.Errorf("%s: CSP = %q", path, csp)
		}
		for k, want := range map[string]string{
			"X-Content-Type-Options":    "nosniff",
			"Referrer-Policy":           "no-referrer",
			"X-Frame-Options":           "DENY",
			"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
		} {
			if got := hd.Get(k); got != want {
				t.Errorf("%s: %s = %q, want %q", path, k, got, want)
			}
		}
	}
}

func TestPagesWithInlineScriptsGetANonce(t *testing.T) {
	t.Parallel()
	s := newClientIPServer(t)
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	csp := w.Header().Get("Content-Security-Policy")
	i := strings.Index(csp, "'nonce-")
	if i < 0 {
		t.Fatalf("landing CSP has no nonce: %q", csp)
	}
	nonce := strings.SplitN(csp[i+len("'nonce-"):], "'", 2)[0]
	if !strings.Contains(w.Body.String(), `<script nonce="`+nonce+`">`) {
		t.Fatal("landing inline script does not carry the CSP nonce")
	}
}

func TestStaticFSRefusesListingsAndDotfiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for name, body := range map[string]string{"app.js": "ok", ".env": "SECRET=1", "sub/x.js": "x"} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h := http.StripPrefix("/static/", http.FileServer(staticFS{dir: http.Dir(dir)}))
	cases := map[string]int{
		"/static/app.js":   http.StatusOK,
		"/static/sub/x.js": http.StatusOK,
		"/static/":         http.StatusNotFound,
		"/static/sub/":     http.StatusNotFound,
		"/static/sub":      http.StatusNotFound,
		"/static/.env":     http.StatusNotFound,
	}
	for path, want := range cases {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != want {
			t.Errorf("%s: status %d, want %d (body %.40q)", path, w.Code, want, w.Body.String())
		}
	}
}

func TestQuerySlugDropsFreeText(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]string{
		"bad_creds": "bad_creds",
		"Your+account+is+locked.+Call+%2B33+1+23": "",
		"<b>x</b>": "",
		"":         "",
	} {
		r := httptest.NewRequest(http.MethodGet, "/admin/login?err="+raw, nil)
		if got := querySlug(r, "err"); got != want {
			t.Errorf("querySlug(%q) = %q, want %q", raw, got, want)
		}
	}
}
