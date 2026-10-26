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
	"testing/fstest"

	"github.com/sched75/sealkeeper/internal/config"
	"github.com/sched75/sealkeeper/internal/webbundle"
)

const bundlePath = "/static/" + webbundle.BundleName

func getStatic(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

// A standalone release binary has no web directory next to it (WebDir
// empty): the reveal page's bundle must come from the embedded copy.
func TestStaticServesEmbeddedBundleWithoutWebDir(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.WebDir = ""
	s := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.embeddedWeb = fstest.MapFS{
		webbundle.BundleName: {Data: []byte("/*embedded*/window.SealKeeper={};")},
		".gitkeep":           {},
	}

	w := getStatic(t, s, bundlePath)
	if w.Code != http.StatusOK {
		t.Fatalf("bundle: status %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "/*embedded*/") {
		t.Errorf("bundle body = %.60q, want the embedded copy", w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("bundle Content-Type = %q", ct)
	}
	for _, p := range []string{"/static/.gitkeep", "/static/", "/static/missing.js"} {
		if w := getStatic(t, s, p); w.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", p, w.Code)
		}
	}
}

// A standalone binary run from a cwd that has an unrelated, bundle-less
// web/ directory (repo checkout, /srv, a home dir) with SK_WEB_DIR unset:
// config autodetection must not mount it over the embedded copy.
func TestStaticEmbeddedBundleSurvivesBundlelessWebDirInCwd(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "web", "src"), 0o750); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	t.Setenv("SK_CONFIG_FILE", "")
	t.Setenv("SK_WEB_DIR", "")
	t.Setenv("SK_MODE", "eval")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	s := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.embeddedWeb = fstest.MapFS{webbundle.BundleName: {Data: []byte("/*embedded*/")}}

	w := getStatic(t, s, bundlePath)
	if w.Code != http.StatusOK || w.Body.String() != "/*embedded*/" {
		t.Fatalf("bundle: status %d body %.60q (WebDir %q), want the embedded copy", w.Code, w.Body.String(), cfg.WebDir)
	}
}

// SK_WEB_DIR (the Docker image's /app/web) wins over the embedded copy.
func TestStaticWebDirTakesPrecedenceOverEmbedded(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, webbundle.BundleName), []byte("/*disk*/"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.WebDir = dir
	s := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.embeddedWeb = fstest.MapFS{webbundle.BundleName: {Data: []byte("/*embedded*/")}}

	w := getStatic(t, s, bundlePath)
	if w.Code != http.StatusOK || w.Body.String() != "/*disk*/" {
		t.Fatalf("bundle: status %d body %q, want the WebDir copy", w.Code, w.Body.String())
	}
}

// Built without a bundle and without a WebDir, /static/* is not mounted.
func TestStaticAbsentWithoutWebDirOrEmbedded(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.WebDir = ""
	s := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.embeddedWeb = nil
	if w := getStatic(t, s, bundlePath); w.Code != http.StatusNotFound {
		t.Fatalf("bundle: status %d, want 404", w.Code)
	}
}
