package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunStatus(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   int
	}{
		{"ok", http.StatusOK, 0},
		{"server error", http.StatusInternalServerError, 1},
		{"no content is not healthy", http.StatusNoContent, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(c.status)
			}))
			defer srv.Close()
			if got := run(srv.URL + "/healthz"); got != c.want {
				t.Fatalf("run() = %d, want %d", got, c.want)
			}
		})
	}
}

// A redirect must be a failure, never followed — even to another healthy
// loopback endpoint.
func TestRunDoesNotFollowRedirects(t *testing.T) {
	var hit bool
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer healthy.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, healthy.URL+"/healthz", http.StatusFound)
	}))
	defer redir.Close()

	if got := run(redir.URL + "/healthz"); got != 1 {
		t.Fatalf("run() = %d on a 302, want 1", got)
	}
	if hit {
		t.Fatal("probe followed the redirect")
	}
}

func TestProbeRefusesNonLoopbackTargets(t *testing.T) {
	cases := []string{
		"http://192.0.2.1:8443/healthz",
		"http://10.0.0.1/healthz",
		"http://[2001:db8::1]:8443/healthz",
		"http://example.com/healthz",
		"http://127.0.0.1.example.com/healthz",
		"http://0.0.0.0:8443/healthz",
	}
	for _, target := range cases {
		t.Run(target, func(t *testing.T) {
			if err := probe(target); !errors.Is(err, errNotLoopback) {
				t.Fatalf("probe(%q) = %v, want errNotLoopback", target, err)
			}
			if got := run(target); got != 1 {
				t.Fatalf("run(%q) = %d, want 1", target, got)
			}
		})
	}
}

func TestProbeRefusesOtherSchemes(t *testing.T) {
	for _, target := range []string{"file:///etc/passwd", "ftp://127.0.0.1/", "127.0.0.1:8443"} {
		if err := probe(target); err == nil {
			t.Fatalf("probe(%q) succeeded, want error", target)
		}
	}
}

func TestCheckTargetAcceptsLoopback(t *testing.T) {
	for _, target := range []string{
		defaultTarget,
		"http://localhost:8443/healthz",
		"http://127.0.0.2:8443/healthz",
		"http://[::1]:8443/healthz",
		"https://127.0.0.1:8443/healthz",
	} {
		if _, err := checkTarget(target); err != nil {
			t.Fatalf("checkTarget(%q) = %v, want nil", target, err)
		}
	}
}

// The dial-time hook covers names (localhost) whose resolution is not ours.
func TestLoopbackOnlyDialControl(t *testing.T) {
	if err := loopbackOnly("tcp", "127.0.0.1:8443", nil); err != nil {
		t.Fatalf("loopback refused: %v", err)
	}
	if err := loopbackOnly("tcp6", "[::1]:8443", nil); err != nil {
		t.Fatalf("::1 refused: %v", err)
	}
	if err := loopbackOnly("tcp", "10.0.30.91:8443", nil); !errors.Is(err, errNotLoopback) {
		t.Fatalf("non-loopback dial = %v, want errNotLoopback", err)
	}
}
