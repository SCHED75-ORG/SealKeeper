package mailcapture_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sched75/sealkeeper/internal/mailcapture"
)

func TestSnapshotForOnlyReturnsOwnedMail(t *testing.T) {
	t.Parallel()
	s := mailcapture.NewStore(10)
	s.CaptureFor("alice-handle", "alice@example.test", "s", "alice link")
	s.CaptureFor("bob-handle", "bob@example.test", "s", "bob link")
	s.Capture("unowned@example.test", "s", "unowned link")

	got := s.SnapshotFor("alice-handle")
	if len(got) != 1 || got[0].To != "alice@example.test" {
		t.Fatalf("SnapshotFor(alice) = %+v, want only alice's mail", got)
	}
	if got := s.SnapshotFor(""); len(got) != 0 {
		t.Fatalf("empty owner matched %d mails (unowned mail leaked)", len(got))
	}
	if got := s.SnapshotFor("mallory"); len(got) != 0 {
		t.Fatalf("unknown owner matched %d mails", len(got))
	}
	if n := len(s.Snapshot()); n != 3 {
		t.Fatalf("Snapshot len = %d, want 3", n)
	}
}

func TestScopedHandlerNeverSerialisesOwner(t *testing.T) {
	t.Parallel()
	s := mailcapture.NewStore(10)
	s.CaptureFor("secret-handle", "a@example.test", "s", "b")
	h := s.ScopedHandler(func(r *http.Request) string { return r.Header.Get("X-Owner") })

	r := httptest.NewRequest(http.MethodGet, "/__captured_mail", nil)
	r.Header.Set("X-Owner", "secret-handle")
	w := httptest.NewRecorder()
	h(w, r)
	if strings.Contains(w.Body.String(), "secret-handle") {
		t.Fatalf("owner handle serialised: %s", w.Body.String())
	}
	var out struct {
		Items []mailcapture.Mail `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(out.Items))
	}

	w = httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, "/__captured_mail", nil))
	if !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Fatalf("caller without handle got %s, want an empty list", w.Body.String())
	}
}

func TestResetDropsEverything(t *testing.T) {
	t.Parallel()
	s := mailcapture.NewStore(10)
	s.Capture("a@example.test", "s", "b")
	s.Reset()
	if n := len(s.Snapshot()); n != 0 {
		t.Fatalf("Snapshot after Reset = %d items", n)
	}
	if id := s.Capture("a@example.test", "s", "b"); id == "1" {
		t.Fatal("ids restarted after Reset; a stale capture id could alias a new mail")
	}
}
