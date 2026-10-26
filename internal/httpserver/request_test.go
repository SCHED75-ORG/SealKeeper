package httpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression: the requester's email reached the To: header verbatim, and
// net/mail tolerates CR/LF inside a trailing comment (header injection
// through the instance's own relay).
func TestHandleRequestRejectsNonBareEmail(t *testing.T) {
	t.Parallel()
	s := newClientIPServer(t)
	body := `{"email":"victim@example.org (x\r\nX-Injected: pwned\r\n\r\n<h1>locked</h1>)"}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/request", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.handleRequest(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_email") {
		t.Fatalf("status=%d body=%q, want 400 invalid_email", w.Code, w.Body.String())
	}
}

func TestHandleRequestCapsBodySize(t *testing.T) {
	t.Parallel()
	s := newClientIPServer(t)
	body := `{"email":"a@b.com","subject":"` + strings.Repeat("x", maxRequestBodyBytes) + `"}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/request", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.handleRequest(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400 for an oversized body", w.Code)
	}
}
