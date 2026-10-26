package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sched75/sealkeeper/internal/audit"
	"github.com/sched75/sealkeeper/internal/tokens"
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

// Regression: the client-supplied "domain" field was stored in
// request_tokens.domain and emitted in audit/SIEM details, letting any
// requester forge the domain operators see. It is now derived from the
// normalised email; "domain" and "subject" are ignored.
func TestHandleRequestDerivesDomainServerSide(t *testing.T) {
	t.Parallel()
	s, repo := newAdminServer(t)
	db := repo.DB()
	s.SetAudit(audit.NewRepo(db, make([]byte, audit.KeySize)))
	s.cfg.InstanceDomain = "sk.test"
	s.SetTokens(tokens.NewRepo(db))
	body := `{"email":"User@Example.TEST","domain":"forged.example","subject":"forged-subject"}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/request", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.handleRequest(w, r)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status=%d, want 202", w.Code)
	}

	ctx := context.Background()
	var domain string
	if err := db.QueryRowContext(ctx, "SELECT domain FROM request_tokens").Scan(&domain); err != nil {
		t.Fatalf("no token issued: %v", err)
	}
	if domain != "example.test" {
		t.Errorf("request_tokens.domain = %q, want example.test", domain)
	}
	rows, err := db.QueryContext(ctx, "SELECT COALESCE(target, ''), details_json FROM audit_log")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var target, details string
		if err := rows.Scan(&target, &details); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(target+details, "forged") {
			t.Fatalf("client-supplied field in audit row: target=%q details=%q", target, details)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
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
