package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/audit"
	"github.com/sched75/sealkeeper/internal/readiness"
	"github.com/sched75/sealkeeper/internal/tokens"
)

// Regression (SK-08): every unmatched path became its own metric series.
func TestMetricsDoNotLabelUnmatchedPaths(t *testing.T) {
	t.Parallel()
	s := newClientIPServer(t)
	h := s.Router()
	for i := 0; i < 20; i++ {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/probe-"+strings.Repeat("x", i)+"-attacker-text", nil))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := w.Body.String()
	if strings.Contains(body, "attacker-text") {
		t.Fatal("request paths leak into metric labels")
	}
	if !strings.Contains(body, `route="unmatched"`) {
		t.Fatal(`missing route="unmatched" series`)
	}
}

// Regression (SK-11): the raw single-use reveal token was the audit
// target, readable by anyone with audit_log or SIEM access.
func TestAuditNeverStoresRawRevealToken(t *testing.T) {
	t.Parallel()
	s, repo := newAdminServer(t)
	db := repo.DB()
	ar := audit.NewRepo(db)
	tr := tokens.NewRepo(db)
	s.SetAudit(ar)
	s.cfg.InstanceDomain = "sk.test"
	s.SetTokens(tr)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/request", strings.NewReader(`{"email":"user@example.test"}`))
	s.handleRequest(httptest.NewRecorder(), r)

	var tok string
	if err := db.QueryRowContext(context.Background(), "SELECT token FROM request_tokens").Scan(&tok); err != nil {
		t.Fatalf("no token issued: %v", err)
	}
	rows, err := db.QueryContext(context.Background(), "SELECT COALESCE(target, ''), details_json FROM audit_log")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var target, details string
		if err := rows.Scan(&target, &details); err != nil {
			t.Fatal(err)
		}
		n++
		if strings.Contains(target, tok) || strings.Contains(details, tok) {
			t.Fatalf("raw reveal token in audit row: target=%q details=%q", target, details)
		}
	}
	if n == 0 {
		t.Fatal("no audit rows written")
	}
}

type failingCheck struct{}

func (failingCheck) Name() string { return "db" }
func (failingCheck) Check(context.Context) error {
	return errors.New(`dial tcp 10.1.2.3:5432: password authentication failed for user "sk_prod"`)
}

// Regression (SK-32): /readyz returned raw error strings to anonymous callers.
func TestReadyzHidesErrorDetails(t *testing.T) {
	t.Parallel()
	set := readiness.New(failingCheck{})
	w := httptest.NewRecorder()
	set.Handler(time.Second).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "sk_prod") || strings.Contains(w.Body.String(), "10.1.2.3") {
		t.Fatalf("internal details leaked: %s", w.Body.String())
	}
}
