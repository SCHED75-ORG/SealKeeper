package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sched75/sealkeeper/internal/audit"
	"github.com/sched75/sealkeeper/internal/domains"
	"github.com/sched75/sealkeeper/internal/elevations"
	"github.com/sched75/sealkeeper/internal/policies"
	"github.com/sched75/sealkeeper/internal/tokens"
)

// Regression (SK-01): once policies are configured, a token whose policy
// cannot be resolved at consume time (policy disabled or deleted during
// the TTL, DB error) used to be burned and answered with the weak
// built-in default. It must fail closed and leave the link usable.
func TestHandlePolicyFailsClosedWithoutBurningToken(t *testing.T) {
	t.Parallel()
	s, repo := newAdminServer(t)
	db := repo.DB()
	dr := domains.NewRepo(db)
	er := elevations.NewRepo(db)
	pr := policies.NewRepo(db, dr, er)
	tr := tokens.NewRepo(db)
	s.SetTokens(tr)
	s.SetDomains(dr)
	s.SetPolicies(pr, er)
	ctx := context.Background()

	d, err := dr.Create(ctx, "example.test", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pr.Create(ctx, policies.CreateInputs{
		DomainID: d.ID, ANSSILevel: elevations.LevelB1, Name: "B1", Generator: policies.GeneratorG3, Active: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := tr.Issue(ctx, tokens.IssueOptions{Email: "user@example.test", Domain: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	// The operator disables the policy while the link is in flight.
	if err := pr.SetActive(ctx, p.ID, false); err != nil {
		t.Fatal(err)
	}

	w := postPolicy(s.Router(), tok.Token)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "policy_unavailable") {
		t.Fatalf("status=%d body=%s, want 503 policy_unavailable", w.Code, w.Body.String())
	}
	if got, err := tr.Get(ctx, tok.Token); err != nil || got.ConsumedAt != nil {
		t.Fatalf("token consumed despite the failure: %+v, %v", got, err)
	}

	// Re-enabled: the same link now works and returns the real policy.
	if err := pr.SetActive(ctx, p.ID, true); err != nil {
		t.Fatal(err)
	}
	w = postPolicy(s.Router(), tok.Token)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"generator":"G3"`) {
		t.Fatalf("status=%d body=%s, want 200 with the G3 policy", w.Code, w.Body.String())
	}
}

// postPolicy consumes a reveal token the way the reveal page does: POST
// /api/v1/policy with the token in a JSON body, never in the URL.
func postPolicy(h http.Handler, token string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"token": token})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/policy", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// Regression (tokenlogs): the reveal token travelled in the query string
// of GET /api/v1/policy?token=…, so every proxy / ingress access log (and
// any SIEM fed by them) held a live, consumable bearer credential. It is
// now consumed from a POST body only.
func TestPolicyTokenConsumedFromPOSTBody(t *testing.T) {
	t.Parallel()
	s, repo := newAdminServer(t)
	tr := tokens.NewRepo(repo.DB())
	s.SetTokens(tr)
	h := s.Router()
	tok, err := tr.Issue(context.Background(), tokens.IssueOptions{Email: "user@example.test", Domain: "example.test"})
	if err != nil {
		t.Fatal(err)
	}

	w := postPolicy(h, tok.Token)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"policy"`) {
		t.Fatalf("first POST: status=%d body=%s, want 200 with policy", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control=%q, want no-store", w.Header().Get("Cache-Control"))
	}
	w = postPolicy(h, tok.Token)
	if w.Code != http.StatusGone || !strings.Contains(w.Body.String(), "token_consumed") {
		t.Fatalf("second POST: status=%d body=%s, want 410 token_consumed", w.Code, w.Body.String())
	}
	if w = postPolicy(h, "does-not-exist"); w.Code != http.StatusNotFound {
		t.Fatalf("unknown token: status=%d, want 404", w.Code)
	}
}

func TestPolicyPOSTRejectsBadBodies(t *testing.T) {
	t.Parallel()
	s, repo := newAdminServer(t)
	tr := tokens.NewRepo(repo.DB())
	s.SetTokens(tr)
	h := s.Router()
	tok, err := tr.Issue(context.Background(), tokens.IssueOptions{Email: "user@example.test", Domain: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, ctype, body string
		want              int
	}{
		{name: "not json", ctype: "application/json", body: "token=" + tok.Token, want: http.StatusBadRequest},
		{name: "empty token", ctype: "application/json", body: `{"token":""}`, want: http.StatusBadRequest},
		{name: "form content type", ctype: "application/x-www-form-urlencoded", body: `{"token":"` + tok.Token + `"}`, want: http.StatusUnsupportedMediaType},
		{name: "oversized", ctype: "application/json", body: `{"token":"` + strings.Repeat("a", 8192) + `"}`, want: http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/policy", strings.NewReader(c.body))
			r.Header.Set("Content-Type", c.ctype)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != c.want {
				t.Fatalf("status=%d body=%s, want %d", w.Code, w.Body.String(), c.want)
			}
		})
	}
	if got, err := tr.Get(context.Background(), tok.Token); err != nil || got.ConsumedAt != nil {
		t.Fatalf("a rejected body consumed the token: %+v, %v", got, err)
	}
}

// Regression (tokenlogs): GET /api/v1/policy?token=… used to burn the
// token. It is refused — never consumed, never answered with the weaker
// built-in default — so a stale client fails loudly.
func TestPolicyRefusesTokenInQueryString(t *testing.T) {
	t.Parallel()
	s, repo := newAdminServer(t)
	tr := tokens.NewRepo(repo.DB())
	s.SetTokens(tr)
	h := s.Router()
	tok, err := tr.Issue(context.Background(), tokens.IssueOptions{Email: "user@example.test", Domain: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/policy?token="+tok.Token, nil))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "token_in_query") {
		t.Fatalf("status=%d body=%s, want 400 token_in_query", w.Code, w.Body.String())
	}
	if got, err := tr.Get(context.Background(), tok.Token); err != nil || got.ConsumedAt != nil {
		t.Fatalf("GET with ?token= consumed the token: %+v, %v", got, err)
	}
	// The documentation GET without a token is unchanged.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/policy", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"generators"`) {
		t.Fatalf("default policy: status=%d body=%s", w.Code, w.Body.String())
	}
}

// Regression (tokenlogs): the reveal page fetched the policy with the
// token in the URL; it must POST it in the body instead.
func TestRevealPageSendsTokenInBody(t *testing.T) {
	t.Parallel()
	s, repo := newAdminServer(t)
	tr := tokens.NewRepo(repo.DB())
	s.SetTokens(tr)
	tok, err := tr.Issue(context.Background(), tokens.IssueOptions{Email: "user@example.test", Domain: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/reveal/"+tok.Token, nil))
	page := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(page, "decode-btn") {
		t.Fatalf("status=%d, reveal page not rendered", w.Code)
	}
	if strings.Contains(page, "?token=") {
		t.Fatal("reveal page still puts the token in a query string")
	}
	if !strings.Contains(page, "method: 'POST'") {
		t.Fatal("reveal page does not POST the token")
	}
}

// Guard (tokenlogs): the server's own logs, at debug level, never carry
// a reveal token across the whole public flow — issue, reveal page,
// refused GET, consume, replay.
func TestPublicFlowNeverLogsRevealToken(t *testing.T) {
	t.Parallel()
	s, repo := newAdminServer(t)
	var logs lockedBuffer
	s.logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	db := repo.DB()
	s.SetTokens(tokens.NewRepo(db))
	s.SetAudit(audit.NewRepo(db, make([]byte, audit.KeySize)))
	s.cfg.InstanceDomain = "sk.test"
	h := s.Router()

	r := httptest.NewRequest(http.MethodPost, "/api/v1/request", strings.NewReader(`{"email":"user@example.test"}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), r)
	s.WaitMail(context.Background())
	var tok string
	if err := db.QueryRowContext(context.Background(), "SELECT token FROM request_tokens").Scan(&tok); err != nil {
		t.Fatalf("no token issued: %v", err)
	}
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/reveal/"+tok, nil))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/policy?token="+tok, nil))
	postPolicy(h, tok)
	postPolicy(h, tok)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/reveal/"+tok, nil))

	if out := logs.String(); strings.Contains(out, tok) {
		t.Fatalf("reveal token found in server logs:\n%s", out)
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}
