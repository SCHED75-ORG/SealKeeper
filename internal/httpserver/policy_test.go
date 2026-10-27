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
	"github.com/sched75/sealkeeper/internal/config"
	"github.com/sched75/sealkeeper/internal/domains"
	"github.com/sched75/sealkeeper/internal/elevations"
	"github.com/sched75/sealkeeper/internal/policies"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/tokens"
	"net/url"
	"strconv"
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
	rs := &recordSender{}
	s.SetSender(rs)
	h := s.Router()

	r := httptest.NewRequest(http.MethodPost, "/api/v1/request", strings.NewReader(`{"email":"user@example.test"}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), r)
	s.WaitMail(context.Background())
	tok := mailedRevealToken(t, rs)
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

// Regression (entropy floor): the editor only warned when a policy was
// weaker than its level ("You can save anyway") and the server stored it.
// Add and save now refuse it with err=below_floor and the computed figure.
func TestAdminPolicyFormsRefuseEntropyBelowFloor(t *testing.T) {
	t.Parallel()
	s, repo, db := newModeServer(t, config.ModeProduction, false)
	sess := adminSessionFor(t, repo, db)
	dr := domains.NewRepo(db)
	er := elevations.NewRepo(db)
	pr := policies.NewRepo(db, dr, er)
	s.SetPolicies(pr, er)
	h := s.Router()
	ctx := context.Background()
	d, err := dr.Create(ctx, "example.test", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	form := func(level, params string) url.Values {
		return url.Values{"domain_id": {strconv.FormatInt(d.ID, 10)}, "anssi_level": {level},
			"name": {"b3"}, "generator": {"G3"}, "params_json": {params}, "active": {"on"}}
	}

	w := adminPOST(h, sess, "/admin/policies/add", form("B3", `{"length":4}`))
	loc := w.Header().Get("Location")
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/admin/policies?err=below_floor&details=") {
		t.Fatalf("add weak B3: %d %q, want 303 err=below_floor", w.Code, loc)
	}
	if n, _ := pr.Count(ctx); n != 0 {
		t.Fatalf("%d policies stored, want 0", n)
	}
	// The details reach the page.
	r := httptest.NewRequest(http.MethodGet, loc, nil)
	r.AddCookie(&http.Cookie{Name: cookieAdminSession, Value: sess.Token})
	page := httptest.NewRecorder()
	h.ServeHTTP(page, r)
	if !strings.Contains(page.Body.String(), "23.8 bits, B3 requires at least 100 bits") {
		t.Errorf("policies page does not show the refusal details")
	}

	w = adminPOST(h, sess, "/admin/policies/add", form("B3", `{"length":20}`))
	if loc := w.Header().Get("Location"); loc != "/admin/policies?ok=created" {
		t.Fatalf("add strong B3: %d %q", w.Code, loc)
	}
	p, err := pr.FindByDomainLevel(ctx, d.ID, elevations.LevelB3)
	if err != nil {
		t.Fatal(err)
	}
	// Claiming B1 in the form does not lower the stored B3 floor.
	w = adminPOST(h, sess, "/admin/policies/"+strconv.FormatInt(p.ID, 10)+"/save", form("B1", `{"length":10}`))
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "/edit?err=below_floor&details=") {
		t.Fatalf("save weak: %d %q, want err=below_floor", w.Code, loc)
	}
}

// A stored policy the reveal bundle refuses (here a G3 alphabetSize claim
// the generator cannot honour, saved before the editor checked it) used to
// be served with the token consumed, so the browser threw and the user lost
// the link. It must fail closed before Consume instead.
func TestHandlePolicyKeepsTokenWhenBundleWouldRefusePolicy(t *testing.T) {
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
	setParams := func(params string) {
		t.Helper()
		if _, err := db.ExecContext(ctx, storage.Rebind(db, `UPDATE policies SET params_json = ? WHERE id = ?`),
			params, p.ID); err != nil {
			t.Fatal(err)
		}
	}
	// Legacy row: written past the save-time validation.
	setParams(`{"length":20,"alphabetSize":94}`)
	tok, err := tr.Issue(ctx, tokens.IssueOptions{Email: "user@example.test", Domain: "example.test"})
	if err != nil {
		t.Fatal(err)
	}

	w := postPolicy(s.Router(), tok.Token)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "policy_unavailable") {
		t.Fatalf("status=%d body=%s, want 503 policy_unavailable", w.Code, w.Body.String())
	}
	if got, err := tr.Get(ctx, tok.Token); err != nil || got.ConsumedAt != nil {
		t.Fatalf("token consumed for a policy the bundle refuses: %+v, %v", got, err)
	}

	// Once the operator fixes the policy, the same link works.
	setParams(`{"length":20,"alphabetSize":62}`)
	w = postPolicy(s.Router(), tok.Token)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"alphabetSize":62`) {
		t.Fatalf("status=%d body=%s, want 200 with the fixed policy", w.Code, w.Body.String())
	}
}
