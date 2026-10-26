package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sched75/sealkeeper/internal/domains"
	"github.com/sched75/sealkeeper/internal/elevations"
	"github.com/sched75/sealkeeper/internal/policies"
	"github.com/sched75/sealkeeper/internal/storage"
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

	w := httptest.NewRecorder()
	s.handlePolicy(w, httptest.NewRequest(http.MethodGet, "/api/v1/policy?token="+tok.Token, nil))
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
	w = httptest.NewRecorder()
	s.handlePolicy(w, httptest.NewRequest(http.MethodGet, "/api/v1/policy?token="+tok.Token, nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"generator":"G3"`) {
		t.Fatalf("status=%d body=%s, want 200 with the G3 policy", w.Code, w.Body.String())
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

	w := httptest.NewRecorder()
	s.handlePolicy(w, httptest.NewRequest(http.MethodGet, "/api/v1/policy?token="+tok.Token, nil))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "policy_unavailable") {
		t.Fatalf("status=%d body=%s, want 503 policy_unavailable", w.Code, w.Body.String())
	}
	if got, err := tr.Get(ctx, tok.Token); err != nil || got.ConsumedAt != nil {
		t.Fatalf("token consumed for a policy the bundle refuses: %+v, %v", got, err)
	}

	// Once the operator fixes the policy, the same link works.
	setParams(`{"length":20,"alphabetSize":62}`)
	w = httptest.NewRecorder()
	s.handlePolicy(w, httptest.NewRequest(http.MethodGet, "/api/v1/policy?token="+tok.Token, nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"alphabetSize":62`) {
		t.Fatalf("status=%d body=%s, want 200 with the fixed policy", w.Code, w.Body.String())
	}
}
