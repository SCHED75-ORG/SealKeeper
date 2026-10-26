package httpserver

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/sched75/sealkeeper/internal/domains"
	"github.com/sched75/sealkeeper/internal/elevations"
	"github.com/sched75/sealkeeper/internal/mailtemplates"
	"github.com/sched75/sealkeeper/internal/policies"
	"github.com/sched75/sealkeeper/internal/tokens"
)

// Regression (FR-C.23): disabling a domain refuses new requests, but a
// link already issued for it stays valid until its TTL. The consume path
// used to resolve through the active-only domain matcher and answered
// 503 policy_unavailable ("try again later") until the link expired.
func TestHandlePolicyServesIssuedLinkAfterDomainDisabled(t *testing.T) {
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
	s.SetMailTemplates(mailtemplates.NewRepo(db))
	ctx := context.Background()

	d, err := dr.Create(ctx, "corp.test", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pr.Create(ctx, policies.CreateInputs{
		DomainID: d.ID, ANSSILevel: elevations.LevelB1, Name: "B1", Generator: policies.GeneratorG3,
		NotifyOnConsult: true, Active: true,
	}, nil); err != nil {
		t.Fatal(err)
	}
	tok, err := tr.Issue(ctx, tokens.IssueOptions{Email: "u@corp.test", Domain: "corp.test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := dr.SetActive(ctx, d.ID, false); err != nil {
		t.Fatal(err)
	}

	// New requests from the disabled domain stay refused.
	if _, err := pr.Resolve(ctx, "u@corp.test"); !errors.Is(err, policies.ErrNoPolicy) {
		t.Fatalf("Resolve after disable = %v, want ErrNoPolicy", err)
	}
	// The post-consultation notice the policy asks for still goes out.
	if !s.shouldNotifyPostConsult(ctx, "u@corp.test") {
		t.Fatal("post-consultation notice dropped for a link issued before the domain was disabled")
	}

	w := postPolicy(s.Router(), tok.Token)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"generator":"G3"`) ||
		!strings.Contains(w.Body.String(), `"domain":"corp.test"`) {
		t.Fatalf("status=%d body=%s, want 200 with the corp.test G3 policy", w.Code, w.Body.String())
	}
	if got, err := tr.Get(ctx, tok.Token); err != nil || got.ConsumedAt == nil {
		t.Fatalf("token not consumed: %+v, %v", got, err)
	}
}
