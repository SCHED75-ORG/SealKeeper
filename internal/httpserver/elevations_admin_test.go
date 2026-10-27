package httpserver

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/sched75/sealkeeper/internal/config"
	"github.com/sched75/sealkeeper/internal/domains"
	"github.com/sched75/sealkeeper/internal/elevations"
	"github.com/sched75/sealkeeper/internal/policies"
)

// Regression (FR-C.24 / FR-C.39): the add form filed alice@corp.test under
// other.test and accepted the same address on both lists.
func TestAdminElevationAddRefusesMisfiledEmail(t *testing.T) {
	t.Parallel()
	s, repo, db := newModeServer(t, config.ModeProduction, false)
	dr := domains.NewRepo(db)
	er := elevations.NewRepo(db)
	s.SetPolicies(policies.NewRepo(db, dr, er), er)
	sess := adminSessionFor(t, repo, db)
	h := s.Router()
	ctx := context.Background()
	corp, _ := dr.Create(ctx, "corp.test", "", true, nil)
	other, _ := dr.Create(ctx, "other.test", "", true, nil)
	id := func(d domains.Domain) string { return strconv.FormatInt(d.ID, 10) }

	cases := []struct {
		name, domain, email, level, want string
	}{
		{"wrong domain", id(other), "alice@corp.test", "B3", "/admin/elevations?err=domain_mismatch"},
		{"malformed", id(corp), "not-an-email", "B2", "/admin/elevations?err=invalid_email"},
		{"legit", id(corp), "alice@corp.test", "B2", "/admin/elevations?ok=added"},
		{"second list", id(corp), "alice@corp.test", "B3", "/admin/elevations?err=duplicate"},
	}
	for _, c := range cases {
		w := adminPOST(h, sess, "/admin/elevations/add", url.Values{
			"domain_id": {c.domain}, "email": {c.email}, "level": {c.level},
		})
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != c.want {
			t.Errorf("%s: %d %q, want 303 %q", c.name, w.Code, w.Header().Get("Location"), c.want)
		}
	}
	if lvl, err := er.LookupEmail(ctx, "alice@corp.test"); err != nil || lvl != elevations.LevelB2 {
		t.Fatalf("LookupEmail = %s, %v; want B2", lvl, err)
	}
}
