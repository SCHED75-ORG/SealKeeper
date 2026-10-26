package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/sched75/sealkeeper/internal/config"
	"github.com/sched75/sealkeeper/internal/domains"
	"github.com/sched75/sealkeeper/internal/elevations"
	"github.com/sched75/sealkeeper/internal/mailtemplates"
	"github.com/sched75/sealkeeper/internal/policies"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/tokens"
)

// lastAuditDetails returns the details of the most recent `event` row.
func lastAuditDetails(t *testing.T, db *sql.DB, event string) map[string]any {
	t.Helper()
	var raw string
	if err := db.QueryRowContext(context.Background(), storage.Rebind(db,
		`SELECT details_json FROM audit_log WHERE event_type = ? ORDER BY sequence_no DESC LIMIT 1`),
		event).Scan(&raw); err != nil {
		t.Fatalf("no %s audit row: %v", event, err)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func wantKeys(t *testing.T, event string, d map[string]any, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if _, ok := d[k]; !ok {
			t.Errorf("%s details lack %q: %v", event, k, d)
		}
	}
}

func change(t *testing.T, d map[string]any, field string) map[string]any {
	t.Helper()
	changes, _ := d["changes"].(map[string]any)
	c, ok := changes[field].(map[string]any)
	if !ok {
		t.Fatalf("changes[%q] missing: %v", field, d["changes"])
	}
	return c
}

// Regression: policy.created / policy.updated only carried domain, level
// and generator, so a weakening (fewer proposals, shorter length, consult
// notice switched off) left no trace, and nothing tied a consumed token to
// the policy content the user's browser received.
func TestPolicyAuditProvesWhatUsersReceived(t *testing.T) {
	t.Parallel()
	s, repo, db := newModeServer(t, config.ModeProduction, false)
	sess := adminSessionFor(t, repo, db)
	dr := domains.NewRepo(db)
	er := elevations.NewRepo(db)
	s.SetPolicies(policies.NewRepo(db, dr, er), er)
	s.SetDomains(dr)
	h := s.Router()
	ctx := context.Background()
	d, err := dr.Create(ctx, "corp.test", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"domain_id": {fmt.Sprint(d.ID)}, "anssi_level": {"B1"}, "name": {"Std"},
		"generator": {"G3"}, "params_json": {`{"length":24}`}, "proposal_count": {"5"},
		"notify_on_consult": {"on"}, "active": {"on"},
	}
	if w := adminPOST(h, sess, "/admin/policies/add", form); w.Code != http.StatusSeeOther {
		t.Fatalf("add: %d", w.Code)
	}
	created := lastAuditDetails(t, db, "policy.created")
	wantKeys(t, "policy.created", created, "params_json", "params_sha256", "proposal_count",
		"notify_on_consult", "regenerate_limit", "session_ttl_seconds", "policy_sha256")

	// Weakening: shorter passwords, a single proposal, no consult notice.
	pid := fmt.Sprint(created["policy_id"])
	form.Set("params_json", `{"length":8}`)
	form.Set("proposal_count", "1")
	form.Del("notify_on_consult")
	if w := adminPOST(h, sess, "/admin/policies/"+pid+"/save", form); w.Code != http.StatusSeeOther {
		t.Fatalf("save: %d", w.Code)
	}
	updated := lastAuditDetails(t, db, "policy.updated")
	if c := change(t, updated, "proposal_count"); c["from"] != float64(5) || c["to"] != float64(1) {
		t.Errorf("proposal_count change = %v", c)
	}
	if c := change(t, updated, "notify_on_consult"); c["from"] != true || c["to"] != false {
		t.Errorf("notify_on_consult change = %v", c)
	}
	if c := change(t, updated, "params_sha256"); c["from"] != created["params_sha256"] || c["to"] == c["from"] {
		t.Errorf("params change = %v", c)
	}
	if updated["params_json"] != `{"length":8}` {
		t.Errorf("params_json = %v", updated["params_json"])
	}
	if updated["previous_policy_sha256"] != created["policy_sha256"] || updated["policy_sha256"] == created["policy_sha256"] {
		t.Errorf("policy hashes: created %v, updated %v", created["policy_sha256"], updated)
	}

	// The consumed token names the exact policy content served.
	tok, err := tokens.NewRepo(db).Issue(ctx, tokens.IssueOptions{Email: "user@corp.test", Domain: "corp.test"})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/policy?token="+tok.Token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("policy fetch: %d %s", w.Code, w.Body.String())
	}
	consumed := lastAuditDetails(t, db, "token.consumed")
	if consumed["policy_sha256"] != updated["policy_sha256"] || fmt.Sprint(consumed["policy_id"]) != pid {
		t.Errorf("token.consumed = %v, want policy %s with hash %v", consumed, pid, updated["policy_sha256"])
	}
}

func TestTemplateAuditRecordsContentHashes(t *testing.T) {
	t.Parallel()
	s, repo, db := newModeServer(t, config.ModeProduction, false)
	sess := adminSessionFor(t, repo, db)
	s.SetMailTemplates(mailtemplates.NewRepo(db))
	h := s.Router()

	form := url.Values{
		"kind": {"reveal_link"}, "language": {"en"}, "subject": {"Your link"},
		"text_body": {"{{ .RevealURL }}\n"}, "html_body": {`<a href="{{ .RevealURL }}">open</a>`},
	}
	if w := adminPOST(h, sess, "/admin/templates/save", form); w.Code != http.StatusSeeOther {
		t.Fatalf("save: %d", w.Code)
	}
	first := lastAuditDetails(t, db, "template.saved")
	wantKeys(t, "template.saved", first, "subject_sha256", "text_sha256", "html_sha256", "changed")
	if prev, _ := first["previous"].(map[string]any); prev["system"] != true {
		t.Errorf("first save should record the system default as previous: %v", first["previous"])
	}

	form.Set("html_body", `<p><a href="{{ .RevealURL }}">open now</a></p>`)
	if w := adminPOST(h, sess, "/admin/templates/save", form); w.Code != http.StatusSeeOther {
		t.Fatalf("save: %d", w.Code)
	}
	second := lastAuditDetails(t, db, "template.saved")
	if prev, _ := second["previous"].(map[string]any); prev["html_sha256"] != first["html_sha256"] {
		t.Errorf("previous html hash = %v, want %v", second["previous"], first["html_sha256"])
	}
	if got := fmt.Sprint(second["changed"]); got != "[html]" {
		t.Errorf("changed = %s, want [html]", got)
	}
}

func TestBrandingAuditRecordsTheDiff(t *testing.T) {
	t.Parallel()
	s, repo, db := newModeServer(t, config.ModeProduction, false)
	sess := adminSessionFor(t, repo, db)
	form := url.Values{
		"instance_name": {"SealKeeper"}, "primary_color": {"#7A1F2B"}, "secondary_color": {"#C9A961"},
		"tertiary_color": {"#1A1814"}, "contact_url": {"https://help.evil.test/"},
	}
	if w := adminPOST(s.Router(), sess, "/admin/branding/save", form); w.Code != http.StatusSeeOther {
		t.Fatalf("save: %d", w.Code)
	}
	d := lastAuditDetails(t, db, "branding.updated")
	if c := change(t, d, "contact_url"); c["from"] != "" || c["to"] != "https://help.evil.test/" {
		t.Errorf("contact_url change = %v", c)
	}
	if changes, _ := d["changes"].(map[string]any); len(changes) != 1 {
		t.Errorf("unchanged fields reported: %v", changes)
	}
}
