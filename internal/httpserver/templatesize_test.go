package httpserver

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/sched75/sealkeeper/internal/config"
	"github.com/sched75/sealkeeper/internal/mailtemplates"
)

// Regression: the template save and preview forms parse the HTML body on
// every request and accepted ParseForm's 10 MB default, which an editor
// (any visitor in demo mode) could feed to a quadratic parser path
// (GO-2026-6860). Bodies over adminTemplateMaxBodyBytes are refused and
// nothing is stored.
func TestTemplateFormsRefuseOversizedBodies(t *testing.T) {
	t.Parallel()
	s, repo, db := newModeServer(t, config.ModeProduction, false)
	sess := adminSessionFor(t, repo, db)
	s.SetMailTemplates(mailtemplates.NewRepo(db))
	h := s.Router()

	big := `<p><a href="{{ .RevealURL }}">open</a></p>` + strings.Repeat("<p>filler text</p>", adminTemplateMaxBodyBytes/18+1)
	form := url.Values{
		"kind": {"reveal_link"}, "language": {"en"}, "subject": {"Your link"},
		"text_body": {"{{ .RevealURL }}\n"}, "html_body": {big},
	}
	for _, path := range []string{"/admin/templates/save", "/admin/templates/preview"} {
		if w := adminPOST(h, sess, path, form); w.Code != http.StatusBadRequest {
			t.Errorf("%s with a %d-byte body: %d, want 400", path, len(big), w.Code)
		}
	}
	var saved int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE event_type = 'template.saved'`).Scan(&saved); err != nil {
		t.Fatal(err)
	}
	if saved != 0 {
		t.Errorf("oversized template was saved (%d template.saved rows)", saved)
	}

	// A template well under the cap still saves.
	form.Set("html_body", `<p><a href="{{ .RevealURL }}">open</a></p>`)
	if w := adminPOST(h, sess, "/admin/templates/save", form); w.Code != http.StatusSeeOther {
		t.Fatalf("normal save: %d", w.Code)
	}
}
