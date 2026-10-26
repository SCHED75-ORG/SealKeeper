package mailtemplates_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/mailtemplates"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
)

func newRepo(t *testing.T) *mailtemplates.Repo {
	t.Helper()
	dsn := storagetest.DSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := storage.Open(ctx, storage.Options{DSN: dsn})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return mailtemplates.NewRepo(s.DB())
}

// ----- defaults -------------------------------------------------------------

func TestGetReturnsSystemDefaultsWhenEmpty(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	for _, lang := range []string{"fr", "en"} {
		tpl, err := r.Get(context.Background(), mailtemplates.KindRevealLink, lang)
		if err != nil {
			t.Fatalf("Get(%q): %v", lang, err)
		}
		if !tpl.IsSystem {
			t.Errorf("lang %q: IsSystem = false, want true", lang)
		}
		if tpl.Subject == "" {
			t.Errorf("lang %q: empty subject", lang)
		}
	}
}

func TestGetFallsBackToEnglish(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	tpl, err := r.Get(context.Background(), mailtemplates.KindRevealLink, "es")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !strings.Contains(tpl.Text, "Hello") {
		t.Errorf("expected English fallback, got %.80s", tpl.Text)
	}
}

func TestGetRejectsUnknownKind(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	if _, err := r.Get(context.Background(), mailtemplates.Kind("nope"), "en"); !errors.Is(err, mailtemplates.ErrInvalidKind) {
		t.Fatalf("err = %v, want ErrInvalidKind", err)
	}
}

// ----- upsert / reset -------------------------------------------------------

func TestUpsertThenGetReturnsCustom(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	const subj = "Custom subject {{ .InstanceName }}"
	const txt = "Hi {{ .UserEmail }} — {{ .RevealURL }}"
	const html = "<p>{{ .UserEmail }} <a href=\"{{ .RevealURL }}\">link</a></p>"
	if err := r.Upsert(ctx, mailtemplates.KindRevealLink, "fr", subj, txt, html, nil); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	tpl, err := r.Get(ctx, mailtemplates.KindRevealLink, "fr")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if tpl.IsSystem {
		t.Error("IsSystem should be false after upsert")
	}
	if tpl.Subject != subj {
		t.Errorf("Subject = %q", tpl.Subject)
	}
}

func TestUpsertRejectsBadTemplate(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	err := r.Upsert(context.Background(), mailtemplates.KindRevealLink, "fr",
		"hi", "{{ broken", "<p>{{ .X </p>", nil)
	if !errors.Is(err, mailtemplates.ErrParse) {
		t.Fatalf("err = %v, want ErrParse", err)
	}
}

func TestResetRemovesOverride(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	_ = r.Upsert(ctx, mailtemplates.KindRevealLink, "fr",
		"custom", "text", "<p>html</p>", nil)
	if err := r.Reset(ctx, mailtemplates.KindRevealLink, "fr"); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	tpl, _ := r.Get(ctx, mailtemplates.KindRevealLink, "fr")
	if !tpl.IsSystem {
		t.Error("after Reset, IsSystem should be true again")
	}
}

// ----- Render ---------------------------------------------------------------

func TestRenderSubstitutesVars(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	got, err := r.Render(context.Background(), mailtemplates.KindRevealLink, "en", mailtemplates.Vars{
		RevealURL:       "https://x.test/reveal/abc",
		UserEmail:       "user@x.test",
		ValidityMinutes: 15,
		InstanceName:    "Acme",
		InstanceDomain:  "x.test",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(got.Text, "https://x.test/reveal/abc") {
		t.Errorf("Text missing URL: %.200s", got.Text)
	}
	if !strings.Contains(got.HTML, "Acme") {
		t.Errorf("HTML missing instance name")
	}
	if got.Subject == "" {
		t.Error("empty subject")
	}
}

func TestRenderHTMLEscapesUserInput(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	got, err := r.Render(context.Background(), mailtemplates.KindRevealLink, "en", mailtemplates.Vars{
		RevealURL:    "https://x.test/reveal/abc",
		UserEmail:    "<script>alert(1)</script>@x.test",
		InstanceName: "Acme",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(got.HTML, "<script>") {
		t.Errorf("html/template did not auto-escape: %s", got.HTML)
	}
}

func TestRenderTemplateInlineWorksWithoutDB(t *testing.T) {
	t.Parallel()
	got, err := mailtemplates.RenderTemplate(mailtemplates.Template{
		Kind:     mailtemplates.KindRevealLink,
		Language: "en",
		Subject:  "S {{ .InstanceName }}",
		Text:     "T {{ .RevealURL }}",
		HTML:     "<p>{{ .UserEmail }}</p>",
	}, mailtemplates.Vars{
		InstanceName: "Acme",
		RevealURL:    "u",
		UserEmail:    "alice@test",
	})
	if err != nil {
		t.Fatalf("RenderTemplate: %v", err)
	}
	if got.Subject != "S Acme" || got.Text != "T u" {
		t.Errorf("got = %+v", got)
	}
}

// ----- PickLanguage ---------------------------------------------------------

func TestPickLanguage(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"":                           "en",
		"fr":                         "fr",
		"fr-FR":                      "fr",
		"fr-FR,fr;q=0.9,en;q=0.8":    "fr",
		"de-DE,de;q=0.9,en;q=0.8":    "en",
		"es-MX,es;q=0.9,fr-FR;q=0.5": "fr",
		"x-klingon":                  "en",
	}
	for accept, want := range cases {
		if got := mailtemplates.PickLanguage(accept); got != want {
			t.Errorf("PickLanguage(%q) = %q, want %q", accept, got, want)
		}
	}
}

// ----- List -----------------------------------------------------------------

func TestListShowsEveryKnownPair(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	list, err := r.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	// We support 2 languages × 2 kinds → 4 rows expected.
	if len(list) != 4 {
		t.Fatalf("List = %d rows, want 4 (kinds × langs)", len(list))
	}
}
