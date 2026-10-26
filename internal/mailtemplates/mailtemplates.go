package mailtemplates

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/sched75/sealkeeper/internal/storage"
)

// Errors.
var (
	ErrNotFound    = errors.New("mailtemplates: not found")
	ErrInvalidKind = errors.New("mailtemplates: invalid kind")
	ErrParse       = errors.New("mailtemplates: template parse failed")
)

// Template is the row view exposed to the admin UI. When IsSystem is true
// the row is synthetic — backed by the in-code default rather than the DB.
type Template struct {
	Kind             Kind
	Language         string
	Subject          string
	Text             string
	HTML             string
	IsSystem         bool
	UpdatedByAdminID *int64
	UpdatedAt        time.Time
}

// Vars carries every value templates may reference (FR-C.72).
//
// Field omissions are tolerated at render time — the templates use
// conditional pipelines and never error on missing optional fields.
type Vars struct {
	// Reveal-link flow
	RevealURL       string
	UserEmail       string
	ValidityMinutes int
	ExpiresAt       time.Time
	InstanceName    string
	InstanceDomain  string
	ContactURL      string

	// Post-consultation flow
	ConsultedAt        string
	ConsultedIP        string
	ConsultedUserAgent string
}

// Rendered carries the three pieces of a fully-realised mail.
type Rendered struct {
	Kind     Kind
	Language string
	Subject  string
	Text     string
	HTML     string
}

// Repo persists overrides and renders.
type Repo struct {
	db  *sql.DB
	now func() time.Time
}

// NewRepo binds a Repo. db may be nil — Render then always falls back to
// the system defaults, which is useful in tests.
func NewRepo(db *sql.DB) *Repo { return &Repo{db: db, now: time.Now} }

// WithClock for tests.
func (r *Repo) WithClock(now func() time.Time) *Repo {
	c := *r
	c.now = now
	return &c
}

// Get returns the active template for (kind, lang). When no DB row exists
// it returns the system default with IsSystem=true.
func (r *Repo) Get(ctx context.Context, kind Kind, lang string) (Template, error) {
	if !isKnownKind(kind) {
		return Template{}, ErrInvalidKind
	}
	lang = canonLang(lang)

	if r.db != nil {
		row, err := r.getDB(ctx, kind, lang)
		if err == nil {
			return row, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return Template{}, err
		}
	}
	return r.systemTemplate(kind, lang)
}

// List returns one row per known (kind, language) pair — DB-backed rows
// when present, synthetic system rows otherwise. Used by the admin index.
func (r *Repo) List(ctx context.Context) ([]Template, error) {
	out := make([]Template, 0, len(AllKinds())*len(SupportedLanguages()))
	for _, k := range AllKinds() {
		for _, l := range SupportedLanguages() {
			row, err := r.Get(ctx, k, l)
			if err != nil {
				return nil, err
			}
			out = append(out, row)
		}
	}
	return out, nil
}

// Upsert validates the three template sources (subject text/template, text
// text/template, html html/template) and writes/updates the row.
func (r *Repo) Upsert(ctx context.Context, kind Kind, lang, subject, text, html string, adminID *int64) error {
	if r.db == nil {
		return errors.New("mailtemplates.Upsert: nil db")
	}
	if !isKnownKind(kind) {
		return ErrInvalidKind
	}
	lang = canonLang(lang)
	if err := ValidateTemplates(subject, text, html); err != nil {
		return err
	}
	now := r.now().UTC()
	// Two-step upsert (read then UPDATE / INSERT) so the same SQL works on
	// SQLite and Postgres without per-driver ON CONFLICT dance.
	existing, err := r.getDB(ctx, kind, lang)
	if errors.Is(err, ErrNotFound) {
		const ins = `INSERT INTO email_templates
			(kind, language, subject, text_body, html_body, updated_by_admin_id, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
		_, err := r.db.ExecContext(ctx, rebind(r.db, ins),
			string(kind), lang, subject, text, html, nullableInt(adminID), now, now)
		return err
	}
	if err != nil {
		return err
	}
	const upd = `UPDATE email_templates
		SET subject = ?, text_body = ?, html_body = ?,
		    updated_by_admin_id = ?, updated_at = ?
		WHERE kind = ? AND language = ?`
	_, err = r.db.ExecContext(ctx, rebind(r.db, upd),
		subject, text, html, nullableInt(adminID), now,
		string(existing.Kind), existing.Language)
	return err
}

// Reset removes the DB override, falling back to the system default.
func (r *Repo) Reset(ctx context.Context, kind Kind, lang string) error {
	if r.db == nil {
		return errors.New("mailtemplates.Reset: nil db")
	}
	lang = canonLang(lang)
	_, err := r.db.ExecContext(ctx,
		rebind(r.db, `DELETE FROM email_templates WHERE kind = ? AND language = ?`),
		string(kind), lang)
	return err
}

// Render assembles a Rendered struct for (kind, lang, vars). Falls back to
// English when the requested language isn't available — neither in the DB
// nor in the system defaults.
func (r *Repo) Render(ctx context.Context, kind Kind, lang string, vars Vars) (Rendered, error) {
	tpl, err := r.Get(ctx, kind, lang)
	if err != nil {
		return Rendered{}, err
	}
	return renderTemplate(tpl, vars)
}

// ValidateTemplates parses the three sources and returns ErrParse on any
// failure, wrapping ErrUnsafe too when a source could leak the reveal
// token or load remote content (see safety.go). Used by the admin Save
// and Preview handlers.
func ValidateTemplates(subject, text, html string) error {
	if strings.TrimSpace(subject) == "" {
		return fmt.Errorf("%w: subject is empty", ErrParse)
	}
	if _, err := texttemplate.New("subject").Parse(subject); err != nil {
		return fmt.Errorf("%w: subject: %s", ErrParse, err.Error())
	}
	if _, err := texttemplate.New("text").Parse(text); err != nil {
		return fmt.Errorf("%w: text: %s", ErrParse, err.Error())
	}
	if _, err := htmltemplate.New("html").Parse(html); err != nil {
		return fmt.Errorf("%w: html: %s", ErrParse, err.Error())
	}
	return checkSafety(subject, text, html)
}

// ----- internals ------------------------------------------------------------

func (r *Repo) systemTemplate(kind Kind, lang string) (Template, error) {
	byLang, ok := defaults[kind]
	if !ok {
		return Template{}, ErrInvalidKind
	}
	d, ok := byLang[lang]
	if !ok {
		// English is the universal fallback.
		d = byLang["en"]
	}
	return Template{
		Kind:     kind,
		Language: lang,
		Subject:  d.Subject,
		Text:     d.Text,
		HTML:     d.HTML,
		IsSystem: true,
	}, nil
}

func (r *Repo) getDB(ctx context.Context, kind Kind, lang string) (Template, error) {
	const q = `SELECT kind, language, subject, text_body, html_body,
		updated_by_admin_id, updated_at
		FROM email_templates WHERE kind = ? AND language = ?`
	var (
		t         Template
		updatedBy sql.NullInt64
		updatedAt any
		kindStr   string
		langStr   string
	)
	err := r.db.QueryRowContext(ctx, rebind(r.db, q), string(kind), lang).
		Scan(&kindStr, &langStr, &t.Subject, &t.Text, &t.HTML, &updatedBy, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Template{}, ErrNotFound
	}
	if err != nil {
		return Template{}, err
	}
	t.Kind = Kind(kindStr)
	t.Language = langStr
	if updatedBy.Valid {
		v := updatedBy.Int64
		t.UpdatedByAdminID = &v
	}
	if u, err := toTime(updatedAt); err == nil {
		t.UpdatedAt = u
	}
	return t, nil
}

// RenderTemplate is the public entry point used by the admin live-preview
// handler. It bypasses the DB and renders straight from the supplied
// Template fields — convenient when the admin hasn't pressed Save yet.
func RenderTemplate(tpl Template, vars Vars) (Rendered, error) {
	return renderTemplate(tpl, vars)
}

// renderTemplate re-applies the safety rules on every render: a row stored
// before they existed, or written straight to the DB, never sends the
// token anywhere but its own link (see safety.go).
func renderTemplate(tpl Template, vars Vars) (Rendered, error) {
	out := Rendered{Kind: tpl.Kind, Language: tpl.Language}
	if err := checkStatic(tpl); err != nil {
		return out, err
	}

	subject, err := renderText("subject", tpl.Subject, vars)
	if err != nil {
		return out, fmt.Errorf("%w: subject: %s", ErrParse, err.Error())
	}
	out.Subject = strings.TrimSpace(subject)

	text, err := renderText("text", tpl.Text, vars)
	if err != nil {
		return out, fmt.Errorf("%w: text: %s", ErrParse, err.Error())
	}
	out.Text = text

	html, err := renderHTML("html", tpl.HTML, vars)
	if err != nil {
		return out, fmt.Errorf("%w: html: %s", ErrParse, err.Error())
	}
	out.HTML = html

	if err := checkRendered(out, vars.RevealURL); err != nil {
		return Rendered{Kind: tpl.Kind, Language: tpl.Language}, err
	}
	return out, nil
}

func renderText(name, src string, vars Vars) (string, error) {
	t, err := texttemplate.New(name).Parse(src)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, vars); err != nil {
		return "", err
	}
	return b.String(), nil
}

func renderHTML(name, src string, vars Vars) (string, error) {
	t, err := htmltemplate.New(name).Parse(src)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, vars); err != nil {
		return "", err
	}
	return b.String(), nil
}

func isKnownKind(k Kind) bool {
	_, ok := defaults[k]
	return ok
}

func canonLang(lang string) string {
	lang = strings.ToLower(strings.TrimSpace(lang))
	if lang == "" {
		return "en"
	}
	if i := strings.IndexAny(lang, "_-"); i > 0 {
		lang = lang[:i]
	}
	return lang
}

// PickLanguage returns the first language code in `acceptLanguage` that the
// templates support, defaulting to "en". Skeleton-grade Accept-Language
// parser: splits on commas, strips q= weights, lowercases, accepts only the
// language subtag (`fr-FR` → `fr`).
func PickLanguage(acceptLanguage string) string {
	if acceptLanguage == "" {
		return "en"
	}
	supported := map[string]bool{}
	for _, l := range SupportedLanguages() {
		supported[l] = true
	}
	for _, part := range strings.Split(acceptLanguage, ",") {
		raw := part
		if i := strings.Index(part, ";"); i > 0 {
			raw = part[:i]
		}
		lang := canonLang(raw)
		if supported[lang] {
			return lang
		}
	}
	return "en"
}

func nullableInt(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

func rebind(db *sql.DB, query string) string { return storage.Rebind(db, query) }

func toTime(v any) (time.Time, error) {
	switch x := v.(type) {
	case time.Time:
		return x.UTC(), nil
	case []byte:
		return parseTS(string(x))
	case string:
		return parseTS(x)
	case nil:
		return time.Time{}, errors.New("nil time")
	default:
		return time.Time{}, fmt.Errorf("unsupported time type %T", v)
	}
}

func parseTS(s string) (time.Time, error) {
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse %q", s)
}
