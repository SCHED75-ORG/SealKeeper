// Package branding owns the single-row instance identity: name, colours
// and logo blob. PRD: FR-C.64..68.
//
// The table has at most one row (id=1, enforced by a CHECK constraint).
// Get auto-creates it on first call with the schema defaults so the
// public surface always has something to render — handy for the eval
// 5-second pitch where no admin has logged in yet.
package branding

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/sched75/sealkeeper/internal/storage"
)

// Errors.
var (
	ErrInvalidColor = errors.New("branding: color must match #RRGGBB")
	ErrInvalidName  = errors.New("branding: instance name required")
	ErrLogoTooLarge = errors.New("branding: logo exceeds 256 KB limit")
	ErrInvalidLogo  = errors.New("branding: logo must be PNG or SVG")
)

// MaxLogoBytes is the FR-C.65 cap.
const MaxLogoBytes = 256 * 1024

// hexColorRe is the strict #RRGGBB form (uppercase or lowercase).
var hexColorRe = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)

// Branding is the row view.
type Branding struct {
	InstanceName     string
	PrimaryColor     string // #RRGGBB
	SecondaryColor   string
	TertiaryColor    string
	ContactURL       string
	LogoMIME         string // empty when no logo
	HasLogo          bool
	UpdatedByAdminID *int64
	UpdatedAt        time.Time
}

// Repo persists branding.
type Repo struct {
	db  *sql.DB
	now func() time.Time
}

// NewRepo binds a Repo.
func NewRepo(db *sql.DB) *Repo { return &Repo{db: db, now: time.Now} }

// WithClock for tests.
func (r *Repo) WithClock(now func() time.Time) *Repo {
	c := *r
	c.now = now
	return &c
}

// Get returns the active branding. Creates the default row on first call.
func (r *Repo) Get(ctx context.Context) (Branding, error) {
	row, err := r.read(ctx)
	if err == nil {
		return row, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Branding{}, err
	}
	// Bootstrap the default row with the heraldic palette so the public
	// flow looks like the project's identity from the very first request,
	// without waiting for an admin to open /admin/branding.
	now := r.now().UTC()
	const ins = `INSERT INTO branding
		(id, instance_name, primary_color, secondary_color, tertiary_color, created_at, updated_at)
		VALUES (1, 'SealKeeper', '#7A1F2B', '#C9A961', '#1A1814', ?, ?)`
	if _, err := r.db.ExecContext(ctx, rebind(r.db, ins), now, now); err != nil {
		// Race: someone else won the insert. Try reading again.
		if row, rerr := r.read(ctx); rerr == nil {
			return row, nil
		}
		return Branding{}, fmt.Errorf("branding.Get: insert default: %w", err)
	}
	return r.read(ctx)
}

// UpdateInputs is what the admin form passes to Update.
type UpdateInputs struct {
	InstanceName   string
	PrimaryColor   string
	SecondaryColor string
	TertiaryColor  string
	ContactURL     string
}

// Update validates and writes the non-logo fields. Logos go through
// SetLogo / ClearLogo so the multipart upload path stays separate from
// the JSON-form save path.
func (r *Repo) Update(ctx context.Context, in UpdateInputs, adminID *int64) error {
	if strings.TrimSpace(in.InstanceName) == "" {
		return ErrInvalidName
	}
	for _, c := range []struct{ name, val string }{
		{"primary_color", in.PrimaryColor},
		{"secondary_color", in.SecondaryColor},
		{"tertiary_color", in.TertiaryColor},
	} {
		if !hexColorRe.MatchString(c.val) {
			return fmt.Errorf("%w: %s=%q", ErrInvalidColor, c.name, c.val)
		}
	}
	if _, err := r.Get(ctx); err != nil { // ensure row exists
		return err
	}
	now := r.now().UTC()
	const q = `UPDATE branding
		SET instance_name = ?, primary_color = ?, secondary_color = ?, tertiary_color = ?,
		    contact_url = ?, updated_by_admin_id = ?, updated_at = ?
		WHERE id = 1`
	_, err := r.db.ExecContext(ctx, rebind(r.db, q),
		strings.TrimSpace(in.InstanceName),
		strings.ToUpper(in.PrimaryColor),
		strings.ToUpper(in.SecondaryColor),
		strings.ToUpper(in.TertiaryColor),
		strings.TrimSpace(in.ContactURL),
		nullableInt(adminID),
		now,
	)
	return err
}

// SetLogo stores the bytes + MIME. Validates size and accepts only
// PNG / SVG (FR-C.65).
func (r *Repo) SetLogo(ctx context.Context, mime string, bytes []byte, adminID *int64) error {
	if len(bytes) > MaxLogoBytes {
		return ErrLogoTooLarge
	}
	mime = strings.ToLower(strings.TrimSpace(mime))
	switch mime {
	case "image/png", "image/svg+xml":
	default:
		return fmt.Errorf("%w: got %q", ErrInvalidLogo, mime)
	}
	if _, err := r.Get(ctx); err != nil {
		return err
	}
	now := r.now().UTC()
	_, err := r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE branding SET logo_bytes = ?, logo_mime = ?, updated_by_admin_id = ?, updated_at = ? WHERE id = 1`),
		bytes, mime, nullableInt(adminID), now)
	return err
}

// ClearLogo drops the stored logo blob.
func (r *Repo) ClearLogo(ctx context.Context, adminID *int64) error {
	now := r.now().UTC()
	_, err := r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE branding SET logo_bytes = NULL, logo_mime = NULL, updated_by_admin_id = ?, updated_at = ? WHERE id = 1`),
		nullableInt(adminID), now)
	return err
}

// Logo returns the stored logo bytes + MIME. Returns sql.ErrNoRows when
// the table itself is missing the row, ErrInvalidLogo when the row exists
// but no logo has been uploaded yet — the HTTP handler maps both to 404.
func (r *Repo) Logo(ctx context.Context) ([]byte, string, error) {
	const q = `SELECT logo_bytes, logo_mime FROM branding WHERE id = 1`
	var (
		bytes []byte
		mime  sql.NullString
	)
	err := r.db.QueryRowContext(ctx, q).Scan(&bytes, &mime)
	if err != nil {
		return nil, "", err
	}
	if len(bytes) == 0 || !mime.Valid {
		return nil, "", ErrInvalidLogo
	}
	return bytes, mime.String, nil
}

// ----- internals ------------------------------------------------------------

func (r *Repo) read(ctx context.Context) (Branding, error) {
	const q = `SELECT instance_name, primary_color, secondary_color, tertiary_color,
		contact_url, logo_mime, updated_by_admin_id, updated_at
		FROM branding WHERE id = 1`
	var (
		b         Branding
		mime      sql.NullString
		adminID   sql.NullInt64
		updatedAt any
	)
	err := r.db.QueryRowContext(ctx, q).Scan(
		&b.InstanceName, &b.PrimaryColor, &b.SecondaryColor, &b.TertiaryColor,
		&b.ContactURL, &mime, &adminID, &updatedAt)
	if err != nil {
		return Branding{}, err
	}
	if mime.Valid && mime.String != "" {
		b.HasLogo = true
		b.LogoMIME = mime.String
	}
	if adminID.Valid {
		v := adminID.Int64
		b.UpdatedByAdminID = &v
	}
	if t, err := toTime(updatedAt); err == nil {
		b.UpdatedAt = t
	}
	return b, nil
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
		time.RFC3339Nano, time.RFC3339,
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
