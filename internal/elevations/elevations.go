// Package elevations owns the per-domain B2 / B3 elevation lists.
//
// PRD: FR-C.38..46.
//
// Resolution semantics, used by policies.Resolve():
//   - if an email appears in elevations with level=B2 → B2 policy applies
//   - if an email appears with level=B3            → B3 policy applies
//   - otherwise the implicit B1 level applies (FR-C.28).
package elevations

import (
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sched75/sealkeeper/internal/storage"
)

// Level enumerates the elevation tiers. B1 isn't stored — it's the default
// when an email is missing from the table.
type Level string

const (
	LevelB1 Level = "B1"
	LevelB2 Level = "B2"
	LevelB3 Level = "B3"
)

// Errors.
var (
	ErrNotFound      = errors.New("elevations: not found")
	ErrAlreadyExists = errors.New("elevations: already exists")
	ErrInvalidLevel  = errors.New("elevations: invalid level")
)

// Elevation is the row view.
type Elevation struct {
	ID               int64
	DomainID         int64
	Email            string
	Level            Level
	Reason           string
	CreatedByAdminID *int64
	CreatedAt        time.Time
	LastUsedAt       *time.Time
}

// Repo persists elevations.
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

// Create inserts an elevation. The email is canonicalised to lowercase and
// trimmed. Returns ErrAlreadyExists when the (domain_id, email) pair
// already has a row — admins must Delete then re-Create to change level.
func (r *Repo) Create(ctx context.Context, domainID int64, email string, level Level, reason string, adminID *int64) (Elevation, error) {
	if level != LevelB2 && level != LevelB3 {
		return Elevation{}, fmt.Errorf("%w: %q", ErrInvalidLevel, level)
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return Elevation{}, errors.New("elevations.Create: empty email")
	}
	now := r.now().UTC()
	const q = `INSERT INTO elevations
		(domain_id, email, level, reason, created_by_admin_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`
	id, err := storage.InsertReturningID(ctx, r.db, q,
		domainID, email, string(level), strings.TrimSpace(reason), nullableInt(adminID), now,
	)
	if err != nil {
		if storage.IsUniqueViolation(err) {
			return Elevation{}, ErrAlreadyExists
		}
		return Elevation{}, fmt.Errorf("elevations.Create: %w", err)
	}
	return Elevation{
		ID:               id,
		DomainID:         domainID,
		Email:            email,
		Level:            level,
		Reason:           reason,
		CreatedByAdminID: adminID,
		CreatedAt:        now,
	}, nil
}

// Lookup returns the level for an (domain_id, email) pair. Returns LevelB1
// and ErrNotFound when no row exists — callers usually swallow the error
// and treat it as the implicit B1.
func (r *Repo) Lookup(ctx context.Context, domainID int64, email string) (Level, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	const q = `SELECT level FROM elevations WHERE domain_id = ? AND email = ?`
	var lvl string
	err := r.db.QueryRowContext(ctx, rebind(r.db, q), domainID, email).Scan(&lvl)
	if errors.Is(err, sql.ErrNoRows) {
		return LevelB1, ErrNotFound
	}
	if err != nil {
		return LevelB1, err
	}
	return Level(lvl), nil
}

// LookupEmail returns the highest level granted to email under any domain
// row. Elevations used to be matched on the domain row Resolve picked, so
// adding an exact row under an existing wildcard (or toggling one) silently
// dropped a B3 user to B1. Sub-addresses ("ciso+x@") resolve like their
// base address, so a different spelling cannot select a weaker policy.
// Levels sort lexically (B1 < B2 < B3).
func (r *Repo) LookupEmail(ctx context.Context, email string) (Level, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	base := email
	if at := strings.LastIndexByte(email, '@'); at > 0 {
		if plus := strings.IndexByte(email[:at], '+'); plus > 0 {
			base = email[:plus] + email[at:]
		}
	}
	const q = `SELECT MAX(level) FROM elevations WHERE email IN (?, ?)`
	var lvl sql.NullString
	if err := r.db.QueryRowContext(ctx, rebind(r.db, q), email, base).Scan(&lvl); err != nil {
		return LevelB1, err
	}
	if !lvl.Valid {
		return LevelB1, ErrNotFound
	}
	return Level(lvl.String), nil
}

// List returns every row for the given domain, ordered by email.
func (r *Repo) List(ctx context.Context, domainID int64) ([]Elevation, error) {
	const q = selectQ + ` WHERE domain_id = ? ORDER BY email ASC`
	rows, err := r.db.QueryContext(ctx, rebind(r.db, q), domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collect(rows)
}

// ListAll returns every elevation row across every domain. Used by the
// admin /admin/elevations index page.
func (r *Repo) ListAll(ctx context.Context) ([]Elevation, error) {
	rows, err := r.db.QueryContext(ctx, selectQ+` ORDER BY domain_id, email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collect(rows)
}

// Delete removes a row by id.
func (r *Repo) Delete(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, rebind(r.db, "DELETE FROM elevations WHERE id = ?"), id)
	return err
}

// Get returns a row by id.
func (r *Repo) Get(ctx context.Context, id int64) (Elevation, error) {
	return scan(r.db.QueryRowContext(ctx, rebind(r.db, selectQ+` WHERE id = ?`), id))
}

// TouchLastUsed bumps the last_used_at column. Best-effort, errors are
// ignored by the caller because this is an observability convenience.
func (r *Repo) TouchLastUsed(ctx context.Context, id int64) error {
	now := r.now().UTC()
	_, err := r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE elevations SET last_used_at = ? WHERE id = ?`), now, id)
	return err
}

// ImportSummary is the shape returned by Import — the admin handler uses
// it to render the post-upload feedback panel.
type ImportSummary struct {
	Created int
	Skipped int // duplicates
	Errors  []ImportError
}

// ImportError describes one row that failed to import. Line is 1-indexed
// for spreadsheet-friendly reporting.
type ImportError struct {
	Line   int
	Email  string
	Reason string
}

// DomainResolver is the callback Import uses to translate a domain name
// to its row id. The admin handler passes domains.Repo.GetByName so the
// elevations package stays free of an import cycle.
type DomainResolver func(ctx context.Context, name string) (int64, error)

// Import reads `domain,email,level,reason` CSV rows from r. The header
// row (if any) is sniffed via the first column. Each row is processed
// independently — failing rows go into Errors and Import keeps reading.
// Domains that are not in the allowlist are reported as errors, not
// silently created, because elevations meaningless without a parent.
func (r *Repo) Import(ctx context.Context, src io.Reader, resolve DomainResolver, adminID *int64) (ImportSummary, error) {
	var out ImportSummary
	if resolve == nil {
		return out, errors.New("elevations.Import: resolver required")
	}
	reader := csv.NewReader(src)
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true
	line := 0
	for {
		row, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return out, fmt.Errorf("elevations.Import: parse line %d: %w", line+1, err)
		}
		line++
		r.importRow(ctx, &out, line, row, resolve, adminID)
	}
	return out, nil
}

// importRow processes one CSV row, recording its outcome (created,
// skipped, or an ImportError) on out. Header and empty rows are ignored.
func (r *Repo) importRow(ctx context.Context, out *ImportSummary, line int, row []string, resolve DomainResolver, adminID *int64) {
	if len(row) == 0 {
		return
	}
	if len(row) < 3 {
		out.Errors = append(out.Errors, ImportError{Line: line, Reason: "expected at least domain,email,level"})
		return
	}
	domain := strings.TrimSpace(row[0])
	email := strings.TrimSpace(row[1])
	level := strings.ToUpper(strings.TrimSpace(row[2]))
	if line == 1 && isHeaderColumn(domain) {
		return
	}
	if domain == "" || email == "" {
		out.Errors = append(out.Errors, ImportError{Line: line, Email: email, Reason: "empty domain or email"})
		return
	}
	reason := ""
	if len(row) >= 4 {
		reason = strings.TrimSpace(row[3])
	}
	domainID, err := resolve(ctx, domain)
	if err != nil {
		out.Errors = append(out.Errors, ImportError{Line: line, Email: email, Reason: "domain not in allowlist: " + domain})
		return
	}
	_, err = r.Create(ctx, domainID, email, Level(level), reason, adminID)
	recordCreate(out, line, email, level, err)
}

// isHeaderColumn reports whether the first column of row 1 is a header.
func isHeaderColumn(domain string) bool {
	lower := strings.ToLower(domain)
	return lower == "domain" || lower == "domain name"
}

// recordCreate tallies the outcome of one Create call on out.
func recordCreate(out *ImportSummary, line int, email, level string, err error) {
	switch {
	case errors.Is(err, ErrAlreadyExists):
		out.Skipped++
	case errors.Is(err, ErrInvalidLevel):
		out.Errors = append(out.Errors, ImportError{Line: line, Email: email, Reason: "invalid level: " + level})
	case err != nil:
		out.Errors = append(out.Errors, ImportError{Line: line, Email: email, Reason: err.Error()})
	default:
		out.Created++
	}
}

// ----- internals ------------------------------------------------------------

const selectQ = `SELECT id, domain_id, email, level, reason, created_by_admin_id, created_at, last_used_at FROM elevations`

type rowScanner interface{ Scan(dest ...any) error }

func scan(rs rowScanner) (Elevation, error) {
	var (
		e          Elevation
		lvl        string
		createdBy  sql.NullInt64
		createdAt  any
		lastUsedAt any
	)
	err := rs.Scan(&e.ID, &e.DomainID, &e.Email, &lvl, &e.Reason, &createdBy, &createdAt, &lastUsedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Elevation{}, ErrNotFound
	}
	if err != nil {
		return Elevation{}, err
	}
	e.Level = Level(lvl)
	if createdBy.Valid {
		v := createdBy.Int64
		e.CreatedByAdminID = &v
	}
	if t, err := toTime(createdAt); err == nil {
		e.CreatedAt = t
	}
	if lastUsedAt != nil {
		if t, err := toTime(lastUsedAt); err == nil {
			t := t
			e.LastUsedAt = &t
		}
	}
	return e, nil
}

func collect(rows *sql.Rows) ([]Elevation, error) {
	var out []Elevation
	for rows.Next() {
		e, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
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
