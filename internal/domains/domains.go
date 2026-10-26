// Package domains owns the email-domain allowlist that gates
// POST /api/v1/request.
//
// PRD: FR-C.20..26 (admin surface) + FR-B.9 / FR-B.13 (silent denial when
// the domain isn't allowed — the public flow MUST NOT leak the policy).
//
// Stored names are case-folded to lowercase. Two forms are accepted:
//
//   - exact FQDN, e.g. "entreprise.com" — matches a single email domain
//   - subdomain wildcard, e.g. "*.entreprise.com" — matches any descendant
//     ("paris.entreprise.com", "fr.paris.entreprise.com"), but NOT the bare
//     "entreprise.com" (list both if you want both).
//
// An empty table (fresh install) fails closed: Allows() refuses every input
// with ErrEmptyAllowlist, so a production instance never mints reveal links
// for arbitrary Internet addresses (SK-37). Zero-config modes whose mail
// never leaves the box (eval, demo) opt back in with WithOpenWhenEmpty.
// Either way the gate is the list itself as soon as the first row lands.
package domains

import (
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/sched75/sealkeeper/internal/storage"
)

// Errors.
var (
	ErrNotFound      = errors.New("domains: not found")
	ErrInvalidName   = errors.New("domains: invalid name")
	ErrAlreadyExists = errors.New("domains: name already exists")
	// ErrEmptyAllowlist accompanies a refusal caused by an empty table on a
	// fail-closed repo, so the caller can tell the operator why.
	ErrEmptyAllowlist = errors.New("domains: allowlist is empty")
)

// Domain is the row view.
type Domain struct {
	ID               int64
	Name             string
	Description      string
	Active           bool
	CreatedByAdminID *int64
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Repo persists domains.
type Repo struct {
	db            *sql.DB
	now           func() time.Time
	openWhenEmpty bool
}

// NewRepo binds a Repo to a *sql.DB.
func NewRepo(db *sql.DB) *Repo { return &Repo{db: db, now: time.Now} }

// WithClock is a test helper.
func (r *Repo) WithClock(now func() time.Time) *Repo {
	c := *r
	c.now = now
	return &c
}

// WithOpenWhenEmpty returns a copy whose empty table admits every domain.
// Only for modes where reveal mail is captured, never relayed (eval, demo).
func (r *Repo) WithOpenWhenEmpty(open bool) *Repo {
	c := *r
	c.openWhenEmpty = open
	return &c
}

// OpenWhenEmpty reports whether an empty table admits every domain.
func (r *Repo) OpenWhenEmpty() bool { return r.openWhenEmpty }

// Canonicalize lowercases and trims a domain name, returns ErrInvalidName on
// an empty or syntactically wrong input. Wildcards must use the `*.` prefix
// once, anywhere else is rejected.
func Canonicalize(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(raw))
	if name == "" {
		return "", ErrInvalidName
	}
	// Strip leading dot (people sometimes write ".entreprise.com").
	name = strings.TrimPrefix(name, ".")
	if strings.Contains(name[1:], "*") {
		return "", fmt.Errorf("%w: wildcard only allowed as leftmost label", ErrInvalidName)
	}
	check := name
	if strings.HasPrefix(name, "*.") {
		check = name[2:]
	}
	if !isFQDN(check) {
		return "", fmt.Errorf("%w: %q is not a valid FQDN", ErrInvalidName, raw)
	}
	return name, nil
}

// fqdnLabelRe is the RFC 1035 letter-digit-hyphen rule, with a relaxation
// for leading digits (RFC 1123 allows them).
var fqdnLabelRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func isFQDN(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !fqdnLabelRe.MatchString(l) {
			return false
		}
	}
	return true
}

// ----- CRUD ----------------------------------------------------------------

// Create inserts a domain. Returns ErrAlreadyExists when name collides.
func (r *Repo) Create(ctx context.Context, name, description string, active bool, adminID *int64) (Domain, error) {
	canon, err := Canonicalize(name)
	if err != nil {
		return Domain{}, err
	}
	now := r.now().UTC()
	const q = `INSERT INTO domains (name, description, active, created_by_admin_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`
	id, err := storage.InsertReturningID(ctx, r.db, q,
		canon, strings.TrimSpace(description), active, nullableInt(adminID), now, now,
	)
	if err != nil {
		// SQLite + Postgres both surface uniqueness as a generic constraint
		// violation — sniff the message rather than chase per-driver error
		// types here.
		if storage.IsUniqueViolation(err) {
			return Domain{}, ErrAlreadyExists
		}
		return Domain{}, fmt.Errorf("domains.Create: %w", err)
	}
	return Domain{
		ID: id, Name: canon, Description: description, Active: active,
		CreatedByAdminID: adminID, CreatedAt: now, UpdatedAt: now,
	}, nil
}

// Get returns the row by id or ErrNotFound.
func (r *Repo) Get(ctx context.Context, id int64) (Domain, error) {
	return scan(r.db.QueryRowContext(ctx, rebind(r.db, selectQ+" WHERE id = ?"), id))
}

// GetByName returns the row by canonical name (lowercased).
func (r *Repo) GetByName(ctx context.Context, name string) (Domain, error) {
	return scan(r.db.QueryRowContext(ctx, rebind(r.db, selectQ+" WHERE name = ?"),
		strings.ToLower(strings.TrimSpace(name))))
}

// List returns all domains in name order.
func (r *Repo) List(ctx context.Context) ([]Domain, error) {
	rows, err := r.db.QueryContext(ctx, selectQ+" ORDER BY name ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		d, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SetActive toggles the active flag.
func (r *Repo) SetActive(ctx context.Context, id int64, active bool) error {
	now := r.now().UTC()
	_, err := r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE domains SET active = ?, updated_at = ? WHERE id = ?`),
		active, now, id,
	)
	return err
}

// UpdateDescription replaces the description.
func (r *Repo) UpdateDescription(ctx context.Context, id int64, description string) error {
	now := r.now().UTC()
	_, err := r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE domains SET description = ?, updated_at = ? WHERE id = ?`),
		strings.TrimSpace(description), now, id,
	)
	return err
}

// Delete removes a row by id. The caller is responsible for ensuring no
// dependent rows exist (policies / elevations) when those tables land.
func (r *Repo) Delete(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, rebind(r.db, "DELETE FROM domains WHERE id = ?"), id)
	return err
}

// Count returns the number of rows. Allows uses it to apply the empty-table
// rule; the admin dashboard uses it to warn about an empty allowlist.
func (r *Repo) Count(ctx context.Context) (int64, error) {
	var n int64
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM domains").Scan(&n)
	return n, err
}

// ----- matching ------------------------------------------------------------

// FindMatching returns the active allowlist row that best matches
// `emailDomain`. Exact match wins over wildcards; the most specific
// wildcard (deepest suffix) wins over a shallower one. Inactive rows are
// skipped. Returns ErrNotFound when nothing applies.
func (r *Repo) FindMatching(ctx context.Context, emailDomain string) (Domain, error) {
	d := strings.ToLower(strings.TrimSpace(emailDomain))
	if d == "" {
		return Domain{}, ErrNotFound
	}
	candidates := []string{d}
	parts := strings.Split(d, ".")
	for i := 0; i < len(parts)-1; i++ {
		candidates = append(candidates, "*."+strings.Join(parts[i+1:], "."))
	}
	for _, c := range candidates {
		row, err := r.GetByName(ctx, c)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return Domain{}, err
		}
		if row.Active {
			return row, nil
		}
	}
	return Domain{}, ErrNotFound
}

// Allows reports whether `emailDomain` (e.g. "paris.entreprise.com") matches
// any active allowlist row. An empty table refuses with ErrEmptyAllowlist
// unless the repo was built WithOpenWhenEmpty(true), which admits all.
func (r *Repo) Allows(ctx context.Context, emailDomain string) (bool, error) {
	d := strings.ToLower(strings.TrimSpace(emailDomain))
	if d == "" {
		return false, nil
	}
	n, err := r.Count(ctx)
	if err != nil {
		return false, err
	}
	if n == 0 {
		if r.openWhenEmpty {
			return true, nil // eval / demo zero-config — see package doc.
		}
		return false, ErrEmptyAllowlist
	}

	// Build the list of candidate names: the exact value plus every
	// ancestor wildcard form.
	candidates := []string{d}
	parts := strings.Split(d, ".")
	for i := 0; i < len(parts)-1; i++ {
		candidates = append(candidates, "*."+strings.Join(parts[i+1:], "."))
	}

	// Single round-trip via IN (...).
	placeholders := make([]string, len(candidates))
	args := make([]any, len(candidates))
	for i, c := range candidates {
		placeholders[i] = "?"
		args[i] = c
	}
	q := `SELECT COUNT(*) FROM domains WHERE active = TRUE AND name IN (` + strings.Join(placeholders, ",") + `)`
	var hits int64
	if err := r.db.QueryRowContext(ctx, rebind(r.db, q), args...).Scan(&hits); err != nil {
		return false, err
	}
	return hits > 0, nil
}

// ImportSummary is the shape returned by Import — the admin handler uses
// it to render the post-upload feedback panel.
type ImportSummary struct {
	Created int
	Skipped int // duplicates (already in the table)
	Errors  []ImportError
}

// ImportError describes one row that failed to import. Line is 1-indexed
// to match what the user sees in a spreadsheet.
type ImportError struct {
	Line   int
	Domain string
	Reason string
}

// Import reads `name,description,active` CSV rows from r and inserts each
// one. The header row (if any) is detected and skipped. Existing
// domains are silently counted as Skipped; rows that fail Canonicalize
// or the insert itself end up in Errors. The bulk-write happens row by
// row — there's no transactional all-or-nothing; partial success is
// reported back so the admin can fix only the broken lines and
// re-upload.
func (r *Repo) Import(ctx context.Context, src io.Reader, adminID *int64) (ImportSummary, error) {
	var out ImportSummary
	reader := csv.NewReader(src)
	reader.FieldsPerRecord = -1 // tolerate variable column counts
	reader.TrimLeadingSpace = true
	line := 0
	for {
		row, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return out, fmt.Errorf("domains.Import: parse line %d: %w", line+1, err)
		}
		line++
		if len(row) == 0 || strings.TrimSpace(row[0]) == "" {
			continue
		}
		name := strings.TrimSpace(row[0])
		// Skip the header row by sniffing column-1 — case-insensitive
		// match on "name" / "domain" / "domain name".
		if line == 1 {
			lower := strings.ToLower(name)
			if lower == "name" || lower == "domain" || lower == "domain name" {
				continue
			}
		}
		description := ""
		if len(row) >= 2 {
			description = strings.TrimSpace(row[1])
		}
		active := true
		if len(row) >= 3 {
			active = parseBoolish(row[2])
		}
		_, err = r.Create(ctx, name, description, active, adminID)
		switch {
		case errors.Is(err, ErrAlreadyExists):
			out.Skipped++
		case err != nil:
			out.Errors = append(out.Errors, ImportError{Line: line, Domain: name, Reason: err.Error()})
		default:
			out.Created++
		}
	}
	return out, nil
}

// parseBoolish recognises "true", "yes", "1", "on" as true and the
// matching falsy strings. Empty / unknown inputs default to true so
// "name,description" two-column files keep the implicit "active" semantics.
func parseBoolish(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "false", "no", "0", "off", "disabled", "inactive":
		return false
	}
	return true
}

// ----- internals ----------------------------------------------------------

const selectQ = `SELECT id, name, description, active, created_by_admin_id, created_at, updated_at FROM domains`

type rowScanner interface{ Scan(dest ...any) error }

func scan(rs rowScanner) (Domain, error) {
	var (
		d                    Domain
		createdBy            sql.NullInt64
		createdAt, updatedAt any
	)
	err := rs.Scan(&d.ID, &d.Name, &d.Description, &d.Active, &createdBy, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Domain{}, ErrNotFound
	}
	if err != nil {
		return Domain{}, err
	}
	if createdBy.Valid {
		v := createdBy.Int64
		d.CreatedByAdminID = &v
	}
	if t, err := toTime(createdAt); err == nil {
		d.CreatedAt = t
	}
	if t, err := toTime(updatedAt); err == nil {
		d.UpdatedAt = t
	}
	return d, nil
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
