// Package policies owns the per-(domain, ANSSI-level) generation policies
// and the email → policy resolver used by the request pipeline.
//
// PRD: FR-C.27..37 + FR-C.28 resolution rules:
//   - B1 covers every user of the domain not listed in B2/B3 (implicit).
//   - B2 applies ONLY to emails listed in the B2 elevation list.
//   - B3 applies ONLY to emails listed in the B3 elevation list.
//
// When a user's bucket doesn't have a matching active policy, the request
// is dropped silently (FR-B.13).
package policies

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sched75/sealkeeper/internal/domains"
	"github.com/sched75/sealkeeper/internal/elevations"
	"github.com/sched75/sealkeeper/internal/storage"
)

// Errors.
var (
	ErrNotFound      = errors.New("policies: not found")
	ErrAlreadyExists = errors.New("policies: already exists for this (domain, level)")
	ErrInvalidShape  = errors.New("policies: invalid shape")
	ErrNoPolicy      = errors.New("policies: no policy applies")
)

// Generator identifies the bundle generator.
type Generator string

const (
	GeneratorG1 Generator = "G1"
	GeneratorG2 Generator = "G2"
	GeneratorG3 Generator = "G3"
)

// Policy is the row view + the parsed params blob.
type Policy struct {
	ID                int64
	DomainID          int64
	DomainName        string
	ANSSILevel        elevations.Level
	Name              string
	Generator         Generator
	Params            json.RawMessage // raw to preserve admin-supplied ordering
	ProposalCount     int
	RegenerateLimit   int
	SessionTTLSeconds int
	NotifyOnConsult   bool
	Active            bool
	CreatedByAdminID  *int64
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// Repo persists policies and exposes the resolver. The domains + elevations
// repos are injected so Resolve can avoid duplicating the canonicalisation
// rules already encoded there.
type Repo struct {
	db         *sql.DB
	domains    *domains.Repo
	elevations *elevations.Repo
	now        func() time.Time
}

// NewRepo binds a Repo. domains and elevations may both be nil — in which
// case Resolve always returns ErrNoPolicy. The HTTP handler then falls
// back to its built-in default.
func NewRepo(db *sql.DB, doms *domains.Repo, elev *elevations.Repo) *Repo {
	return &Repo{db: db, domains: doms, elevations: elev, now: time.Now}
}

// WithClock for tests.
func (r *Repo) WithClock(now func() time.Time) *Repo {
	c := *r
	c.now = now
	return &c
}

// CreateInputs is the form data accepted by Create / Update.
type CreateInputs struct {
	DomainID          int64
	ANSSILevel        elevations.Level
	Name              string
	Generator         Generator
	ParamsJSON        string
	ProposalCount     int
	RegenerateLimit   int
	SessionTTLSeconds int
	NotifyOnConsult   bool
	Active            bool
}

// Create inserts a new policy. Validates that params_json parses, that the
// generator is known, and that the level is one of B1/B2/B3.
func (r *Repo) Create(ctx context.Context, in CreateInputs, adminID *int64) (Policy, error) {
	if err := validateInputs(in); err != nil {
		return Policy{}, err
	}
	now := r.now().UTC()
	const q = `INSERT INTO policies
		(domain_id, anssi_level, name, generator, params_json,
		 proposal_count, regenerate_limit, session_ttl_seconds,
		 notify_on_consult, active, created_by_admin_id, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`
	id, err := storage.InsertReturningID(ctx, r.db, q,
		in.DomainID, string(in.ANSSILevel), strings.TrimSpace(in.Name), string(in.Generator),
		canonJSON(in.ParamsJSON),
		defaultInt(in.ProposalCount, 5),
		defaultInt(in.RegenerateLimit, 3),
		defaultInt(in.SessionTTLSeconds, 900),
		in.NotifyOnConsult,
		in.Active,
		nullableInt(adminID),
		now, now,
	)
	if err != nil {
		if storage.IsUniqueViolation(err) {
			return Policy{}, ErrAlreadyExists
		}
		return Policy{}, fmt.Errorf("policies.Create: %w", err)
	}
	return r.Get(ctx, id)
}

// Update overwrites every editable field of a row.
func (r *Repo) Update(ctx context.Context, id int64, in CreateInputs) error {
	if err := validateInputs(in); err != nil {
		return err
	}
	now := r.now().UTC()
	_, err := r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE policies
			SET name = ?, generator = ?, params_json = ?,
			    proposal_count = ?, regenerate_limit = ?, session_ttl_seconds = ?,
			    notify_on_consult = ?, active = ?, updated_at = ?
			WHERE id = ?`),
		strings.TrimSpace(in.Name), string(in.Generator), canonJSON(in.ParamsJSON),
		defaultInt(in.ProposalCount, 5),
		defaultInt(in.RegenerateLimit, 3),
		defaultInt(in.SessionTTLSeconds, 900),
		in.NotifyOnConsult,
		in.Active,
		now, id,
	)
	return err
}

// SetActive flips the active flag.
func (r *Repo) SetActive(ctx context.Context, id int64, active bool) error {
	now := r.now().UTC()
	_, err := r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE policies SET active = ?, updated_at = ? WHERE id = ?`),
		active, now, id)
	return err
}

// Delete removes a row.
func (r *Repo) Delete(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, rebind(r.db, "DELETE FROM policies WHERE id = ?"), id)
	return err
}

// Get returns one row by id (joining domain name for display).
func (r *Repo) Get(ctx context.Context, id int64) (Policy, error) {
	return scan(r.db.QueryRowContext(ctx, rebind(r.db, selectQ+` WHERE p.id = ?`), id))
}

// FindByDomainLevel returns the row for a (domain, level) pair or
// ErrNotFound. Inactive rows are visible to admins via List() but hidden
// from Resolve().
func (r *Repo) FindByDomainLevel(ctx context.Context, domainID int64, level elevations.Level) (Policy, error) {
	const q = selectQ + ` WHERE p.domain_id = ? AND p.anssi_level = ?`
	return scan(r.db.QueryRowContext(ctx, rebind(r.db, q), domainID, string(level)))
}

// List returns every policy for `domainID` ordered by level.
func (r *Repo) List(ctx context.Context, domainID int64) ([]Policy, error) {
	rows, err := r.db.QueryContext(ctx,
		rebind(r.db, selectQ+` WHERE p.domain_id = ? ORDER BY p.anssi_level`), domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collect(rows)
}

// ListAll returns every policy across every domain — admin index page.
func (r *Repo) ListAll(ctx context.Context) ([]Policy, error) {
	rows, err := r.db.QueryContext(ctx, selectQ+` ORDER BY d.name, p.anssi_level`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collect(rows)
}

// Count returns the number of rows in the table.
func (r *Repo) Count(ctx context.Context) (int64, error) {
	var n int64
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM policies").Scan(&n)
	return n, err
}

// Resolve picks the policy that should govern `email`. The contract:
//
//   - if there's no allowlist row matching the email's domain → ErrNoPolicy
//   - read the elevation level (defaults to B1)
//   - find the active policy for (domain, level)
//   - if none → ErrNoPolicy
//
// The caller maps ErrNoPolicy to the silent FR-B.13 drop.
func (r *Repo) Resolve(ctx context.Context, email string) (Policy, error) {
	if r.domains == nil {
		return Policy{}, ErrNoPolicy
	}
	emailLower := strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndex(emailLower, "@")
	if at <= 0 || at+1 >= len(emailLower) {
		return Policy{}, ErrNoPolicy
	}
	dom, err := r.domains.FindMatching(ctx, emailLower[at+1:])
	if errors.Is(err, domains.ErrNotFound) {
		return Policy{}, ErrNoPolicy
	}
	if err != nil {
		// A database error is not "no policy": callers must not fall back
		// to a weaker default on a transient failure.
		return Policy{}, err
	}

	level := elevations.LevelB1
	if r.elevations != nil {
		lvl, err := r.elevations.LookupEmail(ctx, emailLower)
		switch {
		case err == nil:
			level = lvl
		case !errors.Is(err, elevations.ErrNotFound):
			return Policy{}, err // never downgrade to B1 on a lookup error
		}
	}

	p, err := r.FindByDomainLevel(ctx, dom.ID, level)
	if errors.Is(err, ErrNotFound) || (err == nil && !p.Active) {
		return Policy{}, ErrNoPolicy
	}
	if err != nil {
		return Policy{}, err
	}
	return p, nil
}

// ----- internals ------------------------------------------------------------

// selectQ joins the domain name for display. The d.name column is consumed
// by scan() into Policy.DomainName.
const selectQ = `SELECT p.id, p.domain_id, COALESCE(d.name, ''), p.anssi_level, p.name, p.generator, p.params_json,
	p.proposal_count, p.regenerate_limit, p.session_ttl_seconds,
	p.notify_on_consult, p.active, p.created_by_admin_id, p.created_at, p.updated_at
	FROM policies p LEFT JOIN domains d ON d.id = p.domain_id`

type rowScanner interface{ Scan(dest ...any) error }

func scan(rs rowScanner) (Policy, error) {
	var (
		p                                    Policy
		level, gen, name, params, domainName string
		createdBy                            sql.NullInt64
		createdAt, updatedAt                 any
	)
	err := rs.Scan(&p.ID, &p.DomainID, &domainName, &level, &name, &gen, &params,
		&p.ProposalCount, &p.RegenerateLimit, &p.SessionTTLSeconds,
		&p.NotifyOnConsult, &p.Active, &createdBy, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	if err != nil {
		return Policy{}, err
	}
	p.DomainName = domainName
	p.ANSSILevel = elevations.Level(level)
	p.Name = name
	p.Generator = Generator(gen)
	p.Params = json.RawMessage(params)
	if createdBy.Valid {
		v := createdBy.Int64
		p.CreatedByAdminID = &v
	}
	if t, err := toTime(createdAt); err == nil {
		p.CreatedAt = t
	}
	if t, err := toTime(updatedAt); err == nil {
		p.UpdatedAt = t
	}
	return p, nil
}

func collect(rows *sql.Rows) ([]Policy, error) {
	var out []Policy
	for rows.Next() {
		p, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func validateInputs(in CreateInputs) error {
	if in.DomainID == 0 {
		return fmt.Errorf("%w: domain_id required", ErrInvalidShape)
	}
	switch in.ANSSILevel {
	case elevations.LevelB1, elevations.LevelB2, elevations.LevelB3:
	default:
		return fmt.Errorf("%w: anssi_level %q", ErrInvalidShape, in.ANSSILevel)
	}
	switch in.Generator {
	case GeneratorG1, GeneratorG2, GeneratorG3:
	default:
		return fmt.Errorf("%w: generator %q", ErrInvalidShape, in.Generator)
	}
	if strings.TrimSpace(in.Name) == "" {
		return fmt.Errorf("%w: name required", ErrInvalidShape)
	}
	if in.ParamsJSON != "" {
		var probe any
		if err := json.Unmarshal([]byte(in.ParamsJSON), &probe); err != nil {
			return fmt.Errorf("%w: params_json: %s", ErrInvalidShape, err.Error())
		}
		if _, ok := probe.(map[string]any); !ok {
			return fmt.Errorf("%w: params_json must be a JSON object", ErrInvalidShape)
		}
	}
	return validateGeneratorParams(in.Generator, canonJSON(in.ParamsJSON),
		defaultInt(in.ProposalCount, 5), defaultInt(in.RegenerateLimit, 3))
}

// validateGeneratorParams rejects at save time what the browser bundle
// (web/src/params.js) refuses at reveal time, so an operator learns about a
// broken policy in the editor rather than from users whose links fail.
// proposalCount and regenerateLimit are the values that will be stored.
func validateGeneratorParams(gen Generator, paramsJSON string, proposalCount, regenerateLimit int) error {
	var params any
	if err := json.Unmarshal([]byte(paramsJSON), &params); err != nil {
		return fmt.Errorf("%w: params_json: %s", ErrInvalidShape, err.Error())
	}
	if err := bundleRefusal(gen, params, proposalCount, regenerateLimit); err != nil {
		return err
	}
	// Stricter than the bundle: a whitespace-only entry is a typo.
	if gen == GeneratorG1 || gen == GeneratorG2 {
		lib, _ := prop(params, "library")
		for _, e := range lib.([]any) {
			if strings.TrimSpace(e.(string)) == "" {
				return fmt.Errorf("%w: parameters.library contains an empty entry", ErrInvalidShape)
			}
		}
	}
	return nil
}

func canonJSON(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "{}"
	}
	return s
}

func defaultInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
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
