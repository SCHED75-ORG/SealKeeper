// Package integrations owns the outbound sinks for SealKeeper audit events.
//
// PRD: FR-C.84..89 — Syslog RFC 5424, JSON webhook, Splunk HEC, Microsoft
// Sentinel (Log Analytics), Elastic _bulk are the supported kinds in v0.1.
//
// The package is split in four files:
//   - integrations.go: Repo (CRUD + filters) — this file.
//   - event.go: the Event format pushed through every sink.
//   - sink.go: the Sink interface and the factory that builds the right
//     sink from a stored Integration row.
//   - sink_http.go / sink_syslog.go: the two transports the v0.1 sinks
//     boil down to.
//   - dispatcher.go: the worker goroutine + buffered channel that fans
//     audit events out to enabled sinks without blocking callers.
package integrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sched75/sealkeeper/internal/storage"
)

// Kind enumerates the v0.1 sink types.
type Kind string

const (
	KindWebhook  Kind = "webhook"
	KindSplunk   Kind = "splunk"
	KindSentinel Kind = "sentinel"
	KindElastic  Kind = "elastic"
	KindSyslog   Kind = "syslog"
)

// Errors.
var (
	ErrNotFound      = errors.New("integrations: not found")
	ErrAlreadyExists = errors.New("integrations: name already exists")
	ErrInvalidKind   = errors.New("integrations: invalid kind")
	ErrInvalidConfig = errors.New("integrations: invalid config json")
)

// Integration is the row view consumed by handlers and dispatcher.
type Integration struct {
	ID               int64
	Name             string
	Kind             Kind
	Enabled          bool
	ConfigJSON       json.RawMessage // opaque; sink factory parses
	FiltersJSON      json.RawMessage // {"event_types": ["prefix1.","prefix2."]}
	CreatedByAdminID *int64
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Filters is the parsed form of FiltersJSON.
type Filters struct {
	EventTypes []string `json:"event_types"`
}

// Matches reports whether `eventType` should be forwarded to a sink with
// these filters. Empty filter set forwards everything.
func (f Filters) Matches(eventType string) bool {
	if len(f.EventTypes) == 0 {
		return true
	}
	for _, p := range f.EventTypes {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.HasSuffix(p, ".") {
			if strings.HasPrefix(eventType, p) {
				return true
			}
		} else if eventType == p {
			return true
		}
	}
	return false
}

// Repo persists integrations.
type Repo struct {
	db  *sql.DB
	now func() time.Time
}

// NewRepo binds a Repo to a *sql.DB.
func NewRepo(db *sql.DB) *Repo { return &Repo{db: db, now: time.Now} }

// WithClock for tests.
func (r *Repo) WithClock(now func() time.Time) *Repo {
	c := *r
	c.now = now
	return &c
}

// CreateInputs is the form payload accepted by the admin handler.
type CreateInputs struct {
	Name        string
	Kind        Kind
	Enabled     bool
	ConfigJSON  string
	FiltersJSON string
}

// Create inserts a new integration. Validates that the kind is known and
// that the JSON blobs parse.
func (r *Repo) Create(ctx context.Context, in CreateInputs, adminID *int64) (Integration, error) {
	if err := validateKind(in.Kind); err != nil {
		return Integration{}, err
	}
	if err := validateJSONObject(in.ConfigJSON, "config_json"); err != nil {
		return Integration{}, err
	}
	if err := validateJSONObject(in.FiltersJSON, "filters_json"); err != nil {
		return Integration{}, err
	}
	now := r.now().UTC()
	const q = `INSERT INTO integrations
		(name, kind, enabled, config_json, filters_json, created_by_admin_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	id, err := storage.InsertReturningID(ctx, r.db, q,
		strings.TrimSpace(in.Name), string(in.Kind), in.Enabled,
		canonJSON(in.ConfigJSON), canonJSON(in.FiltersJSON),
		nullableInt(adminID), now, now,
	)
	if err != nil {
		if storage.IsUniqueViolation(err) {
			return Integration{}, ErrAlreadyExists
		}
		return Integration{}, fmt.Errorf("integrations.Create: %w", err)
	}
	return r.Get(ctx, id)
}

// SetEnabled toggles the enabled flag.
func (r *Repo) SetEnabled(ctx context.Context, id int64, enabled bool) error {
	now := r.now().UTC()
	_, err := r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE integrations SET enabled = ?, updated_at = ? WHERE id = ?`),
		enabled, now, id)
	return err
}

// Delete removes a row.
func (r *Repo) Delete(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, rebind(r.db, "DELETE FROM integrations WHERE id = ?"), id)
	return err
}

// Get returns one row by id.
func (r *Repo) Get(ctx context.Context, id int64) (Integration, error) {
	return scan(r.db.QueryRowContext(ctx, rebind(r.db, selectQ+" WHERE id = ?"), id))
}

// List returns every row in name order.
func (r *Repo) List(ctx context.Context) ([]Integration, error) {
	rows, err := r.db.QueryContext(ctx, selectQ+" ORDER BY name ASC")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Integration
	for rows.Next() {
		row, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// ListEnabled returns enabled rows only — used by the dispatcher hot path.
func (r *Repo) ListEnabled(ctx context.Context) ([]Integration, error) {
	rows, err := r.db.QueryContext(ctx, selectQ+" WHERE enabled = TRUE ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Integration
	for rows.Next() {
		row, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// ----- internals ------------------------------------------------------------

const selectQ = `SELECT id, name, kind, enabled, config_json, filters_json,
	created_by_admin_id, created_at, updated_at FROM integrations`

type rowScanner interface{ Scan(dest ...any) error }

func scan(rs rowScanner) (Integration, error) {
	var (
		i          Integration
		kindStr    string
		configStr  string
		filtersStr string
		createdBy  sql.NullInt64
		createdAt  any
		updatedAt  any
	)
	err := rs.Scan(&i.ID, &i.Name, &kindStr, &i.Enabled, &configStr, &filtersStr,
		&createdBy, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Integration{}, ErrNotFound
	}
	if err != nil {
		return Integration{}, err
	}
	i.Kind = Kind(kindStr)
	i.ConfigJSON = json.RawMessage(configStr)
	i.FiltersJSON = json.RawMessage(filtersStr)
	if createdBy.Valid {
		v := createdBy.Int64
		i.CreatedByAdminID = &v
	}
	if t, err := toTime(createdAt); err == nil {
		i.CreatedAt = t
	}
	if t, err := toTime(updatedAt); err == nil {
		i.UpdatedAt = t
	}
	return i, nil
}

func validateKind(k Kind) error {
	switch k {
	case KindWebhook, KindSplunk, KindSentinel, KindElastic, KindSyslog:
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrInvalidKind, k)
	}
}

func validateJSONObject(raw, label string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var probe any
	if err := json.Unmarshal([]byte(raw), &probe); err != nil {
		return fmt.Errorf("%w: %s: %s", ErrInvalidConfig, label, err.Error())
	}
	if _, ok := probe.(map[string]any); !ok {
		return fmt.Errorf("%w: %s must be a JSON object", ErrInvalidConfig, label)
	}
	return nil
}

func canonJSON(s string) string {
	if strings.TrimSpace(s) == "" {
		return "{}"
	}
	return s
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
