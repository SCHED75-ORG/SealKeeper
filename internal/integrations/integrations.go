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
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sched75/sealkeeper/internal/cryptobox"
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
	// ErrNoCryptobox is returned by Create when the Repo was built without
	// a cryptobox: credentials must never be persisted in clear.
	ErrNoCryptobox = errors.New("integrations: cryptobox required to store credentials")
)

// Integration is the row view consumed by handlers and dispatcher.
type Integration struct {
	ID               int64
	Name             string
	Kind             Kind
	Enabled          bool
	ConfigJSON       json.RawMessage // decrypted in memory; never render it back
	FiltersJSON      json.RawMessage // {"event_types": ["prefix1.","prefix2."]}
	CreatedByAdminID *int64
	CreatedAt        time.Time
	UpdatedAt        time.Time

	// ConfigErr is set when the sealed config could not be opened (master
	// secret rotated, tampered row). BuildSink refuses such a row.
	ConfigErr error
}

// Filters is the parsed form of FiltersJSON.
type Filters struct {
	EventTypes []string `json:"event_types"`
}

// ParseFilters strictly decodes a filters_json blob: unknown keys, wrong
// types, trailing data and blank entries are rejected (ErrInvalidConfig).
// An empty blob, `{}` or an empty event_types list means "forward
// everything" — but only when written that way on purpose; a malformed
// filter must never silently widen into forward-everything.
func ParseFilters(raw json.RawMessage) (Filters, error) {
	var f Filters
	if len(bytes.TrimSpace(raw)) == 0 {
		return f, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return Filters{}, fmt.Errorf("%w: filters_json: %s", ErrInvalidConfig, err.Error())
	}
	if dec.More() {
		return Filters{}, fmt.Errorf("%w: filters_json: trailing data", ErrInvalidConfig)
	}
	for _, p := range f.EventTypes {
		if strings.TrimSpace(p) == "" {
			return Filters{}, fmt.Errorf("%w: filters_json: blank event_types entry", ErrInvalidConfig)
		}
	}
	return f, nil
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

// Repo persists integrations. The kind-specific config (URLs, bearer
// tokens, HEC token, Sentinel shared key, basic-auth password, API keys)
// is stored AES-256-GCM-sealed in config_enc under a per-row AAD; the
// legacy clear config_json column is kept at '{}'.
type Repo struct {
	db  *sql.DB
	box *cryptobox.Box
	now func() time.Time
	pol NetPolicy
}

// NewRepo binds a Repo to a *sql.DB and the instance cryptobox.
func NewRepo(db *sql.DB, box *cryptobox.Box) *Repo {
	return &Repo{db: db, box: box, now: time.Now}
}

// WithNetPolicy sets the outbound policy Create validates new rows against
// (https required unless AllowPlainHTTP). The zero policy is the strict one.
func (r *Repo) WithNetPolicy(p NetPolicy) *Repo {
	c := *r
	c.pol = p
	return &c
}

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

// Create inserts a new integration. Validates that the kind is known, that
// the config parses and points somewhere sane for its kind, and that the
// filters decode strictly. The config is sealed with the row's AAD, which
// needs the id: the row is inserted disabled with an empty config, then
// sealed and enabled in a second statement (deleted again on failure).
func (r *Repo) Create(ctx context.Context, in CreateInputs, adminID *int64) (Integration, error) {
	if err := validateKind(in.Kind); err != nil {
		return Integration{}, err
	}
	if err := validateJSONObject(in.ConfigJSON, "config_json"); err != nil {
		return Integration{}, err
	}
	if err := validateKindConfig(in.Kind, json.RawMessage(canonJSON(in.ConfigJSON)), r.pol); err != nil {
		return Integration{}, err
	}
	if err := validateJSONObject(in.FiltersJSON, "filters_json"); err != nil {
		return Integration{}, err
	}
	if _, err := ParseFilters(json.RawMessage(in.FiltersJSON)); err != nil {
		return Integration{}, err
	}
	if r.box == nil {
		return Integration{}, ErrNoCryptobox
	}
	now := r.now().UTC()
	const q = `INSERT INTO integrations
		(name, kind, enabled, config_json, filters_json, created_by_admin_id, created_at, updated_at)
		VALUES (?, ?, ?, '{}', ?, ?, ?, ?)`
	id, err := storage.InsertReturningID(ctx, r.db, q,
		strings.TrimSpace(in.Name), string(in.Kind), false,
		canonJSON(in.FiltersJSON), nullableInt(adminID), now, now,
	)
	if err != nil {
		if storage.IsUniqueViolation(err) {
			return Integration{}, ErrAlreadyExists
		}
		return Integration{}, fmt.Errorf("integrations.Create: %w", err)
	}
	if err := r.sealConfig(ctx, id, canonJSON(in.ConfigJSON), in.Enabled); err != nil {
		_, _ = r.db.ExecContext(ctx, rebind(r.db, "DELETE FROM integrations WHERE id = ?"), id)
		return Integration{}, fmt.Errorf("integrations.Create: %w", err)
	}
	return r.Get(ctx, id)
}

// sealConfig encrypts `config` under the row AAD and stores it, clearing
// the legacy clear column and setting the enabled flag.
func (r *Repo) sealConfig(ctx context.Context, id int64, config string, enabled bool) error {
	enc, err := r.box.Seal([]byte(config), integrationAAD(id))
	if err != nil {
		return fmt.Errorf("seal config: %w", err)
	}
	_, err = r.db.ExecContext(ctx, rebind(r.db,
		`UPDATE integrations SET config_enc = ?, config_json = '{}', enabled = ? WHERE id = ?`),
		enc, enabled, id)
	return err
}

// SealLegacyConfigs encrypts every row still carrying its config in the
// clear config_json column (rows created before migration 0015). Run once
// at boot; idempotent. Returns the number of rows sealed.
func (r *Repo) SealLegacyConfigs(ctx context.Context) (int, error) {
	if r.box == nil {
		return 0, ErrNoCryptobox
	}
	todo, err := r.listLegacy(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, l := range todo {
		enc, err := r.box.Seal([]byte(canonJSON(l.cfg)), integrationAAD(l.id))
		if err != nil {
			return n, fmt.Errorf("integrations.SealLegacyConfigs: %w", err)
		}
		if _, err := r.db.ExecContext(ctx, rebind(r.db,
			`UPDATE integrations SET config_enc = ?, config_json = '{}'
				WHERE id = ? AND config_enc IS NULL`), enc, l.id); err != nil {
			return n, fmt.Errorf("integrations.SealLegacyConfigs: %w", err)
		}
		n++
	}
	return n, nil
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

type legacyConfig struct {
	id  int64
	cfg string
}

// listLegacy reads the clear rows first (and closes the cursor) so the
// UPDATEs below don't contend with an open result set on SQLite.
func (r *Repo) listLegacy(ctx context.Context) ([]legacyConfig, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, config_json FROM integrations WHERE config_enc IS NULL`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []legacyConfig
	for rows.Next() {
		var l legacyConfig
		if err := rows.Scan(&l.id, &l.cfg); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// Get returns one row by id.
func (r *Repo) Get(ctx context.Context, id int64) (Integration, error) {
	return r.scan(r.db.QueryRowContext(ctx, rebind(r.db, selectQ+" WHERE id = ?"), id))
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
		row, err := r.scan(rows)
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
		row, err := r.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// ----- internals ------------------------------------------------------------

const selectQ = `SELECT id, name, kind, enabled, config_json, config_enc, filters_json,
	created_by_admin_id, created_at, updated_at FROM integrations`

type rowScanner interface{ Scan(dest ...any) error }

func (r *Repo) scan(rs rowScanner) (Integration, error) {
	var (
		i          Integration
		kindStr    string
		configStr  string
		configEnc  []byte
		filtersStr string
		createdBy  sql.NullInt64
		createdAt  any
		updatedAt  any
	)
	err := rs.Scan(&i.ID, &i.Name, &kindStr, &i.Enabled, &configStr, &configEnc, &filtersStr,
		&createdBy, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Integration{}, ErrNotFound
	}
	if err != nil {
		return Integration{}, err
	}
	i.Kind = Kind(kindStr)
	switch {
	case len(configEnc) == 0:
		// Legacy clear row not yet sealed by SealLegacyConfigs.
		i.ConfigJSON = json.RawMessage(configStr)
	case r.box == nil:
		i.ConfigErr = ErrNoCryptobox
	default:
		pt, err := r.box.Open(configEnc, integrationAAD(i.ID))
		if err != nil {
			i.ConfigErr = fmt.Errorf("decrypt config: %w", err)
		} else {
			i.ConfigJSON = json.RawMessage(pt)
		}
	}
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

// integrationAAD binds a sealed config to its row, so a blob copied to
// another integration (or to another encrypted column) refuses to open.
func integrationAAD(id int64) []byte {
	h := sha256.Sum256([]byte("sealkeeper-integration:" + strconv.FormatInt(id, 10)))
	return h[:]
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
