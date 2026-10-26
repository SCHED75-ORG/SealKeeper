// Package tokens owns the request_tokens table: minting opaque single-use
// bearer tokens for the reveal flow (FR-B.18, FR-B.36..38) and consuming them
// atomically.
//
// The repository is dialect-agnostic — it speaks to *sql.DB through whichever
// driver the [storage.Store] handed it. Queries stay portable between
// Postgres and SQLite by sticking to ANSI SQL plus a CASE-driven
// "only mark consumed if still consumable" UPDATE.
package tokens

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sched75/sealkeeper/internal/storage"
)

// Token bit length. 256 bits is comfortably above the FR-B.18 floor (128 bits).
const tokenRandomBytes = 32

// DefaultTTL is the lifetime of an unconsumed request token (FR-B PRD).
const DefaultTTL = 15 * time.Minute

// Errors returned by the repository.
var (
	ErrNotFound = errors.New("tokens: not found")
	ErrConsumed = errors.New("tokens: already consumed")
	ErrExpired  = errors.New("tokens: expired")
)

// Token is the row we ever expose to callers.
type Token struct {
	Token      string
	Email      string
	Domain     string
	IssuedAt   time.Time
	ExpiresAt  time.Time
	ConsumedAt *time.Time
}

// IssueOptions controls the call to Issue.
type IssueOptions struct {
	Email  string
	Domain string
	IPHash string // hashed at the caller for privacy (FR-I.* RGPD)
	UAHash string
	TTL    time.Duration // 0 → DefaultTTL
}

// Repo persists request tokens.
type Repo struct {
	db  *sql.DB
	now func() time.Time // injectable for tests
}

// NewRepo binds a repository to a *sql.DB.
func NewRepo(db *sql.DB) *Repo { return &Repo{db: db, now: time.Now} }

// WithClock returns a copy of the repo using the given clock. Tests use this
// to time-travel without sleeping.
func (r *Repo) WithClock(now func() time.Time) *Repo {
	c := *r
	c.now = now
	return &c
}

// Issue mints a fresh token and stores it. Returns the new Token row.
func (r *Repo) Issue(ctx context.Context, opts IssueOptions) (Token, error) {
	if strings.TrimSpace(opts.Email) == "" {
		return Token{}, errors.New("tokens.Issue: email is required")
	}
	if strings.TrimSpace(opts.Domain) == "" {
		idx := strings.LastIndex(opts.Email, "@")
		if idx > 0 && idx+1 < len(opts.Email) {
			opts.Domain = strings.ToLower(opts.Email[idx+1:])
		} else {
			opts.Domain = "unknown"
		}
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}

	raw := make([]byte, tokenRandomBytes)
	if _, err := rand.Read(raw); err != nil {
		return Token{}, fmt.Errorf("tokens.Issue: read random: %w", err)
	}
	tok := base64.RawURLEncoding.EncodeToString(raw)

	issued := r.now().UTC()
	expires := issued.Add(ttl)

	const q = `INSERT INTO request_tokens
		(token, email, domain, requested_ip_hash, requested_ua_hash, issued_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	if _, err := r.db.ExecContext(ctx, rebind(r.db, q),
		tok, strings.ToLower(opts.Email), strings.ToLower(opts.Domain),
		nullable(opts.IPHash), nullable(opts.UAHash),
		issued, expires,
	); err != nil {
		return Token{}, fmt.Errorf("tokens.Issue: insert: %w", err)
	}
	return Token{
		Token:     tok,
		Email:     strings.ToLower(opts.Email),
		Domain:    strings.ToLower(opts.Domain),
		IssuedAt:  issued,
		ExpiresAt: expires,
	}, nil
}

// Consume marks a token as used and returns the row that was consumed.
// Atomic: a second concurrent call will return ErrConsumed for one of them.
func (r *Repo) Consume(ctx context.Context, token string, ipHash, uaHash string) (Token, error) {
	if strings.TrimSpace(token) == "" {
		return Token{}, ErrNotFound
	}

	now := r.now().UTC()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Token{}, fmt.Errorf("tokens.Consume: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	row, err := scanRow(tx.QueryRowContext(ctx, rebind(r.db, selectQ), token))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Token{}, ErrNotFound
		}
		return Token{}, fmt.Errorf("tokens.Consume: select: %w", err)
	}

	if row.ConsumedAt != nil {
		return row, ErrConsumed
	}
	if !now.Before(row.ExpiresAt) {
		return row, ErrExpired
	}

	const upd = `UPDATE request_tokens
		SET consumed_at = ?, consumed_ip_hash = ?, consumed_ua_hash = ?
		WHERE token = ? AND consumed_at IS NULL`
	res, err := tx.ExecContext(ctx, rebind(r.db, upd), now, nullable(ipHash), nullable(uaHash), token)
	if err != nil {
		return Token{}, fmt.Errorf("tokens.Consume: update: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		// Lost the race — somebody else consumed it between our SELECT and UPDATE.
		return row, ErrConsumed
	}

	if err := tx.Commit(); err != nil {
		return Token{}, fmt.Errorf("tokens.Consume: commit: %w", err)
	}
	row.ConsumedAt = &now
	return row, nil
}

// Get returns the row without mutating it. Returns ErrNotFound for missing
// tokens. Useful for the reveal page to check token state before the user
// actually clicks "Décoder".
func (r *Repo) Get(ctx context.Context, token string) (Token, error) {
	row, err := scanRow(r.db.QueryRowContext(ctx, rebind(r.db, selectQ), token))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Token{}, ErrNotFound
		}
		return Token{}, err
	}
	return row, nil
}

const selectQ = `SELECT token, email, domain, issued_at, expires_at, consumed_at
	FROM request_tokens WHERE token = ?`

// rowScanner abstracts *sql.Row and *sql.Rows so scanRow works for both.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanRow reads a request_tokens row, tolerating both time.Time (Postgres,
// driver-decoded) and string (SQLite, raw TIMESTAMP text) representations
// for the timestamp columns.
func scanRow(rs rowScanner) (Token, error) {
	var (
		row         Token
		issuedRaw   any
		expiresRaw  any
		consumedRaw any
	)
	if err := rs.Scan(&row.Token, &row.Email, &row.Domain, &issuedRaw, &expiresRaw, &consumedRaw); err != nil {
		return Token{}, err
	}
	t, err := toTime(issuedRaw)
	if err != nil {
		return Token{}, fmt.Errorf("tokens: parse issued_at: %w", err)
	}
	row.IssuedAt = t
	t, err = toTime(expiresRaw)
	if err != nil {
		return Token{}, fmt.Errorf("tokens: parse expires_at: %w", err)
	}
	row.ExpiresAt = t
	if consumedRaw != nil {
		t, err = toTime(consumedRaw)
		if err != nil {
			return Token{}, fmt.Errorf("tokens: parse consumed_at: %w", err)
		}
		row.ConsumedAt = &t
	}
	return row, nil
}

// toTime accepts time.Time (pgx) or string (SQLite TIMESTAMP textual form)
// and returns a UTC time.Time.
func toTime(v any) (time.Time, error) {
	switch x := v.(type) {
	case time.Time:
		return x.UTC(), nil
	case []byte:
		return parseTimestampString(string(x))
	case string:
		return parseTimestampString(x)
	case nil:
		return time.Time{}, errors.New("nil time value")
	default:
		return time.Time{}, fmt.Errorf("unsupported time type %T", v)
	}
}

func parseTimestampString(s string) (time.Time, error) {
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		// modernc.org/sqlite encodes time.Time values via fmt.Sprint, which
		// yields Go's default `2006-01-02 15:04:05.999999999 -0700 MST`.
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02 15:04:05.999999999 -07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse timestamp %q", s)
}

// nullable converts an empty string into a NULL value at insert time.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func rebind(db *sql.DB, query string) string { return storage.Rebind(db, query) }
