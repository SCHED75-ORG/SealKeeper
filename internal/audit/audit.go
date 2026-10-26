// Package audit owns the hash-chained, append-only event log.
//
// PRD: module E (FR-E.*) — every security-relevant event lands here. The
// chain root is the empty string; each entry's hash is
//
//	entry_hash = sha256_hex(prev_hash || "\n" || canonical(event))
//
// where canonical is the line-form built by canonicalize() below. The chain
// is verifiable offline against the binary's hash function alone — no need
// to trust the DB; an attacker who tampers with one row in the middle
// invalidates every subsequent entry_hash.
//
// At v0.1 the writer covers Append + VerifyChain. Detailed admin tooling
// (replay, diff, gaps) lands with module E.
package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sched75/sealkeeper/internal/storage"
)

// Event types — convenience constants. Callers may add their own ad-hoc
// strings; the writer doesn't validate them so module owners stay flexible.
const (
	EventTokenIssued     = "token.issued"
	EventTokenConsumed   = "token.consumed"
	EventRateLimited     = "request.rate_limited"
	EventRequestAccepted = "request.accepted"
	EventAdminLogin      = "admin.login"
	EventAdminLogout     = "admin.logout"
)

// Entry is the canonical view of a row in audit_log.
type Entry struct {
	SequenceNo int64
	OccurredAt time.Time
	EventType  string
	Actor      string
	Target     string
	Details    json.RawMessage // raw JSON object, canonicalised at write time
	PrevHash   string
	EntryHash  string
}

// Repo persists audit events.
type Repo struct {
	db  *sql.DB
	now func() time.Time
}

// NewRepo binds the audit writer to a *sql.DB.
func NewRepo(db *sql.DB) *Repo { return &Repo{db: db, now: time.Now} }

// WithClock returns a copy of the repo bound to a custom clock (tests).
func (r *Repo) WithClock(now func() time.Time) *Repo {
	c := *r
	c.now = now
	return &c
}

// Append writes a new entry. The previous hash is read inside the same
// transaction to guarantee chain integrity under concurrency.
func (r *Repo) Append(ctx context.Context, eventType, actor, target string, details map[string]any) (Entry, error) {
	if strings.TrimSpace(eventType) == "" {
		return Entry{}, errors.New("audit.Append: event_type required")
	}

	detailsJSON, err := canonicalJSON(details)
	if err != nil {
		return Entry{}, fmt.Errorf("audit.Append: canonical json: %w", err)
	}
	// The hash covers occurred_at, so it must be computed over exactly the
	// value the column hands back to VerifyChain. Postgres TIMESTAMPTZ keeps
	// microseconds (pgx truncates the rest); truncating here makes the
	// stored and hashed instants identical on both dialects. SQLite rows
	// written before this carry full nanoseconds in their TEXT column and
	// were hashed over them, so they still verify unchanged.
	now := r.now().UTC().Truncate(time.Microsecond)

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Entry{}, fmt.Errorf("audit.Append: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// SQLite runs one writer at a time, so the tail read below is stable.
	// Postgres READ COMMITTED would let two concurrent appends read the same
	// tail and fork the chain; an EXCLUSIVE table lock (readers unaffected)
	// serialises appenders the same way.
	if storage.IsPostgres(r.db) {
		if _, err := tx.ExecContext(ctx, `LOCK TABLE audit_log IN EXCLUSIVE MODE`); err != nil {
			return Entry{}, fmt.Errorf("audit.Append: lock: %w", err)
		}
	}

	var prevHash sql.NullString
	const sel = `SELECT entry_hash FROM audit_log ORDER BY sequence_no DESC LIMIT 1`
	if err := tx.QueryRowContext(ctx, sel).Scan(&prevHash); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Entry{}, fmt.Errorf("audit.Append: read prev: %w", err)
	}

	canonical := canonicalize(eventType, actor, target, detailsJSON, now)
	entryHash := chainHash(prevHash.String, canonical)

	const ins = `INSERT INTO audit_log
		(occurred_at, event_type, actor, target, details_json, prev_hash, entry_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	if _, err := tx.ExecContext(ctx, rebind(r.db, ins),
		now, eventType, nullable(actor), nullable(target), string(detailsJSON), prevHash.String, entryHash,
	); err != nil {
		return Entry{}, fmt.Errorf("audit.Append: insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Entry{}, fmt.Errorf("audit.Append: commit: %w", err)
	}
	return Entry{
		OccurredAt: now,
		EventType:  eventType,
		Actor:      actor,
		Target:     target,
		Details:    detailsJSON,
		PrevHash:   prevHash.String,
		EntryHash:  entryHash,
	}, nil
}

// Count returns the number of rows currently in the log.
func (r *Repo) Count(ctx context.Context) (int64, error) {
	var n int64
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log").Scan(&n)
	return n, err
}

// VerifyChain walks the log in sequence order and re-computes every
// entry_hash. Returns the sequence_no of the first bad row, or 0 when the
// chain is intact. The error is non-nil only on driver / scan failures.
//
// This is the foundation for the /__audit/verify admin endpoint (module E).
func (r *Repo) VerifyChain(ctx context.Context) (int64, error) {
	const q = `SELECT sequence_no, occurred_at, event_type, COALESCE(actor, ''),
		COALESCE(target, ''), details_json, prev_hash, entry_hash
		FROM audit_log ORDER BY sequence_no ASC`
	rows, err := r.db.QueryContext(ctx, q)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	previous := ""
	for rows.Next() {
		var (
			seq                                     int64
			occurred                                any
			evt, actor, target, prev, hash, details string
		)
		if err := rows.Scan(&seq, &occurred, &evt, &actor, &target, &details, &prev, &hash); err != nil {
			return 0, err
		}
		ts, err := toTime(occurred)
		if err != nil {
			return seq, nil
		}
		if prev != previous {
			return seq, nil
		}
		canonical := canonicalize(evt, actor, target, []byte(details), ts)
		if chainHash(prev, canonical) != hash {
			return seq, nil
		}
		previous = hash
	}
	return 0, rows.Err()
}

// ----- internals ------------------------------------------------------------

// canonicalize builds the byte slice that gets hashed. The format is a
// single newline-delimited record so future fields can be appended without
// invalidating older signatures.
func canonicalize(eventType, actor, target string, details []byte, occurred time.Time) []byte {
	var b strings.Builder
	b.WriteString(occurred.UTC().Format(time.RFC3339Nano))
	b.WriteByte('\n')
	b.WriteString(eventType)
	b.WriteByte('\n')
	b.WriteString(actor)
	b.WriteByte('\n')
	b.WriteString(target)
	b.WriteByte('\n')
	b.Write(details)
	return []byte(b.String())
}

// chainHash returns sha256_hex(prev || "\n" || canonical).
func chainHash(prev string, canonical []byte) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte{'\n'})
	h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil))
}

// canonicalJSON marshals the details map with sorted keys so the hash is
// independent of map iteration order. Empty/nil maps render as "{}".
func canonicalJSON(m map[string]any) ([]byte, error) {
	if len(m) == 0 {
		return []byte("{}"), nil
	}
	// encoding/json already sorts top-level map keys lexicographically. We
	// expose this as a separate helper so future versions can switch to a
	// fully recursive canonical form (RFC 8785 JCS) without changing call
	// sites.
	return json.Marshal(m)
}

// nullable converts an empty string into a NULL SQL value at insert time.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func rebind(db *sql.DB, query string) string { return storage.Rebind(db, query) }

// toTime mirrors internal/tokens' loose timestamp parser so VerifyChain
// works against SQLite (text) and Postgres (time.Time) alike.
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
