// Package audit owns the keyed, hash-chained, append-only event log.
//
// PRD: module E (FR-E.1, FR-E.3). Every security-relevant event lands in
// audit_log. Each row carries prev_hash (the entry_hash of the row before
// it; "" for the first row) and its own entry_hash.
//
// # Keyed chain (v2)
//
// Rows are authenticated with HMAC-SHA256 under audit_chain_key, a 32-byte
// key derived from the master secret by HKDF-SHA256 with
// info="sealkeeper-audit-v1" (see DeriveKey):
//
//	entry_hash = hex(HMAC(audit_chain_key, prev_hash || canonical_v2))
//	canonical_v2 = JSON array ["sealkeeper-audit-entry-v2", sequence_no,
//	               occurred_at (RFC 3339, µs), event_type, actor, target,
//	               details_json]
//
// The JSON array is unambiguous (no field can bleed into its neighbour)
// and binds sequence_no, so rows cannot be renumbered. Without the key,
// someone with write access to the database can no longer recompute the
// chain after editing a row.
//
// # Head anchor
//
// A per-row chain cannot reveal that its newest rows were deleted. The
// single-row table audit_head (migration 0014) therefore pins the head:
// head_seq and head_hash of the newest row, legacy_until (below), and a
// sticky broken_seq, all bound together by head_mac, an HMAC under the
// same key over a JSON array tagged "sealkeeper-audit-head-v1". Append
// advances the anchor in the same transaction as the insert. VerifyChain
// reports a break when the anchor's MAC is wrong, when it is missing or
// unsealed while the log is non-empty, or when it no longer matches the
// newest row (tail truncation, or rows added without the key). The domain
// tags keep entry and head MACs from ever being confused with each other.
//
// # Legacy rows (v1) and cut-over
//
// Deployments that predate the keyed chain hold rows hashed with plain
// SHA-256:
//
//	entry_hash = sha256_hex(prev_hash || "\n" || canonical_v1(event))
//
// Migration 0014 records the highest sequence_no present at migration time
// as audit_head.legacy_until. Rows at or below it keep verifying as v1;
// every later row must verify as v2. legacy_until is bound by head_mac once
// the anchor is sealed, so it cannot be raised to downgrade newer rows.
// Legacy rows are protected indirectly: the first v2 row (or the sealed
// anchor) commits to the last legacy entry_hash, so rewriting them breaks
// the keyed part of the chain.
//
// Sealing: the anchor starts unsealed (head_mac = ""). The first Append
// seals it on an empty log; SealAnchor seals a freshly migrated legacy
// log, but only when told that the calling process itself just applied
// migration 0014 (storage MigrateUpApplied reports it). That is the only
// path that accepts an unsealed anchor in front of existing rows. At any
// other time (an ordinary boot, Append) the state is indistinguishable
// from a keyless downgrade — rows rehashed as v1, legacy_until raised and
// the anchor reset — so it is treated as tampering and recorded in
// broken_seq.
//
// Residual risk, by design of a symmetric scheme: an attacker who wipes the
// whole log and resets the anchor to its unsealed state leaves an empty,
// consistent log. Likewise, one who rolls the schema back to before 0014
// (drops audit_head and every later migration's objects, deletes their
// goose_db_version rows) makes the next migration re-run the cut-over.
// Continuity across either point is only visible from the outside (the
// SIEM receives real sequence numbers, so it sees the gap or the rewrite).
package audit

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
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

const (
	// keyInfo is the HKDF info string mandated by FR-E.3.
	keyInfo = "sealkeeper-audit-v1"
	// KeySize is the length of the audit chain key in bytes.
	KeySize = 32

	// HeadMigration is the schema version that creates audit_head and
	// records the legacy cut-over (see SealAnchor).
	HeadMigration int64 = 14

	entryTag = "sealkeeper-audit-entry-v2"
	headTag  = "sealkeeper-audit-head-v1"
)

// ErrNoKey is returned when the repo was built without an audit chain key.
var ErrNoKey = errors.New("audit: no chain key configured")

// DeriveKey derives audit_chain_key from the master secret (FR-E.3):
// HKDF-SHA256, no salt, info="sealkeeper-audit-v1", 32 bytes.
func DeriveKey(masterSecret string) ([]byte, error) {
	if masterSecret == "" {
		return nil, errors.New("audit.DeriveKey: empty master secret")
	}
	return hkdf.Key(sha256.New, []byte(masterSecret), nil, keyInfo, KeySize)
}

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
	key []byte
	now func() time.Time
}

// NewRepo binds the audit writer to a *sql.DB and the audit chain key
// (see DeriveKey). The key is copied.
func NewRepo(db *sql.DB, key []byte) *Repo {
	return &Repo{db: db, key: append([]byte(nil), key...), now: time.Now}
}

// WithClock returns a copy of the repo bound to a custom clock (tests).
func (r *Repo) WithClock(now func() time.Time) *Repo {
	c := *r
	c.now = now
	return &c
}

// head mirrors the audit_head row.
type head struct {
	present     bool
	legacyUntil int64
	seq         int64
	hash        string
	broken      int64
	mac         string
}

// tail is the newest audit_log row (seq 0 when the log is empty).
type tail struct {
	seq  int64
	hash string
}

// Append writes a new entry and advances the head anchor in the same
// transaction.
func (r *Repo) Append(ctx context.Context, eventType, actor, target string, details map[string]any) (Entry, error) {
	if strings.TrimSpace(eventType) == "" {
		return Entry{}, errors.New("audit.Append: event_type required")
	}
	if len(r.key) == 0 {
		return Entry{}, fmt.Errorf("audit.Append: %w", ErrNoKey)
	}

	detailsJSON, err := canonicalJSON(details)
	if err != nil {
		return Entry{}, fmt.Errorf("audit.Append: canonical json: %w", err)
	}
	// The MAC covers occurred_at, so it must be computed over exactly the
	// value the column hands back to VerifyChain. Postgres TIMESTAMPTZ keeps
	// microseconds (pgx truncates the rest); truncating here makes the
	// stored and authenticated instants identical on both dialects.
	now := r.now().UTC().Truncate(time.Microsecond)

	tx, err := r.lockedTx(ctx)
	if err != nil {
		return Entry{}, fmt.Errorf("audit.Append: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	h, err := readHead(ctx, tx)
	if err != nil {
		return Entry{}, fmt.Errorf("audit.Append: read head: %w", err)
	}
	t, err := readTail(ctx, tx)
	if err != nil {
		return Entry{}, fmt.Errorf("audit.Append: read prev: %w", err)
	}

	// Carry a valid sticky marker forward; otherwise record whatever the
	// anchor proves broken right now, so the evidence survives this write.
	broken := r.anchorBreak(h, t, false)
	if r.headValid(h) && h.broken != 0 {
		broken = h.broken
	}

	const ins = `INSERT INTO audit_log
		(occurred_at, event_type, actor, target, details_json, prev_hash, entry_hash)
		VALUES (?, ?, ?, ?, ?, ?, '') RETURNING sequence_no`
	var seq int64
	if err := tx.QueryRowContext(ctx, rebind(r.db, ins),
		now, eventType, nullable(actor), nullable(target), string(detailsJSON), t.hash,
	).Scan(&seq); err != nil {
		return Entry{}, fmt.Errorf("audit.Append: insert: %w", err)
	}
	entryHash := r.entryMAC(t.hash, canonicalV2(seq, now, eventType, actor, target, string(detailsJSON)))
	if _, err := tx.ExecContext(ctx, rebind(r.db,
		`UPDATE audit_log SET entry_hash = ? WHERE sequence_no = ?`), entryHash, seq); err != nil {
		return Entry{}, fmt.Errorf("audit.Append: set hash: %w", err)
	}

	next := head{present: true, legacyUntil: h.legacyUntil, seq: seq, hash: entryHash, broken: broken}
	if err := r.writeHead(ctx, tx, next); err != nil {
		return Entry{}, fmt.Errorf("audit.Append: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Entry{}, fmt.Errorf("audit.Append: commit: %w", err)
	}
	return Entry{
		SequenceNo: seq,
		OccurredAt: now,
		EventType:  eventType,
		Actor:      actor,
		Target:     target,
		Details:    detailsJSON,
		PrevHash:   t.hash,
		EntryHash:  entryHash,
	}, nil
}

// SealAnchor seals an unsealed head anchor over the current tail. An
// already sealed anchor is left untouched, so a tampered anchor is never
// re-blessed.
//
// legacyMigrated must be true only when this very process just applied
// migration HeadMigration (see the package comment): that is the one moment
// an unsealed anchor in front of existing rows is the genuine cut-over
// state. Any other time the same state is what someone with database
// write access but no key leaves behind after rewriting the log as v1 and
// resetting the anchor, so it is sealed with the break recorded instead.
func (r *Repo) SealAnchor(ctx context.Context, legacyMigrated bool) error {
	if len(r.key) == 0 {
		return fmt.Errorf("audit.SealAnchor: %w", ErrNoKey)
	}
	tx, err := r.lockedTx(ctx)
	if err != nil {
		return fmt.Errorf("audit.SealAnchor: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	h, err := readHead(ctx, tx)
	if err != nil {
		return fmt.Errorf("audit.SealAnchor: read head: %w", err)
	}
	if h.present && h.mac != "" {
		return nil
	}
	t, err := readTail(ctx, tx)
	if err != nil {
		return fmt.Errorf("audit.SealAnchor: read tail: %w", err)
	}
	next := head{
		present:     true,
		legacyUntil: h.legacyUntil,
		seq:         t.seq,
		hash:        t.hash,
		broken:      r.anchorBreak(h, t, legacyMigrated),
	}
	if err := r.writeHead(ctx, tx, next); err != nil {
		return fmt.Errorf("audit.SealAnchor: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit.SealAnchor: commit: %w", err)
	}
	return nil
}

// Count returns the number of rows currently in the log.
func (r *Repo) Count(ctx context.Context) (int64, error) {
	var n int64
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log").Scan(&n)
	return n, err
}

// VerifyChain walks the log in sequence order, re-computes every
// entry_hash (SHA-256 for legacy rows, HMAC for keyed rows) and checks the
// head anchor. It returns the sequence_no of the first broken entry, or 0
// when the chain is intact. For a truncated tail that is the first missing
// sequence number; when the anchor itself is missing, unsealed in front of
// existing rows, or forged, the whole chain is unproven and 1 is reported
// (or the anchor's head_seq for a forged anchor). The error is non-nil
// only on driver / scan failures or a missing key.
//
// This is the foundation for the /admin/audit integrity badge (FR-E.6).
func (r *Repo) VerifyChain(ctx context.Context) (int64, error) {
	if len(r.key) == 0 {
		return 0, fmt.Errorf("audit.VerifyChain: %w", ErrNoKey)
	}
	// Anchor and rows must come from one snapshot, or an Append committing
	// in between would look like a truncation.
	var opts *sql.TxOptions
	if storage.IsPostgres(r.db) {
		opts = &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}
	}
	tx, err := r.db.BeginTx(ctx, opts)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	h, err := readHead(ctx, tx)
	if err != nil {
		return 0, err
	}
	rowBad, t, err := r.verifyRows(ctx, tx, h.legacyUntil)
	if err != nil {
		return 0, err
	}
	anchorBad := r.anchorBreak(h, t, false)
	if r.headValid(h) && h.broken != 0 && (anchorBad == 0 || h.broken < anchorBad) {
		anchorBad = h.broken
	}
	switch {
	case rowBad == 0:
		return anchorBad, nil
	case anchorBad == 0 || rowBad < anchorBad:
		return rowBad, nil
	default:
		return anchorBad, nil
	}
}

// verifyRows checks every row and returns the first bad sequence_no (0 if
// none) together with the newest row.
func (r *Repo) verifyRows(ctx context.Context, tx *sql.Tx, legacyUntil int64) (int64, tail, error) {
	const q = `SELECT sequence_no, occurred_at, event_type, COALESCE(actor, ''),
		COALESCE(target, ''), details_json, prev_hash, entry_hash
		FROM audit_log ORDER BY sequence_no ASC`
	rows, err := tx.QueryContext(ctx, q)
	if err != nil {
		return 0, tail{}, err
	}
	defer rows.Close()

	var (
		bad  int64
		last tail
	)
	for rows.Next() {
		var (
			seq                                     int64
			occurred                                any
			evt, actor, target, prev, hash, details string
		)
		if err := rows.Scan(&seq, &occurred, &evt, &actor, &target, &details, &prev, &hash); err != nil {
			return 0, tail{}, err
		}
		if bad == 0 && !r.rowValid(seq, occurred, evt, actor, target, details, prev, hash, last.hash, legacyUntil) {
			bad = seq
		}
		last = tail{seq: seq, hash: hash}
	}
	return bad, last, rows.Err()
}

func (r *Repo) rowValid(seq int64, occurred any, evt, actor, target, details, prev, hash, previous string, legacyUntil int64) bool {
	if prev != previous {
		return false
	}
	ts, err := toTime(occurred)
	if err != nil {
		return false
	}
	var want string
	if seq <= legacyUntil {
		want = chainHash(prev, canonicalize(evt, actor, target, []byte(details), ts))
	} else {
		want = r.entryMAC(prev, canonicalV2(seq, ts, evt, actor, target, details))
	}
	return hmac.Equal([]byte(want), []byte(hash))
}

// anchorBreak returns the first sequence number the anchor shows to be
// broken given the newest row, or 0 when they agree. allowUnsealedLegacy
// accepts the post-migration state (unsealed anchor, rows only at or below
// legacy_until); only SealAnchor right after migration 0014 passes true.
func (r *Repo) anchorBreak(h head, t tail, allowUnsealedLegacy bool) int64 {
	switch {
	case !h.present:
		if t.seq == 0 {
			return 0
		}
		return 1
	case h.mac == "":
		switch {
		case t.seq == 0:
			return 0
		case t.seq > h.legacyUntil:
			return h.legacyUntil + 1
		case allowUnsealedLegacy:
			return 0
		default:
			return 1
		}
	case !r.headValid(h):
		return max(h.seq, 1)
	case t.seq < h.seq:
		return t.seq + 1
	case t.seq > h.seq:
		return h.seq + 1
	case t.hash != h.hash:
		return max(t.seq, 1)
	}
	return 0
}

func (r *Repo) headMAC(h head) string {
	msg, _ := json.Marshal([]any{headTag, h.legacyUntil, h.seq, h.hash, h.broken})
	m := hmac.New(sha256.New, r.key)
	m.Write(msg)
	return hex.EncodeToString(m.Sum(nil))
}

func (r *Repo) headValid(h head) bool {
	return h.present && h.mac != "" && hmac.Equal([]byte(h.mac), []byte(r.headMAC(h)))
}

// entryMAC returns hex(HMAC(key, prev || canonical)) (FR-E.1).
func (r *Repo) entryMAC(prev string, canonical []byte) string {
	m := hmac.New(sha256.New, r.key)
	m.Write([]byte(prev))
	m.Write(canonical)
	return hex.EncodeToString(m.Sum(nil))
}

// lockedTx opens a write transaction that serialises chain writers.
// SQLite runs one writer at a time, so the tail read is stable. Postgres
// READ COMMITTED would let two concurrent appends read the same tail and
// fork the chain; an EXCLUSIVE table lock (readers unaffected) serialises
// appenders the same way.
func (r *Repo) lockedTx(ctx context.Context) (*sql.Tx, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	if storage.IsPostgres(r.db) {
		if _, err := tx.ExecContext(ctx, `LOCK TABLE audit_log IN EXCLUSIVE MODE`); err != nil {
			_ = tx.Rollback()
			return nil, fmt.Errorf("lock: %w", err)
		}
	}
	return tx, nil
}

func readHead(ctx context.Context, tx *sql.Tx) (head, error) {
	h := head{present: true}
	err := tx.QueryRowContext(ctx,
		`SELECT legacy_until, head_seq, head_hash, broken_seq, head_mac FROM audit_head WHERE id = 1`,
	).Scan(&h.legacyUntil, &h.seq, &h.hash, &h.broken, &h.mac)
	if errors.Is(err, sql.ErrNoRows) {
		return head{}, nil
	}
	return h, err
}

func readTail(ctx context.Context, tx *sql.Tx) (tail, error) {
	var t tail
	err := tx.QueryRowContext(ctx,
		`SELECT sequence_no, entry_hash FROM audit_log ORDER BY sequence_no DESC LIMIT 1`,
	).Scan(&t.seq, &t.hash)
	if errors.Is(err, sql.ErrNoRows) {
		return tail{}, nil
	}
	return t, err
}

// writeHead seals h and stores it, re-creating the row if it was deleted.
func (r *Repo) writeHead(ctx context.Context, tx *sql.Tx, h head) error {
	mac := r.headMAC(h)
	res, err := tx.ExecContext(ctx, rebind(r.db,
		`UPDATE audit_head SET legacy_until = ?, head_seq = ?, head_hash = ?, broken_seq = ?, head_mac = ?
		 WHERE id = 1`), h.legacyUntil, h.seq, h.hash, h.broken, mac)
	if err != nil {
		return fmt.Errorf("update head: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n > 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, rebind(r.db,
		`INSERT INTO audit_head (id, legacy_until, head_seq, head_hash, broken_seq, head_mac)
		 VALUES (1, ?, ?, ?, ?, ?)`), h.legacyUntil, h.seq, h.hash, h.broken, mac); err != nil {
		return fmt.Errorf("insert head: %w", err)
	}
	return nil
}

// ----- canonical forms -------------------------------------------------------

// canonicalV2 is the unambiguous record authenticated by the keyed chain.
func canonicalV2(seq int64, occurred time.Time, eventType, actor, target, details string) []byte {
	b, _ := json.Marshal([]any{
		entryTag, seq, occurred.UTC().Format(time.RFC3339Nano), eventType, actor, target, details,
	})
	return b
}

// canonicalize builds the legacy (v1) record: newline-delimited fields.
// Only used to verify rows at or below legacy_until.
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

// chainHash returns the legacy (v1) sha256_hex(prev || "\n" || canonical).
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
