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
// A sealed anchor stays MAC-valid forever, so on its own it cannot reveal
// that an older copy of it was written back over a tail cut to match.
// The Repo therefore also keeps an in-memory high-water mark: the highest
// head_seq it has written or seen under a valid MAC (SealAnchor learns it
// at boot). A valid anchor below that mark is reported as broken from
// head_seq+1, and the next Append records it in broken_seq so the
// evidence outlives the process. Restoring a database backup under a
// running server looks exactly the same, so restart it after a restore.
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
// Sealing: the anchor starts unsealed (head_mac = ""). SealCutover seals a
// freshly migrated legacy log inside the very transaction that applies
// migration 0014 (storage MigrateUpCutover), so the schema change and the
// seal commit together or not at all. That is the only path that accepts
// an unsealed anchor in front of existing rows. At any other time (an
// ordinary boot, Append, SealAnchor) the state is indistinguishable from a
// keyless downgrade — rows rehashed as v1, legacy_until raised and the
// anchor reset — so it is treated as tampering and recorded in
// broken_seq. On an empty log the first Append or SealAnchor seals it.
//
// # Retention (FR-I.31, FR-I.37)
//
// Prune deletes the oldest rows once they exceed the retention period. The
// hashed content of the surviving rows is never rewritten: pseudonymising
// a row in place would change what its MAC covers and break every later
// link. Personal data in audit details therefore lives exactly as long as
// the row that carries it, and leaves with it (PRD D-I.23). To keep the
// shortened chain verifiable, the anchor also records a base: base_seq and
// base_hash of the newest deleted row (migration 0017). The oldest
// surviving row must chain onto base_hash instead of "". The base is bound
// by head_mac, which switches to the domain tag "sealkeeper-audit-head-v2"
// once a base is set (an unpruned log keeps the v1 form, so anchors sealed
// before 0017 stay valid). Deleting old rows without the key therefore
// still breaks the chain: the next row no longer links to the base, and
// moving the base needs a new head_mac. Prune refuses to run on a chain
// that does not verify, so it never destroys the evidence of a break.
//
// Residual risk, by design of a symmetric scheme: an attacker who wipes the
// whole log and resets the anchor to its unsealed state leaves an empty,
// consistent log. Likewise, one who rolls the schema back to before 0014
// (drops audit_head and every later migration's objects, deletes their
// goose_db_version rows) makes the next migration re-run the cut-over.
// A selective rollback of the tail is the same kind of residual risk: an
// attacker who keeps a copy of the sealed audit_head row, later deletes the
// rows appended after it and writes the copy back leaves a consistent,
// shorter log. The high-water mark catches this only while a process that
// saw the newer head keeps running; across a restart just a sequence_no
// gap remains (not checked: Postgres sequences burn values on rollback),
// and the attacker can close it by resetting the sequence. Continuity
// across any of these points is only visible from the outside (the SIEM
// receives real sequence numbers, so it sees the gap or the rewrite).
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
	"sync/atomic"
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

	// FR-B.38: refused opening attempts of a reveal link.
	EventTokenReuseAttempt   = "token.reuse_attempt"
	EventTokenExpiredAttempt = "token.expired_attempt"
	EventTokenUnknownAttempt = "token.unknown_attempt"
	// EventRateLimitedSummary folds the request.rate_limited hits of one
	// key over a window (see httpserver/ratelimitaudit.go).
	EventRateLimitedSummary = "request.rate_limited.summary"
)

const (
	// keyInfo is the HKDF info string mandated by FR-E.3.
	keyInfo = "sealkeeper-audit-v1"
	// KeySize is the length of the audit chain key in bytes.
	KeySize = 32

	// HeadMigration is the schema version that creates audit_head and
	// records the legacy cut-over (see SealCutover).
	HeadMigration = storage.AuditHeadMigration

	entryTag  = "sealkeeper-audit-entry-v2"
	headTag   = "sealkeeper-audit-head-v1"
	headTagV2 = "sealkeeper-audit-head-v2"
)

// ErrNoKey is returned when the repo was built without an audit chain key.
var ErrNoKey = errors.New("audit: no chain key configured")

// ErrChainBroken is returned by Prune when the chain does not verify:
// deleting rows then could destroy the evidence of the break.
var ErrChainBroken = errors.New("audit: chain does not verify")

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
	// floor is the highest head_seq this process has written or seen
	// under a valid MAC (see the package comment); shared by WithClock
	// copies.
	floor *atomic.Int64
}

// NewRepo binds the audit writer to a *sql.DB and the audit chain key
// (see DeriveKey). The key is copied.
func NewRepo(db *sql.DB, key []byte) *Repo {
	return &Repo{db: db, key: append([]byte(nil), key...), now: time.Now, floor: new(atomic.Int64)}
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
	// baseSeq / baseHash: the newest row deleted by Prune (0 / "" when the
	// log was never pruned). The oldest surviving row chains onto baseHash.
	baseSeq  int64
	baseHash string
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

	floor := r.floor.Load()
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
	broken := r.anchorBreak(h, t, floor, false)
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

	next := head{present: true, legacyUntil: h.legacyUntil, seq: seq, hash: entryHash, broken: broken,
		baseSeq: h.baseSeq, baseHash: h.baseHash}
	if err := r.writeHead(ctx, tx, next); err != nil {
		return Entry{}, fmt.Errorf("audit.Append: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Entry{}, fmt.Errorf("audit.Append: commit: %w", err)
	}
	r.raiseFloor(seq)
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
// legacyMigrated may be true only right after migration HeadMigration was
// applied without SealCutover, with nothing else run since (tests do
// this). Any other time an unsealed anchor in front of existing rows is
// what someone with database write access but no key leaves behind after
// rewriting the log as v1 and resetting the anchor, so it is sealed with
// the break recorded instead.
func (r *Repo) SealAnchor(ctx context.Context, legacyMigrated bool) error {
	if len(r.key) == 0 {
		return fmt.Errorf("audit.SealAnchor: %w", ErrNoKey)
	}
	tx, err := r.lockedTx(ctx)
	if err != nil {
		return fmt.Errorf("audit.SealAnchor: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	sealed, err := r.sealTx(ctx, tx, legacyMigrated, true)
	if err != nil {
		return fmt.Errorf("audit.SealAnchor: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit.SealAnchor: commit: %w", err)
	}
	r.raiseFloor(sealed)
	return nil
}

// SealCutover is the storage.CutoverFunc for migration HeadMigration: it
// seals the fresh anchor over the legacy rows inside the transaction that
// creates it, so the genuine cut-over state (an unsealed anchor in front
// of v1 rows) never outlives that transaction. A crash, a timeout or a
// failing seal rolls 0014 back for the next run to retry; a later
// migration failing leaves 0014 committed and already sealed.
func (r *Repo) SealCutover(ctx context.Context, tx *sql.Tx) error {
	if len(r.key) == 0 {
		return fmt.Errorf("audit.SealCutover: %w", ErrNoKey)
	}
	if err := r.lockChain(ctx, tx); err != nil {
		return fmt.Errorf("audit.SealCutover: %w", err)
	}
	sealed, err := r.sealTx(ctx, tx, true, false)
	if err != nil {
		return fmt.Errorf("audit.SealCutover: %w", err)
	}
	// Raised before the caller commits: a rollback leaves the anchor
	// unsealed (never MAC-valid) and the tail untouched, so the mark
	// cannot flag a genuine anchor.
	r.raiseFloor(sealed)
	return nil
}

// sealTx seals an unsealed anchor over the current tail within tx and
// returns the sequence it sealed (0 when the anchor was already sealed).
// withBase is false only inside migration 0014, before the retention base
// columns exist; the base is necessarily empty then.
func (r *Repo) sealTx(ctx context.Context, tx *sql.Tx, legacyMigrated, withBase bool) (int64, error) {
	h, err := readHeadCols(ctx, tx, withBase)
	if err != nil {
		return 0, fmt.Errorf("read head: %w", err)
	}
	if h.present && h.mac != "" {
		r.observe(h)
		return 0, nil
	}
	t, err := readTail(ctx, tx)
	if err != nil {
		return 0, fmt.Errorf("read tail: %w", err)
	}
	next := head{
		present:     true,
		legacyUntil: h.legacyUntil,
		seq:         t.seq,
		hash:        t.hash,
		broken:      r.anchorBreak(h, t, 0, legacyMigrated),
		baseSeq:     h.baseSeq,
		baseHash:    h.baseHash,
	}
	if err := r.writeHeadCols(ctx, tx, next, withBase); err != nil {
		return 0, err
	}
	return t.seq, nil
}

// Prune deletes the oldest rows that occurred before cutoff (retention,
// FR-I.31) and moves the anchor's retention base onto the newest deleted
// row, so the shortened chain still verifies. Only a leading run of rows
// older than cutoff is deleted, and never the newest row: the anchor
// keeps pointing at a row that exists. Surviving rows are not modified.
// It returns the number of rows deleted, or ErrChainBroken (deleting
// nothing) when the chain does not verify.
func (r *Repo) Prune(ctx context.Context, cutoff time.Time) (int64, error) {
	if len(r.key) == 0 {
		return 0, fmt.Errorf("audit.Prune: %w", ErrNoKey)
	}
	tx, err := r.lockedTx(ctx)
	if err != nil {
		return 0, fmt.Errorf("audit.Prune: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	h, err := readHead(ctx, tx)
	if err != nil {
		return 0, fmt.Errorf("audit.Prune: read head: %w", err)
	}
	bad, err := r.verifyTx(ctx, tx, h, r.floor.Load())
	if err != nil {
		return 0, fmt.Errorf("audit.Prune: verify: %w", err)
	}
	if bad != 0 {
		return 0, fmt.Errorf("audit.Prune: %w (first broken entry %d)", ErrChainBroken, bad)
	}
	base, err := pruneBoundary(ctx, tx, cutoff.UTC(), h.seq)
	if err != nil || base.seq == 0 {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, rebind(r.db, `DELETE FROM audit_log WHERE sequence_no <= ?`), base.seq)
	if err != nil {
		return 0, fmt.Errorf("audit.Prune: delete: %w", err)
	}
	n, _ := res.RowsAffected()
	h.baseSeq, h.baseHash = base.seq, base.hash
	if err := r.writeHead(ctx, tx, h); err != nil {
		return 0, fmt.Errorf("audit.Prune: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("audit.Prune: commit: %w", err)
	}
	return n, nil
}

// pruneBoundary returns the newest row of the leading run of rows older
// than cutoff, stopping before headSeq (the newest row, which must stay).
// The zero tail means nothing is due.
func pruneBoundary(ctx context.Context, tx *sql.Tx, cutoff time.Time, headSeq int64) (tail, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT sequence_no, occurred_at, entry_hash FROM audit_log ORDER BY sequence_no ASC`)
	if err != nil {
		return tail{}, fmt.Errorf("audit.Prune: scan: %w", err)
	}
	defer rows.Close()
	var base tail
	for rows.Next() {
		var (
			t        tail
			occurred any
		)
		if err := rows.Scan(&t.seq, &occurred, &t.hash); err != nil {
			return tail{}, fmt.Errorf("audit.Prune: scan: %w", err)
		}
		ts, err := toTime(occurred)
		if err != nil || t.seq >= headSeq || !ts.Before(cutoff) {
			break
		}
		base = t
	}
	return base, rows.Err()
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
	// Read the high-water mark before the snapshot: every head it counts
	// was committed before then, so the snapshot cannot be older.
	floor := r.floor.Load()
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
	return r.verifyTx(ctx, tx, h, floor)
}

// verifyTx is VerifyChain's check against an open transaction, the anchor
// h read in it and the rollback high-water mark read before it began.
func (r *Repo) verifyTx(ctx context.Context, tx *sql.Tx, h head, floor int64) (int64, error) {
	rowBad, t, err := r.verifyRows(ctx, tx, h)
	if err != nil {
		return 0, err
	}
	r.observe(h)
	anchorBad := r.anchorBreak(h, t, floor, false)
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
// none) together with the newest row. The oldest row must chain onto the
// retention base, which is only trusted from a valid anchor.
func (r *Repo) verifyRows(ctx context.Context, tx *sql.Tx, h head) (int64, tail, error) {
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
	if r.headValid(h) {
		last = tail{seq: h.baseSeq, hash: h.baseHash}
	}
	for rows.Next() {
		var (
			seq                                     int64
			occurred                                any
			evt, actor, target, prev, hash, details string
		)
		if err := rows.Scan(&seq, &occurred, &evt, &actor, &target, &details, &prev, &hash); err != nil {
			return 0, tail{}, err
		}
		if bad == 0 && !r.rowValid(seq, occurred, evt, actor, target, details, prev, hash, last.hash, h.legacyUntil) {
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
// broken given the newest row, or 0 when they agree. floor is the
// high-water mark read before h: a valid anchor below it was replayed over
// a rolled-back tail. allowUnsealedLegacy accepts the post-migration state
// (unsealed anchor, rows only at or below legacy_until); only SealAnchor
// right after migration 0014 passes true.
func (r *Repo) anchorBreak(h head, t tail, floor int64, allowUnsealedLegacy bool) int64 {
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
	case h.seq < floor:
		return h.seq + 1
	case t.seq < h.seq:
		return t.seq + 1
	case t.seq > h.seq:
		return h.seq + 1
	case t.hash != h.hash:
		return max(t.seq, 1)
	}
	return 0
}

// headMAC authenticates the anchor. An unpruned anchor keeps the v1 form
// so anchors sealed before migration 0017 stay valid; once a retention
// base is set the v2 form binds it too. The distinct tags keep a v2
// anchor from being replayed as a v1 one with the base stripped.
func (r *Repo) headMAC(h head) string {
	fields := []any{headTag, h.legacyUntil, h.seq, h.hash, h.broken}
	if h.baseSeq != 0 || h.baseHash != "" {
		fields = []any{headTagV2, h.legacyUntil, h.seq, h.hash, h.broken, h.baseSeq, h.baseHash}
	}
	msg, _ := json.Marshal(fields)
	m := hmac.New(sha256.New, r.key)
	m.Write(msg)
	return hex.EncodeToString(m.Sum(nil))
}

func (r *Repo) headValid(h head) bool {
	return h.present && h.mac != "" && hmac.Equal([]byte(h.mac), []byte(r.headMAC(h)))
}

// observe raises the high-water mark to a MAC-valid anchor's head_seq.
func (r *Repo) observe(h head) {
	if r.headValid(h) {
		r.raiseFloor(h.seq)
	}
}

// raiseFloor moves the high-water mark up to seq; it never goes down.
func (r *Repo) raiseFloor(seq int64) {
	for {
		cur := r.floor.Load()
		if seq <= cur || r.floor.CompareAndSwap(cur, seq) {
			return
		}
	}
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
	if err := r.lockChain(ctx, tx); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

// lockChain takes the Postgres writer lock described at lockedTx.
func (r *Repo) lockChain(ctx context.Context, tx *sql.Tx) error {
	if storage.IsPostgres(r.db) {
		if _, err := tx.ExecContext(ctx, `LOCK TABLE audit_log IN EXCLUSIVE MODE`); err != nil {
			return fmt.Errorf("lock: %w", err)
		}
	}
	return nil
}

func readHead(ctx context.Context, tx *sql.Tx) (head, error) {
	return readHeadCols(ctx, tx, true)
}

// readHeadCols reads the anchor; withBase=false skips the retention base
// columns, which do not exist yet while migration 0014 runs.
func readHeadCols(ctx context.Context, tx *sql.Tx, withBase bool) (head, error) {
	h := head{present: true}
	var err error
	if withBase {
		err = tx.QueryRowContext(ctx,
			`SELECT legacy_until, head_seq, head_hash, broken_seq, head_mac, base_seq, base_hash
			 FROM audit_head WHERE id = 1`,
		).Scan(&h.legacyUntil, &h.seq, &h.hash, &h.broken, &h.mac, &h.baseSeq, &h.baseHash)
	} else {
		err = tx.QueryRowContext(ctx,
			`SELECT legacy_until, head_seq, head_hash, broken_seq, head_mac FROM audit_head WHERE id = 1`,
		).Scan(&h.legacyUntil, &h.seq, &h.hash, &h.broken, &h.mac)
	}
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
	return r.writeHeadCols(ctx, tx, h, true)
}

// writeHeadCols is writeHead; withBase=false (migration 0014 only, base
// necessarily empty) leaves out the retention base columns.
func (r *Repo) writeHeadCols(ctx context.Context, tx *sql.Tx, h head, withBase bool) error {
	mac := r.headMAC(h)
	if !withBase {
		return r.writeHeadV1(ctx, tx, h, mac)
	}
	res, err := tx.ExecContext(ctx, rebind(r.db,
		`UPDATE audit_head SET legacy_until = ?, head_seq = ?, head_hash = ?, broken_seq = ?, head_mac = ?,
		 base_seq = ?, base_hash = ? WHERE id = 1`),
		h.legacyUntil, h.seq, h.hash, h.broken, mac, h.baseSeq, h.baseHash)
	if err != nil {
		return fmt.Errorf("update head: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n > 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, rebind(r.db,
		`INSERT INTO audit_head (id, legacy_until, head_seq, head_hash, broken_seq, head_mac, base_seq, base_hash)
		 VALUES (1, ?, ?, ?, ?, ?, ?, ?)`),
		h.legacyUntil, h.seq, h.hash, h.broken, mac, h.baseSeq, h.baseHash); err != nil {
		return fmt.Errorf("insert head: %w", err)
	}
	return nil
}

// writeHeadV1 stores an anchor without a retention base (schema 0014).
func (r *Repo) writeHeadV1(ctx context.Context, tx *sql.Tx, h head, mac string) error {
	if h.baseSeq != 0 || h.baseHash != "" {
		return errors.New("write head: retention base needs migration 0017")
	}
	res, err := tx.ExecContext(ctx, rebind(r.db,
		`UPDATE audit_head SET legacy_until = ?, head_seq = ?, head_hash = ?, broken_seq = ?, head_mac = ? WHERE id = 1`),
		h.legacyUntil, h.seq, h.hash, h.broken, mac)
	if err != nil {
		return fmt.Errorf("update head: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n > 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, rebind(r.db,
		`INSERT INTO audit_head (id, legacy_until, head_seq, head_hash, broken_seq, head_mac)
		 VALUES (1, ?, ?, ?, ?, ?)`),
		h.legacyUntil, h.seq, h.hash, h.broken, mac); err != nil {
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
