package audit

import (
	"bytes"
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
)

var (
	chainKey    = bytes.Repeat([]byte{0x11}, KeySize)
	attackerKey = bytes.Repeat([]byte{0x22}, KeySize)
)

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), storagetest.SetupTimeout)
	defer cancel()
	s, err := storage.Open(ctx, storage.Options{DSN: storagetest.DSN(t)})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s.DB()
}

func exec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), storage.Rebind(db, q), args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

func appendN(t *testing.T, r *Repo, n int) []Entry {
	t.Helper()
	out := make([]Entry, 0, n)
	for i := 0; i < n; i++ {
		e, err := r.Append(context.Background(), "policy.updated", "admin@localhost", "policy-1", map[string]any{"i": i})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		out = append(out, e)
	}
	return out
}

func verify(t *testing.T, r *Repo) int64 {
	t.Helper()
	bad, err := r.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	return bad
}

type row struct {
	seq                                   int64
	occurred                              time.Time
	evt, actor, target, details, prevHash string
}

func readRows(t *testing.T, db *sql.DB) []row {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `SELECT sequence_no, occurred_at, event_type,
		COALESCE(actor, ''), COALESCE(target, ''), details_json, prev_hash FROM audit_log ORDER BY sequence_no`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []row
	for rows.Next() {
		var x row
		var occ any
		if err := rows.Scan(&x.seq, &occ, &x.evt, &x.actor, &x.target, &x.details, &x.prevHash); err != nil {
			t.Fatal(err)
		}
		if x.occurred, err = toTime(occ); err != nil {
			t.Fatal(err)
		}
		out = append(out, x)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// rechain rewrites every entry_hash / prev_hash with hashFn, the way an
// attacker with DB write access recomputes the chain after an edit, and
// returns the new head (seq, hash).
func rechain(t *testing.T, db *sql.DB, hashFn func(prev string, x row) string) (int64, string) {
	t.Helper()
	prev := ""
	var seq int64
	for _, x := range readRows(t, db) {
		h := hashFn(prev, x)
		exec(t, db, `UPDATE audit_log SET prev_hash = ?, entry_hash = ? WHERE sequence_no = ?`, prev, h, x.seq)
		prev, seq = h, x.seq
	}
	return seq, prev
}

func legacyHash(prev string, x row) string {
	return chainHash(prev, canonicalize(x.evt, x.actor, x.target, []byte(x.details), x.occurred))
}

// Regression (SK-17b): the chain was unkeyed SHA-256, so editing a row and
// recomputing every later hash verified as intact.
func TestKeylessFullChainRewriteIsDetected(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		forge  func(prev string, x row) string
		anchor func(t *testing.T, db *sql.DB, seq int64, hash string)
	}{
		{
			name:  "sha256 rewrite, anchor head patched, old mac kept",
			forge: legacyHash,
			anchor: func(t *testing.T, db *sql.DB, seq int64, hash string) {
				exec(t, db, `UPDATE audit_head SET head_seq = ?, head_hash = ?`, seq, hash)
			},
		},
		{
			name:  "sha256 rewrite, downgraded to an unsealed legacy-only anchor",
			forge: legacyHash,
			anchor: func(t *testing.T, db *sql.DB, seq int64, _ string) {
				exec(t, db, `UPDATE audit_head SET legacy_until = ?, head_seq = 0, head_hash = '', head_mac = ''`, seq)
			},
		},
		{
			name: "hmac rewrite under a guessed key, anchor re-sealed with it",
			forge: func(prev string, x row) string {
				a := NewRepo(nil, attackerKey)
				return a.entryMAC(prev, canonicalV2(x.seq, x.occurred, x.evt, x.actor, x.target, x.details))
			},
			anchor: func(t *testing.T, db *sql.DB, seq int64, hash string) {
				a := NewRepo(nil, attackerKey)
				mac := a.headMAC(head{present: true, seq: seq, hash: hash})
				exec(t, db, `UPDATE audit_head SET head_seq = ?, head_hash = ?, head_mac = ?`, seq, hash, mac)
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			db := openDB(t)
			r := NewRepo(db, chainKey)
			entries := appendN(t, r, 4)
			if bad := verify(t, r); bad != 0 {
				t.Fatalf("intact chain reported broken at %d", bad)
			}

			// Hide the second event: an admin weakening a policy.
			exec(t, db, `UPDATE audit_log SET actor = ?, details_json = '{}' WHERE sequence_no = ?`,
				"someone-else@corp", entries[1].SequenceNo)
			seq, hash := rechain(t, db, c.forge)
			c.anchor(t, db, seq, hash)

			if bad := verify(t, r); bad == 0 {
				t.Fatal("rewritten chain verified as intact")
			}
		})
	}
}

// Regression (SK-17b): deleting the newest rows left a valid chain.
func TestTailTruncationIsDetected(t *testing.T) {
	t.Parallel()
	db := openDB(t)
	r := NewRepo(db, chainKey)
	entries := appendN(t, r, 5)

	exec(t, db, `DELETE FROM audit_log WHERE sequence_no >= ?`, entries[3].SequenceNo)
	want := entries[3].SequenceNo
	if bad := verify(t, r); bad != want {
		t.Fatalf("after deleting the last two rows: bad = %d, want %d (first missing entry)", bad, want)
	}

	// Logging carries on, but the evidence must not be overwritten.
	appendN(t, r, 2)
	if bad := verify(t, r); bad != want {
		t.Fatalf("after further appends: bad = %d, want sticky %d", bad, want)
	}
}

func TestTruncatingEverythingIsDetected(t *testing.T) {
	t.Parallel()
	db := openDB(t)
	r := NewRepo(db, chainKey)
	appendN(t, r, 3)
	exec(t, db, `DELETE FROM audit_log`)
	if bad := verify(t, r); bad == 0 {
		t.Fatal("emptied log verified as intact")
	}
}

func TestDeletedAnchorIsDetected(t *testing.T) {
	t.Parallel()
	db := openDB(t)
	r := NewRepo(db, chainKey)
	appendN(t, r, 3)
	exec(t, db, `DELETE FROM audit_head`)
	if bad := verify(t, r); bad == 0 {
		t.Fatal("log without its anchor verified as intact")
	}
	// Append re-creates the anchor but keeps the break on record.
	appendN(t, r, 1)
	if bad := verify(t, r); bad == 0 {
		t.Fatal("re-created anchor hid the deletion")
	}
}

func TestWrongKeyReportsBrokenChain(t *testing.T) {
	t.Parallel()
	db := openDB(t)
	appendN(t, NewRepo(db, chainKey), 2)
	if bad := verify(t, NewRepo(db, attackerKey)); bad == 0 {
		t.Fatal("chain verified under a different key")
	}
}

// Rows written before the keyed chain (plain SHA-256) must keep verifying,
// and keyed rows must chain on top of them.
func TestLegacyRowsStillVerify(t *testing.T) {
	t.Parallel()
	db := openDB(t)
	ctx := context.Background()

	// Seed three rows exactly as the pre-HMAC writer did.
	prev := ""
	base := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		x := row{occurred: base.Add(time.Duration(i) * 1500 * time.Microsecond), evt: "admin.login", actor: "admin@localhost", details: "{}"}
		h := legacyHash(prev, x)
		var seq int64
		if err := db.QueryRowContext(ctx, storage.Rebind(db,
			`INSERT INTO audit_log (occurred_at, event_type, actor, target, details_json, prev_hash, entry_hash)
			 VALUES (?, ?, ?, NULL, ?, ?, ?) RETURNING sequence_no`),
			x.occurred, x.evt, x.actor, x.details, prev, h).Scan(&seq); err != nil {
			t.Fatalf("seed legacy row: %v", err)
		}
		prev = h
	}
	// What migration 0014 does on an existing deployment.
	exec(t, db, `UPDATE audit_head SET legacy_until = (SELECT MAX(sequence_no) FROM audit_log)`)

	r := NewRepo(db, chainKey)
	if err := r.SealAnchor(ctx, true); err != nil {
		t.Fatalf("SealAnchor: %v", err)
	}
	if bad := verify(t, r); bad != 0 {
		t.Fatalf("sealed legacy log reported broken at %d", bad)
	}
	entries := appendN(t, r, 2)
	if entries[0].PrevHash != prev {
		t.Fatalf("first keyed row does not chain on the legacy tail")
	}
	if bad := verify(t, r); bad != 0 {
		t.Fatalf("legacy + keyed chain reported broken at %d", bad)
	}

	// Rewriting a legacy row is still caught, even with SHA-256 recomputed
	// up to the cut-over: the first keyed row commits to the old tail.
	all := readRows(t, db)
	exec(t, db, `UPDATE audit_log SET actor = 'mallory' WHERE sequence_no = ?`, all[0].seq)
	if bad := verify(t, r); bad != all[0].seq {
		t.Fatalf("tampered legacy row: bad = %d, want %d", bad, all[0].seq)
	}
	prev = ""
	for _, x := range readRows(t, db)[:3] {
		h := legacyHash(prev, x)
		exec(t, db, `UPDATE audit_log SET prev_hash = ?, entry_hash = ? WHERE sequence_no = ?`, prev, h, x.seq)
		prev = h
	}
	if bad := verify(t, r); bad != entries[0].SequenceNo {
		t.Fatalf("legacy prefix re-hashed: bad = %d, want %d (first keyed row)", bad, entries[0].SequenceNo)
	}
}

// Append on an unsealed anchor in front of existing rows is the shape of a
// downgrade (anchor reset to its post-migration state); only the startup
// seal may accept it.
func TestAppendDoesNotBlessUnsealedLegacyAnchor(t *testing.T) {
	t.Parallel()
	db := openDB(t)
	r := NewRepo(db, chainKey)
	appendN(t, r, 2)
	seq, _ := rechain(t, db, legacyHash)
	exec(t, db, `UPDATE audit_head SET legacy_until = ?, head_seq = 0, head_hash = '', head_mac = ''`, seq)
	appendN(t, r, 1)
	if bad := verify(t, r); bad == 0 {
		t.Fatal("Append blessed a downgraded anchor")
	}
}

// Regression: SealAnchor ran at every boot and accepted an unsealed anchor
// in front of existing rows, so a keyless v1 rewrite plus an anchor reset
// verified as intact after the next restart. Only the process that just
// applied migration 0014 may bless that state.
func TestRestartDoesNotBlessDowngradedAnchor(t *testing.T) {
	t.Parallel()
	db := openDB(t)
	r := NewRepo(db, chainKey)
	entries := appendN(t, r, 4)
	exec(t, db, `UPDATE audit_log SET actor = ?, details_json = '{}' WHERE sequence_no = ?`, "someone-else@corp", entries[1].SequenceNo)
	seq, _ := rechain(t, db, legacyHash)
	exec(t, db, `UPDATE audit_head SET legacy_until = ?, head_seq = 0, head_hash = '', broken_seq = 0, head_mac = ''`, seq)

	restarted := NewRepo(db, chainKey)
	if err := restarted.SealAnchor(context.Background(), false); err != nil {
		t.Fatalf("SealAnchor: %v", err)
	}
	if bad := verify(t, restarted); bad == 0 {
		t.Fatal("boot sealed a downgraded anchor as intact")
	}
	appendN(t, restarted, 1)
	if err := restarted.SealAnchor(context.Background(), false); err != nil {
		t.Fatalf("SealAnchor: %v", err)
	}
	if bad := verify(t, restarted); bad == 0 {
		t.Fatal("downgraded anchor verifies intact after a restart and an append")
	}
}

func TestSealAnchorNeverReblessesSealedAnchor(t *testing.T) {
	t.Parallel()
	db := openDB(t)
	r := NewRepo(db, chainKey)
	entries := appendN(t, r, 3)
	exec(t, db, `DELETE FROM audit_log WHERE sequence_no = ?`, entries[2].SequenceNo)
	if err := r.SealAnchor(context.Background(), true); err != nil {
		t.Fatalf("SealAnchor: %v", err)
	}
	if bad := verify(t, r); bad != entries[2].SequenceNo {
		t.Fatalf("bad = %d, want %d", bad, entries[2].SequenceNo)
	}
}

func TestAppendReturnsRealSequenceNumbers(t *testing.T) {
	t.Parallel()
	db := openDB(t)
	entries := appendN(t, NewRepo(db, chainKey), 3)
	for i, e := range entries {
		if e.SequenceNo == 0 {
			t.Fatalf("entry %d: SequenceNo = 0", i)
		}
		if i > 0 && e.SequenceNo <= entries[i-1].SequenceNo {
			t.Fatalf("entry %d: SequenceNo %d not increasing", i, e.SequenceNo)
		}
	}
}

// The v1 newline encoding let different (actor, target) pairs collide.
func TestCanonicalV2IsUnambiguous(t *testing.T) {
	t.Parallel()
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := canonicalV2(1, ts, "evt", "alice@corp\nmallory@corp", "eve@corp", "{}")
	b := canonicalV2(1, ts, "evt", "alice@corp", "mallory@corp\neve@corp", "{}")
	if bytes.Equal(a, b) {
		t.Fatal("distinct events share a canonical form")
	}
}

func TestEmptyLogVerifiesAndKeylessRepoRefuses(t *testing.T) {
	t.Parallel()
	db := openDB(t)
	if bad := verify(t, NewRepo(db, chainKey)); bad != 0 {
		t.Fatalf("empty log reported broken at %d", bad)
	}
	if _, err := NewRepo(db, nil).Append(context.Background(), "evt", "", "", nil); err == nil {
		t.Fatal("Append without a key succeeded")
	}
}

func TestDeriveKey(t *testing.T) {
	t.Parallel()
	k1, err := DeriveKey("c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3I=")
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := DeriveKey("c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3I=")
	k3, _ := DeriveKey("another-master-secret")
	if len(k1) != KeySize || !bytes.Equal(k1, k2) || bytes.Equal(k1, k3) {
		t.Fatal("DeriveKey must be deterministic, 32 bytes, and secret-dependent")
	}
	if _, err := DeriveKey(""); err == nil {
		t.Fatal("DeriveKey accepted an empty secret")
	}
}
