package audit

import (
	"context"
	"database/sql"
	"testing"
)

// savedHead is a verbatim copy of the audit_head row, as an attacker with
// database write access but no key would keep it.
type savedHead struct {
	legacyUntil, seq, broken int64
	hash, mac                string
}

func saveHead(t *testing.T, db *sql.DB) savedHead {
	t.Helper()
	var h savedHead
	if err := db.QueryRowContext(context.Background(),
		`SELECT legacy_until, head_seq, head_hash, broken_seq, head_mac FROM audit_head WHERE id = 1`,
	).Scan(&h.legacyUntil, &h.seq, &h.hash, &h.broken, &h.mac); err != nil {
		t.Fatal(err)
	}
	return h
}

// rollBack deletes every row after the saved head and writes the old,
// MAC-valid anchor back: the tail and the anchor agree again.
func rollBack(t *testing.T, db *sql.DB, h savedHead) {
	t.Helper()
	exec(t, db, `DELETE FROM audit_log WHERE sequence_no > ?`, h.seq)
	exec(t, db, `UPDATE audit_head SET legacy_until = ?, head_seq = ?, head_hash = ?, broken_seq = ?, head_mac = ?`,
		h.legacyUntil, h.seq, h.hash, h.broken, h.mac)
}

func TestReplayedAnchorTailRollbackIsDetected(t *testing.T) {
	db := openDB(t)
	r := NewRepo(db, chainKey)
	appendN(t, r, 3)
	old := saveHead(t, db)
	appendN(t, r, 3)

	rollBack(t, db, old)
	if got := verify(t, r); got != 4 {
		t.Fatalf("rolled-back tail with replayed anchor: VerifyChain = %d, want 4", got)
	}
	// The next legitimate append records the break in the sealed anchor,
	// so it survives a restart of the process that saw the newer head.
	appendN(t, r, 1)
	if got := verify(t, NewRepo(db, chainKey)); got != 4 {
		t.Fatalf("after next append, fresh process: VerifyChain = %d, want 4", got)
	}
}

func TestRollbackAfterBootIsDetected(t *testing.T) {
	db := openDB(t)
	appendN(t, NewRepo(db, chainKey), 3)
	old := saveHead(t, db)
	appendN(t, NewRepo(db, chainKey), 2)

	// A new process learns the current head when it seals at boot.
	r := NewRepo(db, chainKey)
	if err := r.SealAnchor(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	rollBack(t, db, old)
	if got := verify(t, r); got != 4 {
		t.Fatalf("VerifyChain = %d, want 4", got)
	}
}

func TestDemoResetIsNotARollback(t *testing.T) {
	db := openDB(t)
	r := NewRepo(db, chainKey)
	appendN(t, r, 3)
	if got := verify(t, r); got != 0 {
		t.Fatalf("before reset: VerifyChain = %d", got)
	}
	// Same statements as internal/demo's resetter.
	exec(t, db, `DELETE FROM audit_log`)
	exec(t, db, `UPDATE audit_head SET legacy_until = 0, head_seq = 0, head_hash = '', broken_seq = 0, head_mac = ''`)
	if got := verify(t, r); got != 0 {
		t.Fatalf("after reset: VerifyChain = %d, want 0", got)
	}
	appendN(t, r, 2)
	if got := verify(t, r); got != 0 {
		t.Fatalf("after reset + append: VerifyChain = %d, want 0", got)
	}
}
