package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// clockRepo returns a repo whose clock the test moves by hand.
func clockRepo(t *testing.T) (*Repo, *time.Time) {
	t.Helper()
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	return NewRepo(openDB(t), chainKey).WithClock(func() time.Time { return now }), &now
}

func prune(t *testing.T, r *Repo, cutoff time.Time) int64 {
	t.Helper()
	n, err := r.Prune(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	return n
}

func count(t *testing.T, r *Repo) int64 {
	t.Helper()
	n, err := r.Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// FR-I.31 / FR-I.37: audit rows older than the retention period are
// deleted, and the shortened chain still verifies, before and after
// further appends.
func TestPruneKeepsChainVerifiable(t *testing.T) {
	t.Parallel()
	r, now := clockRepo(t)
	appendN(t, r, 3)
	*now = now.Add(400 * 24 * time.Hour)
	recent := appendN(t, r, 2)

	cutoff := now.Add(-365 * 24 * time.Hour)
	if n := prune(t, r, cutoff); n != 3 {
		t.Fatalf("pruned %d rows, want 3", n)
	}
	if c := count(t, r); c != 2 {
		t.Fatalf("%d rows left, want 2", c)
	}
	if bad := verify(t, r); bad != 0 {
		t.Fatalf("pruned chain reported broken at %d", bad)
	}
	appendN(t, r, 2)
	if bad := verify(t, r); bad != 0 {
		t.Fatalf("appends after a prune reported broken at %d", bad)
	}
	if n := prune(t, r, cutoff); n != 0 {
		t.Fatalf("second prune deleted %d rows, want 0", n)
	}
	// Surviving rows are untouched: their hashes are what Append returned.
	rows := readRows(t, r.db)
	if rows[0].seq != recent[0].SequenceNo || rows[0].prevHash == "" {
		t.Fatalf("oldest surviving row = %+v, want seq %d chained onto the base", rows[0], recent[0].SequenceNo)
	}
}

// The newest row anchors the head; even when every row is past retention
// it survives so the anchor keeps pointing at an existing row.
func TestPruneNeverDeletesNewestRow(t *testing.T) {
	t.Parallel()
	r, now := clockRepo(t)
	entries := appendN(t, r, 4)
	if n := prune(t, r, now.Add(time.Hour)); n != 3 {
		t.Fatalf("pruned %d rows, want 3", n)
	}
	rows := readRows(t, r.db)
	if len(rows) != 1 || rows[0].seq != entries[3].SequenceNo {
		t.Fatalf("rows left = %+v, want only seq %d", rows, entries[3].SequenceNo)
	}
	if bad := verify(t, r); bad != 0 {
		t.Fatalf("chain reported broken at %d", bad)
	}
}

// Only a leading run of old rows goes: a newer row in between stops the
// prune even if older-stamped rows follow it.
func TestPruneStopsAtFirstRecentRow(t *testing.T) {
	t.Parallel()
	r, now := clockRepo(t)
	start := *now
	appendN(t, r, 2)
	*now = start.Add(48 * time.Hour)
	appendN(t, r, 1)
	*now = start // clock stepped back
	appendN(t, r, 2)
	if n := prune(t, r, start.Add(24*time.Hour)); n != 2 {
		t.Fatalf("pruned %d rows, want 2", n)
	}
	if bad := verify(t, r); bad != 0 {
		t.Fatalf("chain reported broken at %d", bad)
	}
}

// Deleting old rows without the key stays detectable after a legitimate
// prune: either the next row no longer links to the base, or the moved
// (or stripped) base no longer matches head_mac.
func TestKeylessPruneIsDetected(t *testing.T) {
	cases := []struct {
		name   string
		tamper func(t *testing.T, r *Repo, victim Entry)
	}{
		{"delete only", func(t *testing.T, r *Repo, victim Entry) {
			exec(t, r.db, `DELETE FROM audit_log WHERE sequence_no <= ?`, victim.SequenceNo)
		}},
		{"delete and move base", func(t *testing.T, r *Repo, victim Entry) {
			exec(t, r.db, `DELETE FROM audit_log WHERE sequence_no <= ?`, victim.SequenceNo)
			exec(t, r.db, `UPDATE audit_head SET base_seq = ?, base_hash = ?`, victim.SequenceNo, victim.EntryHash)
		}},
		{"strip base", func(t *testing.T, r *Repo, _ Entry) {
			exec(t, r.db, `UPDATE audit_head SET base_seq = 0, base_hash = ''`)
		}},
		{"strip base and relink", func(t *testing.T, r *Repo, victim Entry) {
			exec(t, r.db, `UPDATE audit_head SET base_seq = 0, base_hash = ''`)
			exec(t, r.db, `UPDATE audit_log SET prev_hash = '' WHERE sequence_no = ?`, victim.SequenceNo)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			r, now := clockRepo(t)
			appendN(t, r, 2)
			*now = now.Add(time.Hour)
			later := appendN(t, r, 3)
			prune(t, r, now.Add(-time.Minute))
			if bad := verify(t, r); bad != 0 {
				t.Fatalf("legitimate prune reported broken at %d", bad)
			}
			c.tamper(t, r, later[0])
			if bad := verify(t, r); bad == 0 {
				t.Fatal("tampering with the pruned chain verified as intact")
			}
		})
	}
}

// Rows deleted before any prune (base still empty) are detected too, and
// a keyless attacker cannot plant a base on an unpruned log.
func TestPlantedBaseIsDetected(t *testing.T) {
	t.Parallel()
	r, _ := clockRepo(t)
	entries := appendN(t, r, 4)
	exec(t, r.db, `DELETE FROM audit_log WHERE sequence_no <= ?`, entries[1].SequenceNo)
	exec(t, r.db, `UPDATE audit_head SET base_seq = ?, base_hash = ?`, entries[1].SequenceNo, entries[1].EntryHash)
	if bad := verify(t, r); bad == 0 {
		t.Fatal("planted retention base verified as intact")
	}
}

// Prune must not destroy the evidence of a break.
func TestPruneRefusesBrokenChain(t *testing.T) {
	t.Parallel()
	r, now := clockRepo(t)
	entries := appendN(t, r, 4)
	exec(t, r.db, `UPDATE audit_log SET target = 'forged' WHERE sequence_no = ?`, entries[1].SequenceNo)
	n, err := r.Prune(context.Background(), now.Add(time.Hour))
	if !errors.Is(err, ErrChainBroken) || n != 0 {
		t.Fatalf("Prune on a broken chain = (%d, %v), want (0, ErrChainBroken)", n, err)
	}
	if c := count(t, r); c != 4 {
		t.Fatalf("%d rows left, want all 4", c)
	}
	if _, err := NewRepo(r.db, nil).Prune(context.Background(), *now); !errors.Is(err, ErrNoKey) {
		t.Fatalf("keyless Prune err = %v, want ErrNoKey", err)
	}
}

// Anchors sealed before migration 0017 (no base) keep the v1 MAC form,
// so upgrading does not turn every existing chain red; a base switches to
// the v2 form, which binds it.
func TestUnprunedAnchorKeepsV1MAC(t *testing.T) {
	t.Parallel()
	r := NewRepo(nil, chainKey)
	h := head{present: true, legacyUntil: 2, seq: 7, hash: "abc"}
	msg, _ := json.Marshal([]any{"sealkeeper-audit-head-v1", int64(2), int64(7), "abc", int64(0)})
	m := hmac.New(sha256.New, chainKey)
	m.Write(msg)
	if got, want := r.headMAC(h), hex.EncodeToString(m.Sum(nil)); got != want {
		t.Fatalf("unpruned head MAC changed: got %s, want %s", got, want)
	}
	withBase := h
	withBase.baseSeq, withBase.baseHash = 3, "def"
	if r.headMAC(withBase) == r.headMAC(h) {
		t.Fatal("retention base not bound by head_mac")
	}
}
