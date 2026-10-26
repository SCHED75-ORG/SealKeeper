package audit

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/pressly/goose/v3"

	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
)

// legacyStore opens a fresh database migrated only up to the schema before
// the keyed chain and seeds three v1 rows: a deployment about to upgrade
// across migration 0014.
func legacyStore(t *testing.T) storage.Store {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), storagetest.SetupTimeout)
	defer cancel()
	s, err := storage.Open(ctx, storage.Options{DSN: storagetest.DSN(t)})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	dialect := goose.DialectSQLite3
	if s.Dialect() == storage.DialectPostgres {
		dialect = goose.DialectPostgres
	}
	p, err := goose.NewProvider(dialect, s.DB(), os.DirFS("../storage/migrations/"+string(s.Dialect())))
	if err != nil {
		t.Fatalf("goose provider: %v", err)
	}
	if _, err := p.UpTo(ctx, HeadMigration-1); err != nil {
		t.Fatalf("goose UpTo(%d): %v", HeadMigration-1, err)
	}
	prev := ""
	base := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		x := row{occurred: base.Add(time.Duration(i) * time.Second), evt: "admin.login", actor: "admin@localhost", details: "{}"}
		h := legacyHash(prev, x)
		exec(t, s.DB(), `INSERT INTO audit_log (occurred_at, event_type, actor, target, details_json, prev_hash, entry_hash)
			VALUES (?, ?, ?, NULL, ?, ?, ?)`, x.occurred, x.evt, x.actor, x.details, prev, h)
		prev = h
	}
	return s
}

// blockMigration15 makes the migration after 0014 fail (duplicate column)
// until the returned func is called.
func blockMigration15(t *testing.T, db *sql.DB, d storage.Dialect) func() {
	t.Helper()
	typ := "BLOB"
	if d == storage.DialectPostgres {
		typ = "BYTEA"
	}
	exec(t, db, `ALTER TABLE integrations ADD COLUMN config_enc `+typ)
	return func() { exec(t, db, `ALTER TABLE integrations DROP COLUMN config_enc`) }
}

// boot does what cmd/sealkeeper does once migrations are through: seal the
// anchor (blessing a legacy log only when 0014 is among applied), then log.
func boot(t *testing.T, db *sql.DB, applied []int64) *Repo {
	t.Helper()
	r := NewRepo(db, chainKey)
	if err := r.SealAnchor(context.Background(), slices.Contains(applied, HeadMigration)); err != nil {
		t.Fatalf("SealAnchor: %v", err)
	}
	appendN(t, r, 1)
	return r
}

func schemaVersion(t *testing.T, s storage.Store) int64 {
	t.Helper()
	v, err := s.SchemaVersion(context.Background())
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	return v
}

// Regression: the cut-over was blessed only by the process that saw 0014
// in MigrateUpApplied's result. A migration after 0014 failing (its
// applied versions were dropped) lost it, and the next run sealed the
// untampered legacy log as broken, for good.
func TestCutoverSurvivesLaterMigrationFailure(t *testing.T) {
	t.Parallel()
	s := legacyStore(t)
	ctx := context.Background()
	r := NewRepo(s.DB(), chainKey)

	unblock := blockMigration15(t, s.DB(), s.Dialect())
	applied, err := s.MigrateUpCutover(ctx, r.SealCutover)
	if err == nil {
		t.Fatal("blocked migration 0015 succeeded")
	}
	if !slices.Contains(applied, HeadMigration) {
		t.Fatalf("partial run reported applied = %v, want it to include %d", applied, HeadMigration)
	}
	unblock()
	applied, err = s.MigrateUpCutover(ctx, r.SealCutover)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if bad := verify(t, boot(t, s.DB(), applied)); bad != 0 {
		t.Fatalf("untampered legacy log reported broken at %d", bad)
	}
}

// Regression: a process dying (or its seal failing) between the 0014
// commit and the seal lost the cut-over. The seal now runs in 0014's own
// transaction, so such a run leaves 0014 pending and the next one redoes
// both.
func TestCutoverRetriedAfterInterruptedRun(t *testing.T) {
	t.Parallel()
	s := legacyStore(t)
	ctx := context.Background()

	died := errors.New("killed before the seal")
	if _, err := s.MigrateUpCutover(ctx, func(context.Context, *sql.Tx) error { return died }); !errors.Is(err, died) {
		t.Fatalf("interrupted run: err = %v, want %v", err, died)
	}
	if v := schemaVersion(t, s); v != HeadMigration-1 {
		t.Fatalf("schema version after interrupted 0014 = %d, want %d", v, HeadMigration-1)
	}

	r := NewRepo(s.DB(), chainKey)
	applied, err := s.MigrateUpCutover(ctx, r.SealCutover)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	if bad := verify(t, boot(t, s.DB(), applied)); bad != 0 {
		t.Fatalf("untampered legacy log reported broken at %d", bad)
	}
	var legacyUntil int64
	if err := s.DB().QueryRowContext(ctx, `SELECT legacy_until FROM audit_head`).Scan(&legacyUntil); err != nil || legacyUntil != 3 {
		t.Fatalf("legacy_until = %d (%v), want 3", legacyUntil, err)
	}
}

// The in-migration seal must not soften anything for a later boot: a
// keyless downgrade after the cut-over is still recorded as a break.
func TestCutoverDoesNotBlessLaterDowngrade(t *testing.T) {
	t.Parallel()
	s := legacyStore(t)
	ctx := context.Background()
	r := NewRepo(s.DB(), chainKey)
	if _, err := s.MigrateUpCutover(ctx, r.SealCutover); err != nil {
		t.Fatalf("MigrateUpCutover: %v", err)
	}
	appendN(t, r, 2)
	seq, _ := rechain(t, s.DB(), legacyHash)
	exec(t, s.DB(), `UPDATE audit_head SET legacy_until = ?, head_seq = 0, head_hash = '', broken_seq = 0, head_mac = ''`, seq)

	applied, err := s.MigrateUpCutover(ctx, r.SealCutover)
	if err != nil {
		t.Fatalf("MigrateUpCutover (no-op): %v", err)
	}
	if bad := verify(t, boot(t, s.DB(), applied)); bad == 0 {
		t.Fatal("downgraded anchor verified as intact")
	}
}
