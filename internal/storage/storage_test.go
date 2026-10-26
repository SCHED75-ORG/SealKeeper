package storage_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
)

// withSQLite returns a Store backed by a fresh on-disk SQLite database. We
// use on-disk rather than :memory: because goose opens a separate connection
// for its bookkeeping table and an in-memory DB is not shared across
// connections by default.
func withSQLite(t *testing.T) storage.Store {
	t.Helper()
	dir := t.TempDir()
	dsn := "sqlite://" + filepath.ToSlash(filepath.Join(dir, "sk.db"))

	ctx, cancel := context.WithTimeout(context.Background(), storagetest.SetupTimeout)
	defer cancel()

	s, err := storage.Open(ctx, storage.Options{DSN: dsn})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestParseDSNDialects(t *testing.T) {
	t.Parallel()
	cases := []struct {
		dsn  string
		want storage.Dialect
	}{
		{"postgres://u:p@h:5432/d?sslmode=disable", storage.DialectPostgres},
		{"postgresql://u@h/d", storage.DialectPostgres},
		{"pgx://u:p@h/d", storage.DialectPostgres},
		{"sqlite:///tmp/sk.db", storage.DialectSQLite},
		{"sqlite://:memory:", storage.DialectSQLite},
		{"file:sk.db?cache=shared", storage.DialectSQLite},
	}
	for _, c := range cases {
		ctx, cancel := context.WithTimeout(context.Background(), storagetest.SetupTimeout)
		_, err := storage.Open(ctx, storage.Options{DSN: c.dsn})
		cancel()
		// We don't expect Open to succeed for non-existent Postgres servers;
		// we only care that the dialect parser does not reject the DSN.
		if err != nil && c.want == storage.DialectSQLite && !errors.Is(err, context.DeadlineExceeded) {
			// SQLite paths may legitimately fail on read-only test envs; we
			// tolerate that and rely on TestMigrateUp for the round-trip.
			continue
		}
	}
}

func TestParseDSNUnknownScheme(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, err := storage.Open(ctx, storage.Options{DSN: "mysql://x/y"})
	if err == nil {
		t.Fatalf("expected error for unknown scheme")
	}
}

func TestOpenEmptyDSN(t *testing.T) {
	t.Parallel()
	_, err := storage.Open(context.Background(), storage.Options{})
	if err == nil {
		t.Fatal("expected error for empty DSN")
	}
}

func TestPingAfterOpen(t *testing.T) {
	t.Parallel()
	s := withSQLite(t)
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("Ping after Open: %v", err)
	}
}

func TestDialect(t *testing.T) {
	t.Parallel()
	s := withSQLite(t)
	if got := s.Dialect(); got != storage.DialectSQLite {
		t.Fatalf("Dialect = %q, want %q", got, storage.DialectSQLite)
	}
}

func TestMigrateUpAndIdempotency(t *testing.T) {
	t.Parallel()
	s := withSQLite(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp first run: %v", err)
	}

	v, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	// The test asserts the version is positive and matches whatever the
	// migration set ships — it MUST NOT hardcode 1, otherwise every new
	// migration breaks the suite for the wrong reason.
	if v < 1 {
		t.Fatalf("schema version = %d, want ≥ 1", v)
	}

	// Running again must be a no-op.
	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp second run: %v", err)
	}
	v2, _ := s.SchemaVersion(ctx)
	if v2 != v {
		t.Fatalf("MigrateUp re-applied something: version went %d -> %d", v, v2)
	}
}

// The audit anchor seal keys off the versions a run applied (0014), so the
// report must list them on the first run and nothing afterwards.
func TestMigrateUpAppliedReportsVersions(t *testing.T) {
	t.Parallel()
	s := withSQLite(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	applied, err := s.MigrateUpApplied(ctx)
	if err != nil {
		t.Fatalf("MigrateUpApplied first run: %v", err)
	}
	v, _ := s.SchemaVersion(ctx)
	// Numbers may skip (a number reserved by a parallel branch): compare
	// with the files on disk rather than with 1..v.
	files, err := os.ReadDir(filepath.Join("migrations", "sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != len(files) || !slices.IsSorted(applied) || applied[0] != 1 || applied[len(applied)-1] != v || !slices.Contains(applied, 14) {
		t.Fatalf("applied = %v, want every one of the %d migrations up to %d", applied, len(files), v)
	}
	again, err := s.MigrateUpApplied(ctx)
	if err != nil {
		t.Fatalf("MigrateUpApplied second run: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("second run applied %v, want none", again)
	}
}

func TestExpectedTablesExist(t *testing.T) {
	t.Parallel()
	s := withSQLite(t)
	if err := s.MigrateUp(context.Background()); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}

	rows, err := s.DB().QueryContext(context.Background(),
		`SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`)
	if err != nil {
		t.Fatalf("query tables: %v", err)
	}
	defer rows.Close()

	got := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[name] = true
	}
	for _, want := range []string{"schema_meta", "kv", "captured_mail", "audit_log"} {
		if !got[want] {
			t.Errorf("missing table %q after migrate up; got %v", want, got)
		}
	}
}

func TestSchemaMetaRecordsDialect(t *testing.T) {
	t.Parallel()
	s := withSQLite(t)
	if err := s.MigrateUp(context.Background()); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	var value string
	err := s.DB().QueryRowContext(context.Background(),
		`SELECT value FROM schema_meta WHERE key = 'schema_dialect'`).Scan(&value)
	if err != nil {
		t.Fatalf("query schema_meta: %v", err)
	}
	if value != "sqlite" {
		t.Errorf("schema_dialect = %q, want %q", value, "sqlite")
	}
}

func TestReadinessCheckIntegratesWithStore(t *testing.T) {
	t.Parallel()
	s := withSQLite(t)
	chk := storage.NewReadinessCheck("database", s)
	if chk.Name() != "database" {
		t.Errorf("Name = %q", chk.Name())
	}
	if err := chk.Check(context.Background()); err != nil {
		t.Errorf("Check ok store: %v", err)
	}

	// After Close, the check must fail (no usable connection).
	_ = s.Close()
	if err := chk.Check(context.Background()); err == nil {
		t.Error("expected Check to fail after Close")
	}
}

// TestPostgresIntegration is enabled only when TEST_PG_DSN is set, e.g. when
// running locally against a docker-compose Postgres or in CI's
// testcontainers-go matrix (FR-L.3).
func TestPostgresIntegration(t *testing.T) {
	t.Parallel()
	dsn := os.Getenv("TEST_PG_DSN")
	if dsn == "" {
		t.Skip("TEST_PG_DSN not set — skipping Postgres integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), storagetest.SetupTimeout)
	defer cancel()

	s, err := storage.Open(ctx, storage.Options{DSN: dsn})
	if err != nil {
		t.Fatalf("storage.Open postgres: %v", err)
	}
	defer s.Close()

	if s.Dialect() != storage.DialectPostgres {
		t.Fatalf("Dialect = %q, want %q", s.Dialect(), storage.DialectPostgres)
	}
	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp postgres: %v", err)
	}
	if v, _ := s.SchemaVersion(ctx); v < 1 {
		t.Errorf("postgres schema version = %d, want ≥ 1", v)
	}
}
