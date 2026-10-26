package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"
)

// sqlStore is the only Store implementation; it talks to whichever driver
// `sql.Open` selected and dispatches migration files based on Dialect.
type sqlStore struct {
	db      *sql.DB
	dialect Dialect
}

func (s *sqlStore) DB() *sql.DB      { return s.db }
func (s *sqlStore) Dialect() Dialect { return s.dialect }
func (s *sqlStore) Close() error     { return s.db.Close() }
func (s *sqlStore) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// MigrateUp applies every pending migration from the embedded set matching
// the dialect. Idempotent — safe to call at every boot (FR-H.63 step 4).
func (s *sqlStore) MigrateUp(ctx context.Context) error {
	_, err := s.MigrateUpApplied(ctx)
	return err
}

// MigrateUpApplied is MigrateUp that also reports the versions this call
// applied, in order (empty when the schema was already current).
func (s *sqlStore) MigrateUpApplied(ctx context.Context) ([]int64, error) {
	migrations, err := migrationsSub(s.dialect)
	if err != nil {
		return nil, fmt.Errorf("storage.MigrateUp: open migrations FS: %w", err)
	}

	gooseDialect, err := gooseDialectFor(s.dialect)
	if err != nil {
		return nil, err
	}

	provider, err := goose.NewProvider(gooseDialect, s.db, migrations)
	if err != nil {
		return nil, fmt.Errorf("storage.MigrateUp: new provider: %w", err)
	}

	results, err := provider.Up(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage.MigrateUp: up: %w", err)
	}
	applied := make([]int64, 0, len(results))
	for _, res := range results {
		applied = append(applied, res.Source.Version)
	}
	return applied, nil
}

// SchemaVersion returns the most recently applied migration version per
// goose's bookkeeping table. Returns 0 when no migration has run.
func (s *sqlStore) SchemaVersion(ctx context.Context) (int64, error) {
	migrations, err := migrationsSub(s.dialect)
	if err != nil {
		return 0, err
	}
	gooseDialect, err := gooseDialectFor(s.dialect)
	if err != nil {
		return 0, err
	}
	provider, err := goose.NewProvider(gooseDialect, s.db, migrations)
	if err != nil {
		return 0, err
	}
	return provider.GetDBVersion(ctx)
}

func gooseDialectFor(d Dialect) (goose.Dialect, error) {
	switch d {
	case DialectPostgres:
		return goose.DialectPostgres, nil
	case DialectSQLite:
		return goose.DialectSQLite3, nil
	default:
		return "", fmt.Errorf("storage: unknown dialect %q", d)
	}
}
