package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"strings"

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
// applied, in order (empty when the schema was already current). When a
// later migration fails, the versions applied before it are still
// returned, together with the error.
func (s *sqlStore) MigrateUpApplied(ctx context.Context) ([]int64, error) {
	return s.MigrateUpCutover(ctx, nil)
}

// MigrateUpCutover is MigrateUpApplied that runs cutover inside the
// transaction applying migration AuditHeadMigration, after its SQL. A nil
// cutover applies the plain SQL file.
func (s *sqlStore) MigrateUpCutover(ctx context.Context, cutover CutoverFunc) ([]int64, error) {
	migrations, err := migrationsSub(s.dialect)
	if err != nil {
		return nil, fmt.Errorf("storage.MigrateUp: open migrations FS: %w", err)
	}

	gooseDialect, err := gooseDialectFor(s.dialect)
	if err != nil {
		return nil, err
	}

	var opts []goose.ProviderOption
	if cutover != nil {
		m, err := cutoverMigration(migrations, cutover)
		if err != nil {
			return nil, fmt.Errorf("storage.MigrateUp: %w", err)
		}
		opts = append(opts, goose.WithExcludeVersions([]int64{AuditHeadMigration}), goose.WithGoMigrations(m))
	}
	provider, err := goose.NewProvider(gooseDialect, s.db, migrations, opts...)
	if err != nil {
		return nil, fmt.Errorf("storage.MigrateUp: new provider: %w", err)
	}

	results, err := provider.Up(ctx)
	var partial *goose.PartialError
	if errors.As(err, &partial) {
		results = partial.Applied
	}
	applied := make([]int64, 0, len(results))
	for _, res := range results {
		applied = append(applied, res.Source.Version)
	}
	if err != nil {
		return applied, fmt.Errorf("storage.MigrateUp: up: %w", err)
	}
	return applied, nil
}

// cutoverMigration turns the AuditHeadMigration SQL file into a Go
// migration running the same statements, then cutover, in one transaction:
// the audit cut-over commits with the schema change or not at all, so no
// crash, timeout or later failure can separate them.
func cutoverMigration(migrations fs.FS, cutover CutoverFunc) (*goose.Migration, error) {
	names, err := fs.Glob(migrations, fmt.Sprintf("%04d_*.sql", AuditHeadMigration))
	if err != nil {
		return nil, fmt.Errorf("audit head migration: %w", err)
	}
	if len(names) != 1 {
		return nil, fmt.Errorf("audit head migration %04d: found %d files", AuditHeadMigration, len(names))
	}
	src, err := fs.ReadFile(migrations, names[0])
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", names[0], err)
	}
	up, down, ok := strings.Cut(string(src), "-- +goose Down")
	if !ok {
		return nil, fmt.Errorf("%s: no Down section", names[0])
	}
	upSQL, downSQL := stripGooseAnnotations(up), stripGooseAnnotations(down)
	return goose.NewGoMigration(AuditHeadMigration,
		&goose.GoFunc{RunTx: func(ctx context.Context, tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, upSQL); err != nil {
				return err
			}
			return cutover(ctx, tx)
		}},
		&goose.GoFunc{RunTx: func(ctx context.Context, tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, downSQL)
			return err
		}},
	), nil
}

// stripGooseAnnotations drops the "-- +goose ..." lines. The head migration
// is one StatementBegin/End block per section, which goose itself sends as
// a single Exec, so the remainder runs the same way.
func stripGooseAnnotations(section string) string {
	lines := strings.Split(section, "\n")
	kept := lines[:0]
	for _, l := range lines {
		if !strings.HasPrefix(strings.TrimSpace(l), "-- +goose") {
			kept = append(kept, l)
		}
	}
	return strings.Join(kept, "\n")
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
