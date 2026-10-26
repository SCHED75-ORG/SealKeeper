// Package storage owns the database surface for SealKeeper.
//
// The exposed [Store] is intentionally narrow at v0.1 — it is the seam every
// caller (HTTP handlers, the CLI, /readyz probes, the test suite) goes
// through, regardless of whether the driver underneath is Postgres or
// SQLite.
//
// Schema migrations are forward-only, owned by goose, and embedded at build
// time. See migrations/README.md for the contract.
package storage

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ensureSQLiteDir creates the parent directory of a file-backed SQLite DB.
// :memory: and file:?cache=... DSNs are left alone. This lets the 5-second
// `docker run -e SK_MODE=eval` pitch work without external volume mounts.
func ensureSQLiteDir(dsn string) error {
	if dsn == "" || strings.HasPrefix(dsn, ":memory:") {
		return nil
	}
	// Strip query string and `file:` scheme to get a filesystem path.
	path := strings.TrimPrefix(dsn, "file:")
	if i := strings.Index(path, "?"); i >= 0 {
		path = path[:i]
	}
	if path == "" || path == ":memory:" {
		return nil
	}
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}

// Dialect identifies which migration set + driver applies to a DSN.
type Dialect string

const (
	DialectPostgres Dialect = "postgres"
	DialectSQLite   Dialect = "sqlite"
)

// Store is the application-facing handle. It deliberately does not expose
// CRUD primitives yet — the typed repositories will sit on top of this once
// their consuming features land.
type Store interface {
	// Ping verifies the connection is alive. Used by /readyz.
	Ping(ctx context.Context) error
	// Close releases the underlying pool.
	Close() error
	// DB returns the underlying *sql.DB so the migration runner and
	// repositories can talk to it directly.
	DB() *sql.DB
	// Dialect reports which migration set applies.
	Dialect() Dialect

	// MigrateUp runs all pending up migrations. Idempotent.
	MigrateUp(ctx context.Context) error
	// MigrateUpApplied is MigrateUp that also returns the versions this
	// call applied. Callers use it for one-shot work tied to a specific
	// migration (the audit anchor seal after 0014).
	MigrateUpApplied(ctx context.Context) ([]int64, error)
	// SchemaVersion returns the version recorded by goose. Zero means no
	// migration has ever been applied.
	SchemaVersion(ctx context.Context) (int64, error)
}

// Options configures [Open].
type Options struct {
	// DSN is the database connection string. Schemes recognised:
	//   postgres://  pgx://     → DialectPostgres
	//   sqlite://    file:      → DialectSQLite
	DSN string
	// MaxOpenConns / MaxIdleConns / ConnMaxLifetime configure the pool.
	// Zero values get sensible defaults per driver.
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// Open returns a Store for the given DSN.
//
// The dialect is inferred from the URL scheme, the appropriate driver is
// registered (via blank imports in the per-dialect files) and the pool is
// configured with sane defaults. The caller is responsible for [Store.Close].
func Open(ctx context.Context, opts Options) (Store, error) {
	if opts.DSN == "" {
		return nil, errors.New("storage.Open: empty DSN")
	}
	dialect, driver, dataSource, err := parseDSN(opts.DSN)
	if err != nil {
		return nil, err
	}

	if dialect == DialectSQLite {
		if err := ensureSQLiteDir(dataSource); err != nil {
			return nil, fmt.Errorf("storage.Open: %w", err)
		}
	}

	db, err := sql.Open(driver, dataSource)
	if err != nil {
		return nil, fmt.Errorf("storage.Open: %w", err)
	}
	configurePool(db, dialect, opts)

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage.Open: initial ping: %w", err)
	}

	return &sqlStore{db: db, dialect: dialect}, nil
}

func configurePool(db *sql.DB, dialect Dialect, opts Options) {
	maxOpen := opts.MaxOpenConns
	if maxOpen == 0 {
		if dialect == DialectSQLite {
			// SQLite is single-writer; oversubscribing only causes lock contention.
			maxOpen = 1
		} else {
			maxOpen = 25
		}
	}
	maxIdle := opts.MaxIdleConns
	if maxIdle == 0 {
		maxIdle = maxOpen
	}
	lifetime := opts.ConnMaxLifetime
	if lifetime == 0 {
		lifetime = 30 * time.Minute
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(lifetime)
}

// parseDSN returns (dialect, driverName, dataSource, error).
func parseDSN(dsn string) (Dialect, string, string, error) {
	switch {
	case strings.HasPrefix(dsn, "postgres://"), strings.HasPrefix(dsn, "postgresql://"):
		return DialectPostgres, "pgx", dsn, nil
	case strings.HasPrefix(dsn, "pgx://"):
		return DialectPostgres, "pgx", strings.Replace(dsn, "pgx://", "postgres://", 1), nil
	case strings.HasPrefix(dsn, "sqlite://"):
		// Strip the URL scheme and keep modernc-style file path with options.
		// `sqlite:///data/db.sqlite?_pragma=journal_mode(WAL)` parses with
		// url.Parse so we can preserve query parameters cleanly.
		u, err := url.Parse(dsn)
		if err != nil {
			return "", "", "", fmt.Errorf("storage.Open: parse sqlite DSN: %w", err)
		}
		path := u.Path
		if u.Host != "" && u.Host != "/" {
			// sqlite://:memory: surfaces as Host = ":memory:".
			path = u.Host + u.Path
		}
		if path == "" {
			path = ":memory:"
		}
		if u.RawQuery != "" {
			path += "?" + u.RawQuery
		}
		return DialectSQLite, "sqlite", sqliteForeignKeys(path), nil
	case strings.HasPrefix(dsn, "file:"), dsn == ":memory:":
		return DialectSQLite, "sqlite", sqliteForeignKeys(dsn), nil
	default:
		return "", "", "", fmt.Errorf("storage.Open: unrecognised DSN scheme in %q", dsn)
	}
}

// sqliteForeignKeys turns PRAGMA foreign_keys on for every pooled SQLite
// connection. Without it SQLite parses the schema's REFERENCES … ON DELETE
// clauses but never enforces them, whereas Postgres always does — deleting
// an admin would cascade to its sessions on one dialect only. A DSN that
// already sets foreign_keys keeps its own value.
func sqliteForeignKeys(dataSource string) string {
	if strings.Contains(dataSource, "foreign_keys") {
		return dataSource
	}
	sep := "?"
	if strings.Contains(dataSource, "?") {
		sep = "&"
	}
	return dataSource + sep + "_pragma=foreign_keys(1)"
}

// ----------------------------------------------------------------------------
// Migrations — embedded at build time, applied by goose against the live DB.
// ----------------------------------------------------------------------------

//go:embed all:migrations
var migrationsFS embed.FS

// migrationsSub returns an fs.FS rooted at migrations/<dialect>/.
func migrationsSub(dialect Dialect) (fs.FS, error) {
	return fs.Sub(migrationsFS, "migrations/"+string(dialect))
}

// readinessCheck adapts a Store to the readiness.Checker shape without pulling
// the readiness package into storage (which would create a cycle if readiness
// ever adopted typed checks). The HTTP server wires this via
// NewReadinessCheck.
type readinessCheck struct {
	name  string
	store Store
}

// Name implements readiness.Checker.
func (r readinessCheck) Name() string { return r.name }

// Check implements readiness.Checker — pings within a short context.
func (r readinessCheck) Check(ctx context.Context) error {
	if r.store == nil {
		return errors.New("storage: nil store")
	}
	c, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	return r.store.Ping(c)
}

// NewReadinessCheck returns a value usable by internal/readiness.
func NewReadinessCheck(name string, s Store) interface {
	Name() string
	Check(ctx context.Context) error
} {
	if name == "" {
		name = "database"
	}
	return readinessCheck{name: name, store: s}
}
