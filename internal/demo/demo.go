// Package demo holds runtime helpers that only matter when
// SK_DEMO_MODE=true. Today that's the periodic data-reset goroutine
// (FR-H.79) which wipes every admin-controlled table every 24 h while
// preserving the schema and the system-flagged library entries that
// shipped with the binary.
//
// The demo console is shared by strangers, so anything a visitor can
// change must come back to a known state at the next reset. Tables a
// visitor may legitimately edit (domains, policies, elevations, templates)
// are emptied. The instance identity a visitor must never keep —
// operator accounts, branding, SMTP override, kv — is restored from a
// snapshot taken at boot (Snapshot), i.e. whatever the operator seeded.
package demo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sched75/sealkeeper/internal/mailcapture"
	"github.com/sched75/sealkeeper/internal/storage"
)

// wipedTables are emptied on every reset. Order matters because of FK
// constraints: child rows first, then parents.
var wipedTables = []string{
	"DELETE FROM admin_sessions",
	"DELETE FROM admin_webauthn_credentials",
	"DELETE FROM request_tokens",
	"DELETE FROM user_sessions",
	"DELETE FROM audit_log",
	// Back to the unsealed, empty state so the wiped log verifies as intact
	// instead of as a truncated tail; the next append re-seals.
	"UPDATE audit_head SET legacy_until = 0, head_seq = 0, head_hash = '', broken_seq = 0, head_mac = ''",
	"DELETE FROM captured_mail",
	"DELETE FROM integrations",
	"DELETE FROM email_templates",
	"DELETE FROM elevations",
	"DELETE FROM policies",
	"DELETE FROM domains",
	"DELETE FROM libraries WHERE system_flag = FALSE",
}

// restoredTables are rewritten from the boot snapshot on every reset.
// Parents first on insert; the reverse order is used to delete.
var restoredTables = []string{"admins", "branding", "smtp_config", "kv"}

// Resetter cycles the state of a SealKeeper demo instance.
// One per database. Owns no goroutines until Run is called.
type Resetter struct {
	db       *sql.DB
	logger   *slog.Logger
	interval time.Duration
	mail     *mailcapture.Store
	libDir   string

	mu       sync.Mutex
	snapshot map[string]tableRows // nil until Snapshot succeeds
}

type tableRows struct {
	cols []string
	rows [][]any
}

// NewResetter binds a Resetter. interval is the wall-clock spacing
// between resets; for the production demo it's 24h, tests pass a tiny
// value to drive the loop.
func NewResetter(db *sql.DB, logger *slog.Logger, interval time.Duration) *Resetter {
	return &Resetter{db: db, logger: logger, interval: interval}
}

// WithMailStore makes every reset also purge the in-memory capture queue,
// which holds the demo visitors' addresses and reveal links.
func (r *Resetter) WithMailStore(m *mailcapture.Store) *Resetter {
	r.mail = m
	return r
}

// WithLibrariesDir points the reset at the on-disk library store
// (SK_LIBRARIES_DIR). Wiping the non-system rows alone would leave their
// files behind, so after each reset every library blob no remaining row
// references is deleted.
func (r *Resetter) WithLibrariesDir(dir string) *Resetter {
	r.libDir = dir
	return r
}

// Snapshot records the current rows of the restored tables (accounts,
// branding, SMTP override, kv) as the known state every reset returns to.
// Call it at boot, after the bootstrap admin exists and before the HTTP
// server accepts visitors. Run takes it itself when it has not been taken.
func (r *Resetter) Snapshot(ctx context.Context) error {
	snap := make(map[string]tableRows, len(restoredTables))
	for _, table := range restoredTables {
		tr, err := readTable(ctx, r.db, table)
		if err != nil {
			return fmt.Errorf("demo: snapshot %s: %w", table, err)
		}
		snap[table] = tr
	}
	r.mu.Lock()
	r.snapshot = snap
	r.mu.Unlock()
	return nil
}

// Run blocks until ctx is cancelled. Resets fire on a ticker — the
// first one runs after `interval`, not on boot, so a freshly deployed
// demo keeps whatever the operator pre-seeded for the first cycle.
func (r *Resetter) Run(ctx context.Context) {
	if r.interval <= 0 {
		return
	}
	r.mu.Lock()
	missing := r.snapshot == nil
	r.mu.Unlock()
	if missing {
		if err := r.Snapshot(ctx); err != nil {
			r.logError("demo snapshot failed; accounts and branding will not be restored", err)
		}
	}
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.ResetOnce(ctx); err != nil {
				r.logError("demo reset failed", err)
			}
		}
	}
}

// ResetOnce executes the wipe and the restore in one transaction, so a
// reset never interleaves with live requests and never leaves the demo
// half-reset. Without a snapshot the restored tables are left untouched:
// snapshotting now would capture whatever a visitor did since boot.
func (r *Resetter) ResetOnce(ctx context.Context) error {
	start := time.Now()
	r.mu.Lock()
	snap := r.snapshot
	r.mu.Unlock()

	if err := r.resetTx(ctx, snap); err != nil {
		return err
	}
	if r.mail != nil {
		r.mail.Reset()
	}
	if r.libDir != "" {
		if err := r.sweepLibraryFiles(ctx); err != nil {
			r.logError("demo reset: library file sweep failed", err)
		}
	}
	if r.logger != nil {
		r.logger.Info("demo reset complete",
			"wiped", len(wipedTables),
			"restored", snap != nil,
			"elapsed_ms", time.Since(start).Milliseconds())
	}
	return nil
}

// resetTx runs the wipe and, when snap is non-nil, the snapshot restore
// inside a single transaction, committing only if every step succeeded.
func (r *Resetter) resetTx(ctx context.Context, snap map[string]tableRows) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("demo: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, q := range wipedTables {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("demo: %s: %w", q, err)
		}
	}
	if snap != nil {
		if err := r.restoreSnapshot(ctx, tx, snap); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("demo: commit: %w", err)
	}
	return nil
}

// restoreSnapshot clears the restored tables in reverse order, then
// re-inserts the boot snapshot rows in forward order, all within tx.
func (r *Resetter) restoreSnapshot(ctx context.Context, tx *sql.Tx, snap map[string]tableRows) error {
	for i := len(restoredTables) - 1; i >= 0; i-- {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+restoredTables[i]); err != nil {
			return fmt.Errorf("demo: clear %s: %w", restoredTables[i], err)
		}
	}
	for _, table := range restoredTables {
		if err := insertRows(ctx, r.db, tx, table, snap[table]); err != nil {
			return fmt.Errorf("demo: restore %s: %w", table, err)
		}
	}
	return nil
}

// libraryBlob matches the content-addressed names libraries.Repo.Upload
// writes (<sha256 hex>.txt); nothing else in the directory is touched.
var libraryBlob = regexp.MustCompile(`^[0-9a-f]{64}\.txt$`)

// sweepLibraryFiles deletes every library blob in libDir that no
// remaining libraries row references: the files of the non-system rows
// the reset just wiped, plus any orphan an earlier reset left behind.
func (r *Resetter) sweepLibraryFiles(ctx context.Context) error {
	keep, err := r.libraryFiles(ctx)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(r.libDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	var errs []error
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || !libraryBlob.MatchString(name) || keep[name] {
			continue
		}
		if err := os.Remove(filepath.Join(r.libDir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// libraryFiles returns the base names of the files the remaining
// libraries rows reference.
func (r *Resetter) libraryFiles(ctx context.Context) (map[string]bool, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT file_path FROM libraries")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keep := map[string]bool{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		keep[filepath.Base(p)] = true
	}
	return keep, rows.Err()
}

// readTable copies every row of table. Values round-trip through the same
// driver on insert, so no per-column typing is needed.
func readTable(ctx context.Context, db *sql.DB, table string) (tableRows, error) {
	rows, err := db.QueryContext(ctx, "SELECT * FROM "+table) // #nosec G202 -- table is from the fixed restoredTables list
	if err != nil {
		return tableRows{}, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return tableRows{}, err
	}
	out := tableRows{cols: cols}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return tableRows{}, err
		}
		out.rows = append(out.rows, vals)
	}
	return out, rows.Err()
}

func insertRows(ctx context.Context, db *sql.DB, tx *sql.Tx, table string, tr tableRows) error {
	if len(tr.rows) == 0 {
		return nil
	}
	if len(tr.cols) == 0 {
		return errors.New("no columns")
	}
	quoted := make([]string, len(tr.cols))
	for i, c := range tr.cols {
		quoted[i] = `"` + strings.ReplaceAll(c, `"`, `""`) + `"`
	}
	q := storage.Rebind(db, "INSERT INTO "+table+" ("+strings.Join(quoted, ", ")+
		") VALUES ("+strings.TrimSuffix(strings.Repeat("?, ", len(tr.cols)), ", ")+")")
	for _, row := range tr.rows {
		if _, err := tx.ExecContext(ctx, q, row...); err != nil {
			return err
		}
	}
	return nil
}

func (r *Resetter) logError(msg string, err error) {
	if r.logger == nil {
		return
	}
	r.logger.Error(msg, "err", err)
}
