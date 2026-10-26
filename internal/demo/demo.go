// Package demo holds runtime helpers that only matter when
// SK_DEMO_MODE=true. Today that's the periodic data-reset goroutine
// (FR-H.79) which wipes every admin-controlled table every 24 h while
// preserving the schema, the bootstrap admin row, and the system-flagged
// library entries that shipped with the binary.
package demo

import (
	"context"
	"database/sql"
	"log/slog"
	"time"
)

// Resetter cycles the in-memory state of a SealKeeper demo instance.
// One per database. Owns no goroutines until Run is called.
type Resetter struct {
	db       *sql.DB
	logger   *slog.Logger
	interval time.Duration
}

// NewResetter binds a Resetter. interval is the wall-clock spacing
// between resets; for the production demo it's 24h, tests pass a tiny
// value to drive the loop.
func NewResetter(db *sql.DB, logger *slog.Logger, interval time.Duration) *Resetter {
	return &Resetter{db: db, logger: logger, interval: interval}
}

// Run blocks until ctx is cancelled. Resets fire on a ticker — the
// first one runs after `interval`, not on boot, so a freshly deployed
// demo keeps whatever the operator pre-seeded for the first cycle.
func (r *Resetter) Run(ctx context.Context) {
	if r.interval <= 0 {
		return
	}
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.ResetOnce(ctx)
		}
	}
}

// ResetOnce executes the wipe. Each statement is independent so a
// missing table (older schema, partial migration) doesn't stop the
// rest from running. Per-statement errors are logged and counted.
func (r *Resetter) ResetOnce(ctx context.Context) {
	// Order matters because of FK constraints: child rows first, then
	// parents. Schema-level metadata, admins, and system-flagged
	// libraries stay intact so the admin can still log in and the
	// shipped corpora remain available.
	statements := []string{
		"DELETE FROM admin_sessions",
		"DELETE FROM admin_webauthn_credentials",
		"DELETE FROM request_tokens",
		"DELETE FROM user_sessions",
		"DELETE FROM audit_log",
		// Back to the unsealed, empty state so the wiped log verifies as
		// intact instead of as a truncated tail; the next append re-seals.
		"UPDATE audit_head SET legacy_until = 0, head_seq = 0, head_hash = '', broken_seq = 0, head_mac = ''",
		"DELETE FROM captured_mail",
		"DELETE FROM integrations",
		"DELETE FROM email_templates",
		"DELETE FROM elevations",
		"DELETE FROM policies",
		"DELETE FROM domains",
		"DELETE FROM libraries WHERE system_flag = FALSE",
	}
	var failures int
	start := time.Now()
	for _, q := range statements {
		if _, err := r.db.ExecContext(ctx, q); err != nil {
			failures++
			r.logf("demo reset stmt failed", "stmt", q, "err", err)
		}
	}
	r.logf("demo reset complete",
		"statements", len(statements),
		"failures", failures,
		"elapsed_ms", time.Since(start).Milliseconds())
}

func (r *Resetter) logf(msg string, args ...any) {
	if r.logger == nil {
		return
	}
	r.logger.Info(msg, args...)
}
