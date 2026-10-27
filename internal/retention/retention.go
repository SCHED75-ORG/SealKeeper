// Package retention runs the scheduled purge of personal data that has
// outlived its retention period (RGPD module I, FR-I.10, FR-I.29..38).
//
// The job runs at startup and then daily (FR-I.37). Each category has its
// own period (see Policy and the SK_RETENTION_* knobs):
//
//	request_tokens   e-mail + hashed IP/UA of a request: expiry + 30 days (FR-I.29)
//	user_sessions    ended (expired, idled out or revoked) + 24 h (FR-I.30)
//	admin_sessions   ended (expired, idled out or revoked) + 24 h (FR-I.30)
//	audit_log        365 days, six-month floor (FR-I.31)
//	captured mail    7 days, table and in-memory queue (FR-I.32)
//	admins           disabled for 90 days: account deleted (FR-I.34)
//
// The audit log is pruned through audit.Repo.Prune, which only deletes
// whole rows from the old end of the chain and records a MAC-bound base so
// VerifyChain still passes; hashed content is never rewritten. Personal
// data inside audit details (actor / target e-mails) therefore expires
// with its row. A chain that does not verify is not pruned at all: the
// evidence of the break outranks storage limitation (GDPR art. 17.3.b).
//
// Every run writes one retention.purge_run audit event carrying the number
// of entries purged per category (FR-I.38).
package retention

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/sched75/sealkeeper/internal/audit"
	"github.com/sched75/sealkeeper/internal/mailcapture"
	"github.com/sched75/sealkeeper/internal/storage"
)

// EventPurgeRun is the audit event written after every run (FR-I.38).
const EventPurgeRun = "retention.purge_run"

// Interval is how often serve runs the job (FR-I.37: daily).
const Interval = 24 * time.Hour

// Policy holds the retention period of each category.
type Policy struct {
	RequestTokens  time.Duration // after the token's expiry (FR-I.29)
	SessionGrace   time.Duration // after a session ended (FR-I.30)
	AuditLog       time.Duration // after the event (FR-I.31)
	CapturedMail   time.Duration // after capture (FR-I.32)
	DisabledAdmins time.Duration // after the account was disabled (FR-I.34)
}

// DefaultPolicy returns the PRD defaults (module I §3.5).
func DefaultPolicy() Policy {
	return Policy{
		RequestTokens:  30 * 24 * time.Hour,
		SessionGrace:   24 * time.Hour,
		AuditLog:       365 * 24 * time.Hour,
		CapturedMail:   7 * 24 * time.Hour,
		DisabledAdmins: 90 * 24 * time.Hour,
	}
}

// validate refuses a period that is not positive: a zero value (say, a
// Policy built without its fields) would purge everything at once,
// including every audit row but the newest.
func (p Policy) validate() error {
	for _, d := range []time.Duration{p.RequestTokens, p.SessionGrace, p.AuditLog, p.CapturedMail, p.DisabledAdmins} {
		if d <= 0 {
			return fmt.Errorf("retention: every period must be positive, got %+v", p)
		}
	}
	return nil
}

// Recorder appends an audit event. serve passes the HTTP server's audit
// writer so the run summary also reaches the SIEM integrations.
type Recorder func(ctx context.Context, event, actor, target string, details map[string]any)

// Result counts the entries purged per category by one run.
type Result struct {
	RequestTokens  int64
	UserSessions   int64
	AdminSessions  int64
	CapturedMail   int64
	DisabledAdmins int64
	AuditLog       int64
	// AuditSkipped is set when the audit chain did not verify and was
	// therefore left untouched.
	AuditSkipped bool
}

// Job purges expired personal data. Build it with NewJob.
type Job struct {
	db     *sql.DB
	audit  *audit.Repo
	mail   *mailcapture.Store
	record Recorder
	policy Policy
	logger *slog.Logger
	now    func() time.Time
}

// NewJob binds the job to the database and the audit repo (nil skips the
// audit log and records nothing).
func NewJob(db *sql.DB, auditRepo *audit.Repo, policy Policy, logger *slog.Logger) *Job {
	return &Job{db: db, audit: auditRepo, policy: policy, logger: logger, now: time.Now}
}

// WithMailStore also prunes the in-memory captured-mail queue.
func (j *Job) WithMailStore(m *mailcapture.Store) *Job {
	j.mail = m
	return j
}

// WithRecorder routes the run summary through rec instead of appending
// it to the audit repo directly.
func (j *Job) WithRecorder(rec Recorder) *Job {
	j.record = rec
	return j
}

// WithClock returns a copy of the job bound to a custom clock (tests).
func (j *Job) WithClock(now func() time.Time) *Job {
	c := *j
	c.now = now
	return &c
}

// Run purges once immediately, then every interval until ctx is done.
func (j *Job) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		j.runLogged(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (j *Job) runLogged(ctx context.Context) {
	res, err := j.RunOnce(ctx)
	if err != nil {
		j.logger.Error("retention purge failed", "err", err)
	}
	j.logger.Info("retention purge run", "summary", res.details())
}

// RunOnce purges every category once and records the run in the audit
// log. A failing category does not stop the others; their errors are
// joined.
func (j *Job) RunOnce(ctx context.Context) (Result, error) {
	now := j.now().UTC()
	p := j.policy
	var res Result
	if err := p.validate(); err != nil {
		return res, err
	}
	steps := []struct {
		query string
		age   time.Duration
		dst   *int64
	}{
		// Sessions first: user_sessions references request_tokens and
		// admin_sessions references admins.
		{`DELETE FROM user_sessions WHERE expires_at < ? OR idle_expires_at < ? OR revoked_at < ?`,
			p.SessionGrace, &res.UserSessions},
		{`DELETE FROM admin_sessions WHERE expires_at < ? OR idle_expires_at < ? OR revoked_at < ?`,
			p.SessionGrace, &res.AdminSessions},
		{`DELETE FROM request_tokens WHERE expires_at < ?`, p.RequestTokens, &res.RequestTokens},
		{`DELETE FROM captured_mail WHERE captured_at < ?`, p.CapturedMail, &res.CapturedMail},
		{`DELETE FROM admins WHERE disabled_at IS NOT NULL AND disabled_at < ?`,
			p.DisabledAdmins, &res.DisabledAdmins},
	}
	var errs []error
	for _, s := range steps {
		n, err := j.purge(ctx, s.query, now.Add(-s.age))
		errs = append(errs, err)
		*s.dst += n
	}
	if j.mail != nil {
		res.CapturedMail += int64(j.mail.PruneBefore(now.Add(-p.CapturedMail)))
	}
	errs = append(errs, j.pruneAudit(ctx, now.Add(-p.AuditLog), &res))
	j.recordRun(ctx, res)
	return res, errors.Join(errs...)
}

// purge runs one DELETE, binding cutoff to every placeholder.
func (j *Job) purge(ctx context.Context, query string, cutoff time.Time) (int64, error) {
	args := make([]any, strings.Count(query, "?"))
	for i := range args {
		args[i] = cutoff
	}
	r, err := j.db.ExecContext(ctx, storage.Rebind(j.db, query), args...)
	if err != nil {
		return 0, fmt.Errorf("retention: %s: %w", strings.Fields(query)[2], err)
	}
	n, _ := r.RowsAffected()
	return n, nil
}

func (j *Job) pruneAudit(ctx context.Context, cutoff time.Time, res *Result) error {
	if j.audit == nil {
		return nil
	}
	n, err := j.audit.Prune(ctx, cutoff)
	if errors.Is(err, audit.ErrChainBroken) {
		res.AuditSkipped = true
		j.logger.Warn("retention: audit chain does not verify; audit log left untouched", "err", err)
		return nil
	}
	res.AuditLog = n
	return err
}

func (j *Job) recordRun(ctx context.Context, res Result) {
	details := res.details()
	switch {
	case j.record != nil:
		j.record(ctx, EventPurgeRun, "system", "retention", details)
	case j.audit != nil:
		if _, err := j.audit.Append(ctx, EventPurgeRun, "system", "retention", details); err != nil {
			j.logger.Warn("retention: audit append failed", "err", err)
		}
	}
}

func (r Result) details() map[string]any {
	return map[string]any{
		"request_tokens":  r.RequestTokens,
		"user_sessions":   r.UserSessions,
		"admin_sessions":  r.AdminSessions,
		"captured_mail":   r.CapturedMail,
		"disabled_admins": r.DisabledAdmins,
		"audit_log":       r.AuditLog,
		"audit_skipped":   r.AuditSkipped,
	}
}
