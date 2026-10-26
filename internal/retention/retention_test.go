package retention_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/audit"
	"github.com/sched75/sealkeeper/internal/mailcapture"
	"github.com/sched75/sealkeeper/internal/retention"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
	"github.com/sched75/sealkeeper/internal/tokens"
)

const day = 24 * time.Hour

var (
	chainKey = bytes.Repeat([]byte{0x33}, audit.KeySize)
	now      = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
)

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), storagetest.SetupTimeout)
	defer cancel()
	s, err := storage.Open(ctx, storage.Options{DSN: storagetest.DSN(t)})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s.DB()
}

func exec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), storage.Rebind(db, q), args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

func count(t *testing.T, db *sql.DB, q string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := db.QueryRowContext(context.Background(), storage.Rebind(db, q), args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", q, err)
	}
	return n
}

// issueToken issues a reveal token and returns its row key: the stored
// digest (token_hash), which user_sessions.request_token references.
func issueToken(t *testing.T, db *sql.DB, at time.Time, email string) string {
	t.Helper()
	if _, err := tokens.NewRepo(db).WithClock(func() time.Time { return at }).
		Issue(context.Background(), tokens.IssueOptions{Email: email}); err != nil {
		t.Fatal(err)
	}
	var key string
	if err := db.QueryRowContext(context.Background(),
		storage.Rebind(db, `SELECT token_hash FROM request_tokens WHERE email = ?`), email).Scan(&key); err != nil {
		t.Fatal(err)
	}
	return key
}

func addAdmin(t *testing.T, db *sql.DB, email string, disabledAt any) int64 {
	t.Helper()
	exec(t, db, `INSERT INTO admins (email, password_hash, disabled_at) VALUES (?, 'x', ?)`, email, disabledAt)
	return count(t, db, `SELECT id FROM admins WHERE email = ?`, email)
}

func addAdminSession(t *testing.T, db *sql.DB, token string, adminID int64, expires, idle time.Time, revoked any) {
	t.Helper()
	exec(t, db, `INSERT INTO admin_sessions (token, admin_id, issued_at, expires_at, idle_expires_at, csrf_token, revoked_at)
		VALUES (?, ?, ?, ?, ?, 'c', ?)`, token, adminID, expires.Add(-time.Hour), expires, idle, revoked)
}

func addUserSession(t *testing.T, db *sql.DB, token, reqToken string, expires time.Time, revoked any) {
	t.Helper()
	exec(t, db, `INSERT INTO user_sessions (token, request_token, issued_at, expires_at, idle_expires_at, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?)`, token, reqToken, expires.Add(-time.Hour), expires, expires, revoked)
}

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

// SK-29 / FR-I.37: nothing ever purged request_tokens (e-mail + hashed
// IP/UA), ended sessions, captured mail, disabled accounts or old audit
// rows. One run deletes exactly what is past its period, keeps the rest,
// leaves an audit chain that verifies and records the counts (FR-I.38).
func TestRunOncePurgesExpiredData(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openDB(t)

	// request_tokens: expiry + 30 days.
	oldTok := issueToken(t, db, now.Add(-31*day), "old@corp.example")
	newTok := issueToken(t, db, now.Add(-29*day), "new@corp.example")

	// user_sessions: ended + 24 h.
	addUserSession(t, db, "us-expired", newTok, now.Add(-25*time.Hour), nil)
	addUserSession(t, db, "us-revoked", newTok, now.Add(time.Hour), now.Add(-25*time.Hour))
	addUserSession(t, db, "us-recent-end", newTok, now.Add(-23*time.Hour), nil)
	addUserSession(t, db, "us-live", newTok, now.Add(time.Hour), nil)
	addUserSession(t, db, "us-of-old-token", oldTok, now.Add(time.Hour), nil) // cascades with its token

	// admins + admin_sessions.
	active := addAdmin(t, db, "admin@localhost", nil)
	addAdmin(t, db, "paused@corp.example", now.Add(-89*day))
	longDisabled := addAdmin(t, db, "gone@corp.example", now.Add(-91*day))
	live := now.Add(time.Hour)
	addAdminSession(t, db, "as-expired", active, now.Add(-25*time.Hour), now.Add(-25*time.Hour), nil)
	addAdminSession(t, db, "as-idled", active, live, now.Add(-25*time.Hour), nil)
	addAdminSession(t, db, "as-revoked", active, live, live, now.Add(-25*time.Hour))
	addAdminSession(t, db, "as-revoked-recently", active, live, live, now.Add(-time.Hour))
	addAdminSession(t, db, "as-live", active, live, live, nil)
	addAdminSession(t, db, "as-of-gone", longDisabled, live, live, nil) // cascades with the account

	// captured_mail: 7 days.
	exec(t, db, `INSERT INTO captured_mail (to_addr, subject, body, captured_at) VALUES ('a@x', 's', 'b', ?)`, now.Add(-8*day))
	exec(t, db, `INSERT INTO captured_mail (to_addr, subject, body, captured_at) VALUES ('b@x', 's', 'b', ?)`, now.Add(-6*day))

	// audit_log: 365 days.
	auditAt := now.Add(-400 * day)
	auditRepo := audit.NewRepo(db, chainKey).WithClock(func() time.Time { return auditAt })
	for range 3 {
		if _, err := auditRepo.Append(ctx, "request.accepted", "", "old@corp.example", nil); err != nil {
			t.Fatal(err)
		}
	}
	auditAt = now.Add(-10 * day)
	if _, err := auditRepo.Append(ctx, "request.accepted", "", "new@corp.example", nil); err != nil {
		t.Fatal(err)
	}

	auditAt = now
	job := retention.NewJob(db, auditRepo, retention.DefaultPolicy(), discard()).
		WithClock(func() time.Time { return now })
	res, err := job.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	want := retention.Result{RequestTokens: 1, UserSessions: 2, AdminSessions: 3, CapturedMail: 1, DisabledAdmins: 1, AuditLog: 3}
	if res != want {
		t.Fatalf("result = %+v, want %+v", res, want)
	}

	checks := []struct {
		q    string
		want int64
	}{
		{`SELECT COUNT(*) FROM request_tokens WHERE token_hash = '` + newTok + `'`, 1},
		{`SELECT COUNT(*) FROM request_tokens`, 1},
		{`SELECT COUNT(*) FROM user_sessions WHERE token IN ('us-recent-end', 'us-live')`, 2},
		{`SELECT COUNT(*) FROM user_sessions`, 2},
		{`SELECT COUNT(*) FROM admin_sessions WHERE token IN ('as-revoked-recently', 'as-live')`, 2},
		{`SELECT COUNT(*) FROM admin_sessions`, 2},
		{`SELECT COUNT(*) FROM captured_mail`, 1},
		{`SELECT COUNT(*) FROM admins WHERE email = 'gone@corp.example'`, 0},
		{`SELECT COUNT(*) FROM admins`, 2},
		{`SELECT COUNT(*) FROM audit_log WHERE target = 'old@corp.example'`, 0},
	}
	for _, c := range checks {
		if got := count(t, db, c.q); got != c.want {
			t.Errorf("%s = %d, want %d", c.q, got, c.want)
		}
	}

	if bad, err := auditRepo.VerifyChain(ctx); err != nil || bad != 0 {
		t.Fatalf("VerifyChain after purge = %d, %v", bad, err)
	}

	// FR-I.38: the run is on record with the per-category counts.
	var details string
	if err := db.QueryRowContext(ctx, storage.Rebind(db,
		`SELECT details_json FROM audit_log WHERE event_type = ?`), retention.EventPurgeRun).Scan(&details); err != nil {
		t.Fatalf("no %s event: %v", retention.EventPurgeRun, err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(details), &got); err != nil {
		t.Fatal(err)
	}
	if got["request_tokens"] != 1.0 || got["audit_log"] != 3.0 || got["disabled_admins"] != 1.0 || got["audit_skipped"] != false {
		t.Fatalf("purge run details = %v", got)
	}

	// A second run finds nothing new and still verifies.
	if res, err := job.RunOnce(ctx); err != nil || res != (retention.Result{}) {
		t.Fatalf("second run = %+v, %v; want nothing purged", res, err)
	}
	if bad, _ := auditRepo.VerifyChain(ctx); bad != 0 {
		t.Fatalf("VerifyChain after second run = %d", bad)
	}
}

// A broken chain is evidence: the job leaves the audit log alone, says so
// in the run record, and still purges the other categories.
func TestRunOnceLeavesBrokenAuditChainAlone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openDB(t)
	auditRepo := audit.NewRepo(db, chainKey).WithClock(func() time.Time { return now.Add(-400 * day) })
	for range 3 {
		if _, err := auditRepo.Append(ctx, "admin.login", "admin@localhost", "", nil); err != nil {
			t.Fatal(err)
		}
	}
	exec(t, db, `UPDATE audit_log SET actor = 'forged' WHERE sequence_no = (SELECT MIN(sequence_no) FROM audit_log)`)
	issueToken(t, db, now.Add(-40*day), "old@corp.example")

	var recorded map[string]any
	job := retention.NewJob(db, auditRepo, retention.DefaultPolicy(), discard()).
		WithClock(func() time.Time { return now }).
		WithRecorder(func(_ context.Context, event, _, _ string, d map[string]any) {
			if event == retention.EventPurgeRun {
				recorded = d
			}
		})
	res, err := job.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !res.AuditSkipped || res.AuditLog != 0 || res.RequestTokens != 1 {
		t.Fatalf("result = %+v, want audit skipped and the token purged", res)
	}
	if n := count(t, db, `SELECT COUNT(*) FROM audit_log`); n != 3 {
		t.Fatalf("%d audit rows left, want all 3", n)
	}
	if recorded == nil || recorded["audit_skipped"] != true {
		t.Fatalf("recorder got %v, want audit_skipped=true", recorded)
	}
}

// The in-memory captured-mail queue (eval / demo) expires too.
func TestRunOncePrunesMailStore(t *testing.T) {
	t.Parallel()
	db := openDB(t)
	store := mailcapture.NewStore(10)
	store.Capture("a@corp.example", "s", "b")
	later := time.Now().Add(8 * day)
	res, err := retention.NewJob(db, nil, retention.DefaultPolicy(), discard()).
		WithMailStore(store).
		WithClock(func() time.Time { return later }).
		RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.CapturedMail != 1 || len(store.Snapshot()) != 0 {
		t.Fatalf("captured mail purged = %d, %d left", res.CapturedMail, len(store.Snapshot()))
	}
}

// A zero period would purge everything at once; the job refuses to run.
func TestRunOnceRefusesZeroPeriod(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openDB(t)
	auditRepo := audit.NewRepo(db, chainKey)
	for range 3 {
		if _, err := auditRepo.Append(ctx, "admin.login", "", "", nil); err != nil {
			t.Fatal(err)
		}
	}
	p := retention.DefaultPolicy()
	p.AuditLog = 0
	if _, err := retention.NewJob(db, auditRepo, p, discard()).
		WithClock(func() time.Time { return time.Now().Add(time.Hour) }).RunOnce(ctx); err == nil {
		t.Fatal("RunOnce accepted a zero audit retention")
	}
	if n := count(t, db, `SELECT COUNT(*) FROM audit_log`); n != 3 {
		t.Fatalf("%d audit rows left, want 3", n)
	}
}

// Run purges at start-up without waiting for the first tick.
func TestRunPurgesImmediately(t *testing.T) {
	t.Parallel()
	db := openDB(t)
	issueToken(t, db, now.Add(-40*day), "old@corp.example")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	job := retention.NewJob(db, nil, retention.DefaultPolicy(), discard()).
		WithClock(func() time.Time { return now })
	go func() { job.Run(ctx, time.Hour); close(done) }()
	deadline := time.Now().Add(30 * time.Second)
	for count(t, db, `SELECT COUNT(*) FROM request_tokens`) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("Run did not purge at start-up")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}
