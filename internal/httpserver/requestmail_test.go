package httpserver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/config"
	"github.com/sched75/sealkeeper/internal/domains"
	"github.com/sched75/sealkeeper/internal/mail"
)

// relaySender emulates a slow SMTP relay.
type relaySender struct {
	delay time.Duration
	err   error
	sent  chan string
}

func (r *relaySender) Send(ctx context.Context, msg mail.Message) error {
	select {
	case <-time.After(r.delay):
	case <-ctx.Done():
		return ctx.Err()
	}
	r.sent <- msg.To
	return r.err
}

func (*relaySender) Name() string { return "smtp" }

func countAudit(t *testing.T, db *sql.DB, event string) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_log WHERE event_type = '`+event+`'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Regression (SK-28): the allowed path waited for the SMTP relay inline
// while denied paths returned at once, so response latency revealed the
// domain allowlist and the policy coverage despite identical 202 bodies.
func TestRequestLatencyDoesNotRevealTheOutcome(t *testing.T) {
	t.Parallel()
	s, _, db := newModeServer(t, config.ModeProduction, false)
	const floor = 150 * time.Millisecond
	const relay = 600 * time.Millisecond
	s.requestFloor = floor
	relaySend := &relaySender{delay: relay, sent: make(chan string, 1)}
	s.SetSender(relaySend)
	if _, err := domains.NewRepo(db).Create(context.Background(), "corp.test", "", true, nil); err != nil {
		t.Fatal(err)
	}
	h := s.Router()

	timed := func(remote, email string) time.Duration {
		t.Helper()
		start := time.Now()
		w := postRequest(h, remote, email)
		if w.Code != http.StatusAccepted || w.Body.String() != "{\"status\":\"accepted\"}\n" {
			t.Fatalf("%s: %d %q", email, w.Code, w.Body.String())
		}
		return time.Since(start)
	}
	denied := timed("192.0.2.10:1000", "someone@not-allowlisted.test")
	allowed := timed("192.0.2.11:1000", "user@corp.test")
	t.Logf("allowed=%v denied=%v", allowed, denied)

	if allowed >= relay {
		t.Errorf("allowed path took %v: it still waits for the relay (%v)", allowed, relay)
	}
	if denied < floor {
		t.Errorf("denied path took %v, below the %v floor", denied, floor)
	}

	select {
	case to := <-relaySend.sent:
		if to != "user@corp.test" {
			t.Errorf("mail sent to %q", to)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reveal mail never reached the relay")
	}
	if n := countAudit(t, db, "token.issued"); n != 1 {
		t.Errorf("token.issued audited %d times, want 1", n)
	}
}

func TestBackgroundSendFailureIsAudited(t *testing.T) {
	t.Parallel()
	s, _, db := newModeServer(t, config.ModeProduction, false)
	s.requestFloor = 0
	s.SetSender(&relaySender{err: errors.New("relay refused"), sent: make(chan string, 1)})
	if w := postRequest(s.Router(), "192.0.2.12:1000", "user@example.test"); w.Code != http.StatusAccepted {
		t.Fatalf("status %d", w.Code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.WaitMail(ctx)
	if n := countAudit(t, db, "mail.send_failed"); n != 1 {
		t.Fatalf("mail.send_failed audited %d times, want 1", n)
	}
}

func TestMailQueueFullDropsAndAudits(t *testing.T) {
	t.Parallel()
	s, _, db := newModeServer(t, config.ModeProduction, false)
	s.requestFloor = 0
	s.mailQueue = make(chan struct{}) // queue full
	s.SetSender(&relaySender{sent: make(chan string, 1)})
	if w := postRequest(s.Router(), "192.0.2.13:1000", "user@example.test"); w.Code != http.StatusAccepted {
		t.Fatalf("status %d", w.Code)
	}
	if n := countAudit(t, db, "mail.send_failed"); n != 1 {
		t.Fatalf("mail.send_failed audited %d times, want 1", n)
	}
}

// Regression: with every worker busy the reveal mail was dropped at once,
// so a burst of slow sends silently cost legitimate users their link.
func TestMailWaitsForAFreeWorker(t *testing.T) {
	t.Parallel()
	s, _, db := newModeServer(t, config.ModeProduction, false)
	s.requestFloor = 0
	s.mailSlots = make(chan struct{}, 1)
	relaySend := &relaySender{delay: 50 * time.Millisecond, sent: make(chan string, 3)}
	s.SetSender(relaySend)
	h := s.Router()
	for i := 1; i <= 3; i++ {
		if w := postRequest(h, fmt.Sprintf("192.0.2.%d:1000", 40+i), fmt.Sprintf("user%d@example.test", i)); w.Code != http.StatusAccepted {
			t.Fatalf("status %d", w.Code)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.WaitMail(ctx)
	if got := len(relaySend.sent); got != 3 {
		t.Errorf("relay received %d mails, want 3", got)
	}
	if n := countAudit(t, db, "mail.send_failed"); n != 0 {
		t.Errorf("mail.send_failed audited %d times, want 0", n)
	}
}
