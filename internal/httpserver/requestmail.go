package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/sched75/sealkeeper/internal/mail"
	"github.com/sched75/sealkeeper/internal/mailer"
)

// FR-B.13 says every outcome of POST /api/v1/request looks the same. The
// body always did; the latency did not: only the allowed path issued a
// token and waited for the SMTP relay, so timing revealed the allowlist
// and the per-level policy coverage. Two measures close that:
//
//   - the reveal mail goes out on a bounded background worker, after the
//     202, so the relay round trip never shows in the response time;
//   - every 202 is held until a fixed floor (plus jitter) since the start
//     of the request, which hides the remaining DB / template work.

const (
	// requestLatencyFloor is the minimum time every 202 takes. It must stay
	// well above the allowed path's own work (token insert, audit insert,
	// template render) on a loaded database.
	requestLatencyFloor = 250 * time.Millisecond
	// requestLatencyJitter is the spread added on top of the floor.
	requestLatencyJitter = 50 * time.Millisecond
	// mailWorkers caps the reveal mails in flight. When all slots are busy
	// the mail is dropped and audited rather than delaying the response.
	mailWorkers = 32
	// mailSendTimeout bounds one background send, detached from the
	// request context (which is cancelled as soon as the 202 is written).
	mailSendTimeout = 60 * time.Second
)

// padRequestLatency sleeps until floor + jitter has elapsed since start,
// or until the client goes away.
func (s *Server) padRequestLatency(ctx context.Context, start time.Time) {
	if s.requestFloor <= 0 {
		return
	}
	wait := s.requestFloor + randomDuration(requestLatencyJitter) - time.Since(start)
	if wait <= 0 {
		return
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

func randomDuration(limit time.Duration) time.Duration {
	if limit <= 0 {
		return 0
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return time.Duration(binary.LittleEndian.Uint64(b[:]) % uint64(limit))
}

// sendRevealMail hands msg to sender on a background worker. The outcome
// is audited (mail.send_failed) since the requester never learns it.
func (s *Server) sendRevealMail(ctx context.Context, sender mailer.Sender, email, ref string, msg mail.Message) {
	select {
	case s.mailSlots <- struct{}{}:
	default:
		s.logger.Error("mail queue full — reveal mail dropped", "transport", sender.Name())
		s.auditAppend(ctx, "mail.send_failed", email, ref, map[string]any{
			"transport": sender.Name(),
			"error":     "mail queue full",
		})
		return
	}
	s.mailWG.Add(1)
	// Detached from the request context on purpose: the 202 is written
	// before the relay answers, and its cancellation must not abort the send.
	// #nosec G118 -- bounded by mailSlots, fire-and-forget by design
	go func() {
		defer s.mailWG.Done()
		defer func() { <-s.mailSlots }()
		ctx, cancel := context.WithTimeout(context.Background(), mailSendTimeout)
		defer cancel()
		if err := sender.Send(ctx, msg); err != nil {
			s.logger.Error("mail send failed", "transport", sender.Name(), "err", err)
			s.auditAppend(ctx, "mail.send_failed", email, ref, map[string]any{
				"transport": sender.Name(),
				"error":     err.Error(),
			})
		}
	}()
}

// WaitMail blocks until every background mail (reveal links and
// post-consultation notices) has been handed to
// the relay (or failed), or ctx ends. Used at shutdown and by tests.
func (s *Server) WaitMail(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		s.mailWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}
