package httpserver

// Aggregated audit of throttled POST /api/v1/request hits (SK-05).
//
// Writing one request.rate_limited row per throttled request let an
// unauthenticated flood grow the immutable, unpurgeable audit chain — and
// every SIEM sink behind it — without limit. Throttled hits are now folded
// per (dimension, subject): the first hit on a key is audited in full as
// before; later hits are only counted in memory and flushed as one
// request.rate_limited.summary row per key and window. A key with no hit
// during a whole window is forgotten, so the next hit is audited in full
// again. The Prometheus counter still counts every hit.
//
// The subject is the limiter key of the refused dimension: the per-IP key
// (IPv6 folded to its /64) for "ip", the folded email for "email". Both key
// spaces only grow with ALLOWED traffic — a key is refused only once it has
// spent its quota — and the table is capped anyway: past rateAuditMaxKeys a
// hit falls into one overflow bucket per dimension.

import (
	"context"
	"sync"
	"time"

	"github.com/sched75/sealkeeper/internal/audit"
)

const (
	// rateAuditWindow is how often the counted hits are flushed as summary
	// rows: at most one row per key per window.
	rateAuditWindow = 5 * time.Minute
	// rateAuditMaxKeys bounds the keys tracked between two flushes.
	rateAuditMaxKeys = 4096
	// rateAuditMaxPeers bounds the distinct counterparts (emails behind an
	// IP, IPs behind an email) counted per key.
	rateAuditMaxPeers = 32
	// rateAuditOverflow is the subject of the per-dimension overflow bucket.
	rateAuditOverflow = "*"
)

type rateAuditKey struct {
	dimension string
	subject   string
}

// rateAuditEntry is the in-memory state of one key since its last flush.
type rateAuditEntry struct {
	actor       string // summary actor: the folded email ("email" dimension)
	ipHash      string // ip_hash of the hit that opened the key
	suppressed  int64  // hits counted, not audited, since the last flush
	firstAt     time.Time
	lastAt      time.Time
	peers       map[string]struct{}
	peersCapped bool
}

// rateAuditHit is one throttled request as the aggregator sees it.
type rateAuditHit struct {
	dimension string
	subject   string
	actor     string
	ipHash    string
	peer      string
}

// rateAuditSummary is one flushed key.
type rateAuditSummary struct {
	key         rateAuditKey
	actor       string
	ipHash      string
	suppressed  int64
	firstAt     time.Time
	lastAt      time.Time
	peers       int
	peersCapped bool
}

// rateAuditAgg folds throttled hits per key. Concurrency-safe.
type rateAuditAgg struct {
	maxKeys  int
	maxPeers int
	now      func() time.Time

	mu      sync.Mutex
	entries map[rateAuditKey]*rateAuditEntry
}

func newRateAuditAgg(maxKeys, maxPeers int) *rateAuditAgg {
	return &rateAuditAgg{
		maxKeys:  maxKeys,
		maxPeers: maxPeers,
		now:      time.Now,
		entries:  make(map[rateAuditKey]*rateAuditEntry),
	}
}

// observe records h. It returns true when h opens its key: the caller then
// audits it in full. Any other hit is only counted.
func (a *rateAuditAgg) observe(h rateAuditHit) bool {
	key := rateAuditKey{dimension: h.dimension, subject: h.subject}
	now := a.now()

	a.mu.Lock()
	defer a.mu.Unlock()
	e, ok := a.entries[key]
	if !ok && len(a.entries) >= a.maxKeys {
		key.subject = rateAuditOverflow
		h.actor = ""
		e, ok = a.entries[key]
	}
	if !ok {
		a.entries[key] = &rateAuditEntry{actor: h.actor, ipHash: h.ipHash, peers: map[string]struct{}{}}
		return true
	}
	e.suppressed++
	if e.firstAt.IsZero() {
		e.firstAt = now
	}
	e.lastAt = now
	a.addPeer(e, h.peer)
	return false
}

func (a *rateAuditAgg) addPeer(e *rateAuditEntry, peer string) {
	if _, seen := e.peers[peer]; seen || peer == "" {
		return
	}
	if len(e.peers) >= a.maxPeers {
		e.peersCapped = true
		return
	}
	e.peers[peer] = struct{}{}
}

// drain returns one summary per key that counted hits since the last
// drain and resets it. Keys that counted none are forgotten.
func (a *rateAuditAgg) drain() []rateAuditSummary {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []rateAuditSummary
	for key, e := range a.entries {
		if e.suppressed == 0 {
			delete(a.entries, key)
			continue
		}
		out = append(out, rateAuditSummary{
			key: key, actor: e.actor, ipHash: e.ipHash, suppressed: e.suppressed,
			firstAt: e.firstAt, lastAt: e.lastAt, peers: len(e.peers), peersCapped: e.peersCapped,
		})
		e.suppressed, e.firstAt, e.lastAt = 0, time.Time{}, time.Time{}
		e.peers, e.peersCapped = map[string]struct{}{}, false
	}
	return out
}

// auditRateLimited audits a throttled request: in full when it opens its
// key, otherwise only counted until the next flushRateAudit.
func (s *Server) auditRateLimited(ctx context.Context, pr publicRequest, dimension string) {
	hit := rateAuditHit{dimension: dimension, ipHash: pr.ipHash}
	if dimension == "ip" {
		hit.subject = rateLimitIPKey(pr.ip)
		hit.peer = s.hashShort(rateLimitKey(pr.email))
	} else {
		hit.subject = rateLimitKey(pr.email)
		hit.actor = hit.subject
		hit.peer = pr.ipHash
	}
	if !s.rateAudit.observe(hit) {
		return
	}
	s.auditAppend(ctx, audit.EventRateLimited, pr.email, dimension, map[string]any{
		"ip_hash":              pr.ipHash,
		"ua_hash":              pr.uaHash,
		"limit_email_per_hour": s.cfg.RateLimitEmailPerHour,
		"limit_ip_per_hour":    s.cfg.RateLimitIPPerHour,
	})
}

// flushRateAudit writes one request.rate_limited.summary row per key that
// counted hits since the previous flush.
func (s *Server) flushRateAudit(ctx context.Context) {
	sums := s.rateAudit.drain()
	for i := range sums {
		sum := &sums[i]
		peersField := "distinct_ip_hashes"
		if sum.key.dimension == "ip" {
			peersField = "distinct_emails"
		}
		details := map[string]any{
			"suppressed":           sum.suppressed,
			"first_at":             sum.firstAt.UTC().Format(time.RFC3339),
			"last_at":              sum.lastAt.UTC().Format(time.RFC3339),
			peersField:             sum.peers,
			peersField + "_capped": sum.peersCapped,
			"overflow":             sum.key.subject == rateAuditOverflow,
			"limit_email_per_hour": s.cfg.RateLimitEmailPerHour,
			"limit_ip_per_hour":    s.cfg.RateLimitIPPerHour,
		}
		if sum.key.dimension == "ip" && sum.key.subject != rateAuditOverflow {
			details["ip_hash"] = sum.ipHash
		}
		s.auditAppend(ctx, audit.EventRateLimitedSummary, sum.actor, sum.key.dimension, details)
	}
}

// startRateAuditFlusher flushes every rateAuditWindow in the background.
// The returned stop waits for the ticker goroutine to exit, then flushes
// what is left with ctx, so no counted hit is lost on shutdown.
func (s *Server) startRateAuditFlusher() (stop func(ctx context.Context)) {
	quit := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(rateAuditWindow)
		defer t.Stop()
		for {
			select {
			case <-quit:
				return
			case <-t.C:
				s.flushRateAudit(context.Background())
			}
		}
	}()
	return func(ctx context.Context) {
		close(quit)
		<-done
		s.flushRateAudit(ctx)
	}
}
