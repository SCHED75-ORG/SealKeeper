// Package ratelimit is an in-memory sliding-window rate limiter used by the
// request-handling pipeline.
//
// PRD: FR-B.11 (3 requests / hour per email, configurable by domain policy),
// FR-B.12 (10 requests / hour per IP, globally configurable), FR-B.13 (the
// rate-limit hit MUST NOT leak through the response — anti-enumeration; the
// audit log is the only observable side-effect).
//
// Single-instance scope. When module D ships the Redis-backed session store
// (D-D.20) we will swap this for a Redis sliding-window implementation —
// the [Limiter] surface is intentionally tiny so the swap is local.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a sliding-window log limiter, keyed by an arbitrary string.
// Concurrency-safe.
type Limiter struct {
	limit  int
	window time.Duration
	now    func() time.Time // injectable for tests

	mu      sync.Mutex
	buckets map[string][]time.Time
}

// New returns a Limiter that allows at most `limit` events per key within the
// rolling `window`. `limit` ≤ 0 turns the limiter into a no-op (always
// allows) — useful for disabling at runtime by setting the configured value
// to 0.
func New(limit int, window time.Duration) *Limiter {
	if window <= 0 {
		window = time.Hour
	}
	return &Limiter{
		limit:   limit,
		window:  window,
		now:     time.Now,
		buckets: make(map[string][]time.Time),
	}
}

// WithClock returns the same Limiter wired with a custom clock. Tests use
// this to fast-forward without sleeping.
func (l *Limiter) WithClock(now func() time.Time) *Limiter {
	l.now = now
	return l
}

// Limit reports the configured cap.
func (l *Limiter) Limit() int { return l.limit }

// Window reports the configured window.
func (l *Limiter) Window() time.Duration { return l.window }

// Allow records an event against `key` and returns true when the key is
// still under cap. When the key is at or above cap, the event is NOT
// recorded and Allow returns false.
//
// A limit of 0 or below is treated as "disabled" — every call returns true.
func (l *Limiter) Allow(key string) bool {
	if l.limit <= 0 {
		return true
	}
	now := l.now()
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	bucket := l.buckets[key]
	// Drop timestamps that fell out of the window. They are stored in
	// chronological order so a simple linear scan from the front works.
	keep := 0
	for keep < len(bucket) && bucket[keep].Before(cutoff) {
		keep++
	}
	if keep > 0 {
		bucket = bucket[keep:]
	}

	if len(bucket) >= l.limit {
		l.buckets[key] = bucket
		return false
	}
	bucket = append(bucket, now)
	l.buckets[key] = bucket
	return true
}

// Inspect returns the current usage for `key` without recording a new event.
// remaining is `max(0, limit - count)`; resetAt is the time at which the
// oldest in-window event will fall out (i.e. when one more slot opens up).
// On an empty bucket resetAt is the zero time.
func (l *Limiter) Inspect(key string) (count, remaining int, resetAt time.Time) {
	now := l.now()
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	bucket := l.buckets[key]
	keep := 0
	for keep < len(bucket) && bucket[keep].Before(cutoff) {
		keep++
	}
	bucket = bucket[keep:]
	l.buckets[key] = bucket

	count = len(bucket)
	remaining = l.limit - count
	if remaining < 0 {
		remaining = 0
	}
	if count > 0 {
		resetAt = bucket[0].Add(l.window)
	}
	return
}

// Sweep drops keys whose buckets are empty. Call this periodically (e.g.
// from a janitor goroutine) to bound memory under high churn. O(n) over the
// total key set; for v0.1 expected key counts (≤ 10k) this is a sub-ms
// operation.
func (l *Limiter) Sweep() int {
	now := l.now()
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	dropped := 0
	for k, bucket := range l.buckets {
		keep := 0
		for keep < len(bucket) && bucket[keep].Before(cutoff) {
			keep++
		}
		bucket = bucket[keep:]
		if len(bucket) == 0 {
			delete(l.buckets, k)
			dropped++
		} else {
			l.buckets[k] = bucket
		}
	}
	return dropped
}

// RunJanitor sweeps every `interval` until ctx is cancelled. Returns a stop
// channel; callers using a context.Context can just cancel.
func (l *Limiter) RunJanitor(stop <-chan struct{}, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			l.Sweep()
		}
	}
}

// Decision is the outcome of a Composite.Check.
type Decision struct {
	Allowed bool
	Reason  string // "email" | "ip" | "" when Allowed
}

// Composite layers two limiters: a per-email cap and a per-IP cap. A request
// that is rejected on either dimension consumes NO slot on the other: when
// the email was charged before the IP check, one IP over its own cap could
// still burn every victim's per-email quota and silently block delivery.
// The IP is tested first so the audit log names the attacker's dimension.
type Composite struct {
	Email *Limiter
	IP    *Limiter
}

// Check peeks at both limiters and records the event in both only when the
// request is allowed.
func (c Composite) Check(email, ip string) Decision {
	ipOn := c.IP != nil && ip != "" && c.IP.Limit() > 0
	emailOn := c.Email != nil && email != "" && c.Email.Limit() > 0
	if ipOn {
		if _, remaining, _ := c.IP.Inspect(ip); remaining == 0 {
			return Decision{Allowed: false, Reason: "ip"}
		}
	}
	if emailOn {
		if _, remaining, _ := c.Email.Inspect(email); remaining == 0 {
			return Decision{Allowed: false, Reason: "email"}
		}
	}
	// A concurrent request may have taken the last slot since the peek.
	if ipOn && !c.IP.Allow(ip) {
		return Decision{Allowed: false, Reason: "ip"}
	}
	if emailOn && !c.Email.Allow(email) {
		return Decision{Allowed: false, Reason: "email"}
	}
	return Decision{Allowed: true}
}
