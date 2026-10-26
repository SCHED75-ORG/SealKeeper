package httpserver

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/config"
	"github.com/sched75/sealkeeper/internal/ratelimit"
)

// Regression: the per-IP limiters keyed on the full IPv6 /128, so a client
// holding a /64 (the usual end-site allocation) could pick a fresh source
// address per request and never reach SK_RATE_LIMIT_IP_PER_HOUR.
func TestRequestIPLimitCoversIPv6Slash64(t *testing.T) {
	t.Parallel()
	s, _, db := newModeServer(t, config.ModeProduction, false)
	s.requestFloor = 0
	h := s.Router()
	limit := s.cfg.RateLimitIPPerHour
	for i := 1; i <= limit+20; i++ {
		remote := fmt.Sprintf("[2001:db8:1:2::%x]:5555", i)
		if w := postRequest(h, remote, fmt.Sprintf("user%d@example.org", i)); w.Code != http.StatusAccepted {
			t.Fatalf("request %d: status %d", i, w.Code)
		}
	}
	if n := countAudit(t, db, "token.issued"); n != limit {
		t.Fatalf("tokens issued from one IPv6 /64: %d, want %d", n, limit)
	}
	// Another /64 has its own budget.
	if w := postRequest(h, "[2001:db8:1:3::1]:5555", "other@example.org"); w.Code != http.StatusAccepted {
		t.Fatalf("status %d", w.Code)
	}
	if n := countAudit(t, db, "token.issued"); n != limit+1 {
		t.Fatalf("other /64 was throttled: %d tokens, want %d", n, limit+1)
	}
}

func TestAdminLoginRateLimitedPerIPv6Slash64(t *testing.T) {
	t.Parallel()
	s, _ := newAdminServer(t)
	s.loginLimiter = ratelimit.New(2, time.Hour)
	for i := 1; i <= 2; i++ {
		if loc := postLogin(s, fmt.Sprintf("[2001:db8:7:7::%x]:1", i), "nobody@example.test", "x").Header().Get("Location"); strings.Contains(loc, "rate_limited") {
			t.Fatalf("attempt %d rate limited too early", i)
		}
	}
	if loc := postLogin(s, "[2001:db8:7:7:ffff::3]:1", "nobody@example.test", "x").Header().Get("Location"); !strings.Contains(loc, "err=rate_limited") {
		t.Fatalf("3rd attempt from the same /64: Location = %q, want err=rate_limited", loc)
	}
	if loc := postLogin(s, "[2001:db8:7:8::1]:1", "nobody@example.test", "x").Header().Get("Location"); strings.Contains(loc, "rate_limited") {
		t.Fatal("another /64 was rate limited")
	}
}

func TestRateLimitIPKey(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"203.0.113.7":             "203.0.113.7",
		"2001:db8:1:2::5":         "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff:1:2:3": "2001:db8:1:2::/64",
		"::ffff:203.0.113.7":      "203.0.113.7",
		"fe80::1%eth0":            "fe80::/64",
		"not-an-ip":               "not-an-ip",
	} {
		if got := rateLimitIPKey(in); got != want {
			t.Errorf("rateLimitIPKey(%q) = %q, want %q", in, got, want)
		}
	}
}
