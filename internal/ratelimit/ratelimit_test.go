package ratelimit_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/ratelimit"
)

func TestAllowUnderLimit(t *testing.T) {
	t.Parallel()
	l := ratelimit.New(3, time.Hour)
	for i := 0; i < 3; i++ {
		if !l.Allow("alice") {
			t.Fatalf("call %d should be allowed", i)
		}
	}
	if l.Allow("alice") {
		t.Fatal("4th call should be denied")
	}
}

func TestAllowSeparateKeysDoNotInterfere(t *testing.T) {
	t.Parallel()
	l := ratelimit.New(1, time.Hour)
	if !l.Allow("alice") {
		t.Fatal("alice first ok")
	}
	if l.Allow("alice") {
		t.Fatal("alice second should be denied")
	}
	if !l.Allow("bob") {
		t.Fatal("bob first ok — independent bucket")
	}
}

func TestDisabledLimiterAlwaysAllows(t *testing.T) {
	t.Parallel()
	l := ratelimit.New(0, time.Hour)
	for i := 0; i < 100; i++ {
		if !l.Allow("anyone") {
			t.Fatal("disabled limiter should always allow")
		}
	}
}

func TestWindowSlides(t *testing.T) {
	t.Parallel()
	var nowVal atomic.Value
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	nowVal.Store(t0)
	l := ratelimit.New(2, time.Minute).WithClock(func() time.Time { return nowVal.Load().(time.Time) })

	// Two distinct Allow calls (linter-friendly) — both mutate the bucket
	// state, so we cannot fold them into a single short-circuited
	// expression.
	for i := 0; i < 2; i++ {
		if !l.Allow("k") {
			t.Fatalf("call %d within window should pass", i)
		}
	}
	if l.Allow("k") {
		t.Fatal("third within same window should be denied")
	}
	// Slide past the window.
	nowVal.Store(t0.Add(61 * time.Second))
	if !l.Allow("k") {
		t.Fatal("after window slides, new call should pass")
	}
}

func TestInspectReportsState(t *testing.T) {
	t.Parallel()
	var nowVal atomic.Value
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	nowVal.Store(t0)
	l := ratelimit.New(3, time.Hour).WithClock(func() time.Time { return nowVal.Load().(time.Time) })

	count, remaining, reset := l.Inspect("eve")
	if count != 0 || remaining != 3 || !reset.IsZero() {
		t.Fatalf("empty Inspect = (%d, %d, %v)", count, remaining, reset)
	}
	l.Allow("eve")
	count, remaining, reset = l.Inspect("eve")
	if count != 1 || remaining != 2 {
		t.Errorf("post-Allow Inspect = (%d, %d), want (1, 2)", count, remaining)
	}
	if !reset.Equal(t0.Add(time.Hour)) {
		t.Errorf("reset = %v, want %v", reset, t0.Add(time.Hour))
	}
}

func TestSweepDropsExpiredBuckets(t *testing.T) {
	t.Parallel()
	var nowVal atomic.Value
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	nowVal.Store(t0)
	l := ratelimit.New(5, time.Minute).WithClock(func() time.Time { return nowVal.Load().(time.Time) })

	for _, k := range []string{"a", "b", "c"} {
		l.Allow(k)
	}
	nowVal.Store(t0.Add(2 * time.Minute))
	dropped := l.Sweep()
	if dropped != 3 {
		t.Fatalf("dropped = %d, want 3", dropped)
	}
	// Sweeping again is a no-op.
	if again := l.Sweep(); again != 0 {
		t.Errorf("second sweep dropped %d, want 0", again)
	}
}

func TestConcurrentAllowExactlyHonoursLimit(t *testing.T) {
	t.Parallel()
	const limit = 100
	l := ratelimit.New(limit, time.Hour)

	const goroutines = 500
	var ok int64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if l.Allow("shared") {
				atomic.AddInt64(&ok, 1)
			}
		}()
	}
	wg.Wait()
	if int(ok) != limit {
		t.Fatalf("Allow under contention granted %d, want exactly %d", ok, limit)
	}
}

func TestCompositeChecksBoth(t *testing.T) {
	t.Parallel()
	c := ratelimit.Composite{
		Email: ratelimit.New(2, time.Hour),
		IP:    ratelimit.New(3, time.Hour),
	}
	// Drain the email bucket — IP bucket should remain untouched.
	for i := 0; i < 2; i++ {
		if d := c.Check("user@example.test", "1.2.3.4"); !d.Allowed {
			t.Fatalf("Check %d denied unexpectedly", i)
		}
	}
	d := c.Check("user@example.test", "1.2.3.4")
	if d.Allowed || d.Reason != "email" {
		t.Fatalf("expected denied with reason=email, got %+v", d)
	}

	// Same IP, different email → IP bucket still has 1 slot used (the 2
	// initial allows charged 2 IP slots). One more should pass.
	if d := c.Check("other@example.test", "1.2.3.4"); !d.Allowed {
		t.Fatalf("3rd IP slot should be open, got %+v", d)
	}
	// 4th IP charge should hit the IP cap.
	if d := c.Check("third@example.test", "1.2.3.4"); d.Allowed || d.Reason != "ip" {
		t.Fatalf("expected denied with reason=ip, got %+v", d)
	}
}

func TestCompositeWithNilLimitersAlwaysAllows(t *testing.T) {
	t.Parallel()
	c := ratelimit.Composite{}
	for i := 0; i < 10; i++ {
		if d := c.Check("a", "b"); !d.Allowed {
			t.Fatalf("nil composite must allow, got %+v", d)
		}
	}
}

// Regression: Check charged the email bucket before testing the IP, so an
// IP that was already over its cap still burned every victim's per-email
// quota and blocked their real requests for the window.
func TestCompositeIPRejectionDoesNotChargeEmail(t *testing.T) {
	t.Parallel()
	c := ratelimit.Composite{
		Email: ratelimit.New(3, time.Hour),
		IP:    ratelimit.New(1, time.Hour),
	}
	if d := c.Check("seed@example.test", "6.6.6.6"); !d.Allowed {
		t.Fatalf("first request denied: %+v", d)
	}
	for i := 0; i < 10; i++ {
		if d := c.Check("victim@example.test", "6.6.6.6"); d.Allowed || d.Reason != "ip" {
			t.Fatalf("attacker request %d: %+v, want denied by ip", i, d)
		}
	}
	if count, _, _ := c.Email.Inspect("victim@example.test"); count != 0 {
		t.Fatalf("victim email bucket charged %d times by IP-rejected requests", count)
	}
	if d := c.Check("victim@example.test", "10.0.0.1"); !d.Allowed {
		t.Fatalf("victim's own request denied: %+v", d)
	}
}
