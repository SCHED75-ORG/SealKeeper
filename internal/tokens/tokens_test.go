package tokens_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
	"github.com/sched75/sealkeeper/internal/tokens"
)

// newRepo returns a clock-controllable Repo bound to a fresh on-disk SQLite
// migrated to the latest schema.
func newRepo(t *testing.T, now func() time.Time) (*tokens.Repo, storage.Store) {
	t.Helper()
	dsn := storagetest.DSN(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s, err := storage.Open(ctx, storage.Options{DSN: dsn})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	repo := tokens.NewRepo(s.DB())
	if now != nil {
		repo = repo.WithClock(now)
	}
	return repo, s
}

func TestIssueAssignsTokenAndExpiry(t *testing.T) {
	t.Parallel()
	repo, _ := newRepo(t, nil)

	tok, err := repo.Issue(context.Background(), tokens.IssueOptions{
		Email: "Alice@Example.COM",
		TTL:   time.Minute,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(tok.Token) < 32 {
		t.Errorf("token too short: %q", tok.Token)
	}
	if tok.Email != "alice@example.com" {
		t.Errorf("Email = %q, want lowercased", tok.Email)
	}
	if tok.Domain != "example.com" {
		t.Errorf("Domain = %q, want derived from email", tok.Domain)
	}
	if d := tok.ExpiresAt.Sub(tok.IssuedAt); d < 55*time.Second || d > 65*time.Second {
		t.Errorf("expiry window %v, want ~1m", d)
	}
}

func TestIssueRejectsEmptyEmail(t *testing.T) {
	t.Parallel()
	repo, _ := newRepo(t, nil)
	_, err := repo.Issue(context.Background(), tokens.IssueOptions{})
	if err == nil {
		t.Fatal("expected error for empty email")
	}
}

func TestConsumeHappyPath(t *testing.T) {
	t.Parallel()
	repo, _ := newRepo(t, nil)

	tok, err := repo.Issue(context.Background(), tokens.IssueOptions{Email: "bob@example.com"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := repo.Consume(context.Background(), tok.Token, "", "")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.Email != "bob@example.com" {
		t.Errorf("Email = %q", got.Email)
	}
	if got.ConsumedAt == nil {
		t.Error("ConsumedAt should be set")
	}
}

func TestConsumeAlreadyConsumed(t *testing.T) {
	t.Parallel()
	repo, _ := newRepo(t, nil)

	tok, err := repo.Issue(context.Background(), tokens.IssueOptions{Email: "carol@example.com"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := repo.Consume(context.Background(), tok.Token, "", ""); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if _, err := repo.Consume(context.Background(), tok.Token, "", ""); !errors.Is(err, tokens.ErrConsumed) {
		t.Fatalf("second Consume err = %v, want ErrConsumed", err)
	}
}

func TestConsumeExpired(t *testing.T) {
	t.Parallel()
	// Issue at t0, then advance the clock past expiry.
	var nowVal atomic.Value
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	nowVal.Store(t0)
	clock := func() time.Time { return nowVal.Load().(time.Time) }

	repo, _ := newRepo(t, clock)
	tok, err := repo.Issue(context.Background(), tokens.IssueOptions{
		Email: "eve@example.com",
		TTL:   time.Minute,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	nowVal.Store(t0.Add(2 * time.Minute))
	if _, err := repo.Consume(context.Background(), tok.Token, "", ""); !errors.Is(err, tokens.ErrExpired) {
		t.Fatalf("Consume err = %v, want ErrExpired", err)
	}
}

func TestConsumeUnknown(t *testing.T) {
	t.Parallel()
	repo, _ := newRepo(t, nil)
	_, err := repo.Consume(context.Background(), "no-such-token", "", "")
	if !errors.Is(err, tokens.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestConsumeRaceCondition(t *testing.T) {
	t.Parallel()
	repo, _ := newRepo(t, nil)

	tok, err := repo.Issue(context.Background(), tokens.IssueOptions{Email: "race@example.com"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	const concurrent = 8
	var wg sync.WaitGroup
	results := make([]error, concurrent)
	wg.Add(concurrent)
	for i := 0; i < concurrent; i++ {
		go func(i int) {
			defer wg.Done()
			_, results[i] = repo.Consume(context.Background(), tok.Token, "", "")
		}(i)
	}
	wg.Wait()

	successes := 0
	consumedErrs := 0
	for _, err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, tokens.ErrConsumed):
			consumedErrs++
		default:
			t.Errorf("unexpected err: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("got %d successful consumes, want exactly 1", successes)
	}
	if consumedErrs+successes != concurrent {
		t.Fatalf("expected %d total, got %d successes + %d ErrConsumed", concurrent, successes, consumedErrs)
	}
}

func TestGetReturnsRow(t *testing.T) {
	t.Parallel()
	repo, _ := newRepo(t, nil)
	tok, err := repo.Issue(context.Background(), tokens.IssueOptions{Email: "x@example.com"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := repo.Get(context.Background(), tok.Token)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Token != tok.Token {
		t.Errorf("Get returned different token: %q vs %q", got.Token, tok.Token)
	}
	if got.ConsumedAt != nil {
		t.Errorf("ConsumedAt should be nil for fresh token")
	}
}
