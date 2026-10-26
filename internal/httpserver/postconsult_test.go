package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/config"
	"github.com/sched75/sealkeeper/internal/domains"
	"github.com/sched75/sealkeeper/internal/elevations"
	"github.com/sched75/sealkeeper/internal/mail"
	"github.com/sched75/sealkeeper/internal/mailtemplates"
	"github.com/sched75/sealkeeper/internal/policies"
	"github.com/sched75/sealkeeper/internal/tokens"
)

// bodySender emulates a slow relay and keeps every message it accepted.
type bodySender struct {
	delay time.Duration
	mu    sync.Mutex
	msgs  []mail.Message
}

func (b *bodySender) Send(ctx context.Context, msg mail.Message) error {
	select {
	case <-time.After(b.delay):
	case <-ctx.Done():
		return ctx.Err()
	}
	b.mu.Lock()
	b.msgs = append(b.msgs, msg)
	b.mu.Unlock()
	return nil
}

func (*bodySender) Name() string { return "smtp" }

func (b *bodySender) sent() []mail.Message {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]mail.Message(nil), b.msgs...)
}

// consultFixture wires a policy with NotifyOnConsult and returns a fresh
// reveal token for it.
func consultFixture(t *testing.T, sender *bodySender) (*Server, string) {
	t.Helper()
	s, _, db := newModeServer(t, config.ModeProduction, false)
	ctx := context.Background()
	dr := domains.NewRepo(db)
	er := elevations.NewRepo(db)
	pr := policies.NewRepo(db, dr, er)
	tr := tokens.NewRepo(db)
	s.SetTokens(tr)
	s.SetDomains(dr)
	s.SetPolicies(pr, er)
	s.SetMailTemplates(mailtemplates.NewRepo(db))
	s.SetSender(sender)
	d, err := dr.Create(ctx, "example.test", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pr.Create(ctx, policies.CreateInputs{
		DomainID: d.ID, ANSSILevel: elevations.LevelB1, Name: "B1", Generator: policies.GeneratorG3,
		NotifyOnConsult: true, Active: true,
	}, nil); err != nil {
		t.Fatal(err)
	}
	tok, err := tr.Issue(ctx, tokens.IssueOptions{Email: "user@example.test", Domain: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	return s, tok.Token
}

// Regression: the post-consultation mail ran on a detached goroutine that
// Shutdown (WaitMail) never waited for, so a SIGTERM right after a
// consultation silently dropped the notification.
func TestPostConsultMailIsAwaitedAtShutdown(t *testing.T) {
	t.Parallel()
	sender := &bodySender{delay: 300 * time.Millisecond}
	s, token := consultFixture(t, sender)

	w := httptest.NewRecorder()
	s.handlePolicyConsume(w, consumeRequest(token))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.WaitMail(ctx)
	if got := len(sender.sent()); got != 1 {
		t.Fatalf("WaitMail returned with %d post-consultation mails sent, want 1", got)
	}
}

// Regression: the notification showed a truncated keyed hash of the IP and
// User-Agent, which the recipient cannot compare with anything. FR-B.40
// asks for the IP and the user agent themselves.
func TestPostConsultMailShowsIPAndUserAgent(t *testing.T) {
	t.Parallel()
	sender := &bodySender{}
	s, token := consultFixture(t, sender)

	r := consumeRequest(token)
	r.RemoteAddr = "192.0.2.50:4242"
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) TestBrowser/1.0\x7f"+strings.Repeat("A", 1000))
	r.Header.Set("Accept-Language", "en")
	w := httptest.NewRecorder()
	s.handlePolicyConsume(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.WaitMail(ctx)
	msgs := sender.sent()
	if len(msgs) != 1 {
		t.Fatalf("%d mails sent, want 1", len(msgs))
	}
	body := msgs[0].Body
	for _, want := range []string{"192.0.2.50", "TestBrowser/1.0"} {
		if !strings.Contains(body, want) {
			t.Errorf("notification lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "\x7f") {
		t.Error("control character from the User-Agent reached the mail")
	}
	if strings.Contains(body, strings.Repeat("A", 300)) {
		t.Error("User-Agent was not truncated")
	}
}

// consumeRequest builds the POST /api/v1/policy request the reveal page sends.
func consumeRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/policy", strings.NewReader(`{"token":"`+token+`"}`))
	r.Header.Set("Content-Type", "application/json")
	return r
}
