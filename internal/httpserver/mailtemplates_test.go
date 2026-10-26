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
	"github.com/sched75/sealkeeper/internal/mail"
	"github.com/sched75/sealkeeper/internal/mailtemplates"
)

// recordSender keeps every message it is handed.
type recordSender struct {
	mu   sync.Mutex
	msgs []mail.Message
}

func (r *recordSender) Send(_ context.Context, msg mail.Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, msg)
	return nil
}

func (*recordSender) Name() string { return "smtp" }

func (r *recordSender) last(t *testing.T) mail.Message {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.msgs) == 0 {
		t.Fatal("no mail sent")
	}
	return r.msgs[len(r.msgs)-1]
}

func requestWithLanguage(t *testing.T, s *Server, remote, email, acceptLanguage string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/request", strings.NewReader(`{"email":"`+email+`"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept-Language", acceptLanguage)
	r.RemoteAddr = remote
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status %d", w.Code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.WaitMail(ctx)
}

// Regression: the reveal mail language followed the requester's
// Accept-Language, so whoever submitted the form for someone else chose
// the template the target received. It now follows the instance setting.
func TestRevealMailLanguageIsTheInstanceDefault(t *testing.T) {
	t.Parallel()
	s, _, db := newModeServer(t, config.ModeProduction, false)
	s.requestFloor = 0
	s.SetMailTemplates(mailtemplates.NewRepo(db))
	rec := &recordSender{}
	s.SetSender(rec)

	requestWithLanguage(t, s, "192.0.2.20:1000", "user@example.test", "fr-FR,fr;q=0.9")
	if got := rec.last(t).Subject; got != "Your SealKeeper password proposals" {
		t.Errorf("default instance, French requester: subject %q, want the English default", got)
	}

	s.cfg.MailLanguage = "fr"
	requestWithLanguage(t, s, "192.0.2.21:1000", "other@example.test", "en-US,en;q=0.9")
	if got := rec.last(t).Subject; got != "Vos propositions de mot de passe SealKeeper" {
		t.Errorf("French instance, English requester: subject %q, want the French default", got)
	}
}
