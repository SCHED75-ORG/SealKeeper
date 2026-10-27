package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/sched75/sealkeeper/internal/config"
	"github.com/sched75/sealkeeper/internal/cryptobox"
	"github.com/sched75/sealkeeper/internal/mail"
	"github.com/sched75/sealkeeper/internal/mailer"
	"github.com/sched75/sealkeeper/internal/smtpconfig"
)

// envSender stands in for the SK_SMTP_* relay main.go wires at boot.
type envSender struct{}

func (*envSender) Name() string                             { return "env" }
func (*envSender) Send(context.Context, mail.Message) error { return nil }

// Regression: /admin/smtp/clear only blanked the DB row; the relay saved
// before it kept carrying reveal links until the next restart.
func TestSMTPClearSwitchesOffAdminRelay(t *testing.T) {
	t.Parallel()
	env := &envSender{}
	cases := []struct {
		name  string
		mode  config.Mode
		boot  mailer.Sender // what main.go's SetSender installs, if any
		check func(mailer.Sender) bool
		want  string
	}{
		{"production env relay", config.ModeProduction, env,
			func(s mailer.Sender) bool { return s == env }, "env"},
		{"production no relay", config.ModeProduction, nil,
			func(s mailer.Sender) bool { _, ok := s.(mailer.NopSender); return ok }, "noop"},
		{"eval capture", config.ModeEval, nil,
			func(s mailer.Sender) bool { _, ok := s.(*mailer.CaptureSender); return ok }, "capture"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s, repo, db := newModeServer(t, c.mode, false)
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				t.Fatal(err)
			}
			box, err := cryptobox.New(base64.StdEncoding.EncodeToString(key))
			if err != nil {
				t.Fatal(err)
			}
			s.SetSMTPConfig(smtpconfig.NewRepo(db, box))
			if c.boot != nil {
				s.SetSender(c.boot)
			}
			sess := adminSessionFor(t, repo, db)
			h := s.Router()

			w := adminPOST(h, sess, "/admin/smtp/save", url.Values{
				"host":            {"relay.attacker.test"},
				"port":            {"25"},
				"from_addr":       {"noreply@sk.test"},
				"tls_mode":        {"disable"},
				"timeout_seconds": {"1"},
				"password":        {"pw"},
			})
			if loc := w.Header().Get("Location"); loc != "/admin/smtp?ok=saved" {
				t.Fatalf("save: %d %q", w.Code, loc)
			}
			if _, ok := s.currentSender().(*mailer.SMTPSender); !ok {
				t.Fatalf("after save sender = %T, want *mailer.SMTPSender", s.currentSender())
			}

			w = adminPOST(h, sess, "/admin/smtp/clear", url.Values{})
			if loc := w.Header().Get("Location"); loc != "/admin/smtp?ok=cleared" {
				t.Fatalf("clear: %d %q", w.Code, loc)
			}
			if got := s.currentSender(); !c.check(got) {
				t.Fatalf("after clear sender = %T (%s), want %s", got, got.Name(), c.want)
			}
			d := lastAuditDetails(t, db, "smtp.cleared")
			if d["transport"] != c.want {
				t.Errorf("smtp.cleared transport = %v, want %s", d["transport"], c.want)
			}
		})
	}
}
