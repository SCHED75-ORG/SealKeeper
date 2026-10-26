package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"testing"

	"github.com/sched75/sealkeeper/internal/config"
	"github.com/sched75/sealkeeper/internal/mail"
)

// bannerSender fails like a relay (or any TCP service the admin pointed the
// relay at) that answers with a chatty multi-line reply.
type bannerSender struct{ err error }

func (b bannerSender) Name() string                             { return "smtp" }
func (b bannerSender) Send(context.Context, mail.Message) error { return b.err }

// Regression: a failed SMTP test echoed err.Error() — the remote server's
// reply text — into the /admin/smtp redirect (rendered in the page) and the
// audit row (shipped to every SIEM sink). Pointing the relay at an internal
// service turned the test button into a banner-grabbing read primitive.
// Only a sanitised status (stage + SMTP code) may leave the server.
func TestSMTPTestFailureShowsSanitisedStatusOnly(t *testing.T) {
	t.Parallel()
	const banner = "relay-07.corp.internal ESMTP Postfix (Debian) build-4.2 secret-banner"
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"rcpt rejected", fmt.Errorf("mailer: RCPT TO: %w",
			&textproto.Error{Code: 550, Msg: "5.7.1 <x@y> relay denied by " + banner}), "rcpt_to (SMTP 550)"},
		{"helo garbage", fmt.Errorf("mailer: HELO: %w",
			textproto.ProtocolError("short response: "+banner)), "helo"},
		{"auth", fmt.Errorf("mailer: AUTH: %w",
			fmt.Errorf("no supported AUTH mechanism (server: %s)", banner)), "auth"},
		{"opaque", fmt.Errorf("%s", banner), "failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s, repo, db := newModeServer(t, config.ModeProduction, false)
			s.SetSender(bannerSender{err: c.err})
			sess := adminSessionFor(t, repo, db)
			w := adminPOST(s.Router(), sess, "/admin/smtp/test", url.Values{"test_to": {"ops@example.test"}})
			loc := w.Header().Get("Location")
			if w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/admin/smtp?err=test_failed") {
				t.Fatalf("POST /admin/smtp/test: %d %q", w.Code, loc)
			}
			u, err := url.Parse(loc)
			if err != nil {
				t.Fatal(err)
			}
			if got := u.Query().Get("details"); got != c.want {
				t.Errorf("details = %q, want %q", got, c.want)
			}
			if strings.Contains(loc, "secret-banner") || strings.Contains(loc, "corp.internal") {
				t.Errorf("redirect reflects the remote reply: %q", loc)
			}
			var details string
			if err := db.QueryRow(`SELECT details_json FROM audit_log WHERE event_type = 'smtp.test_failed'`).
				Scan(&details); err != nil {
				t.Fatalf("audit row: %v", err)
			}
			if strings.Contains(details, "secret-banner") || strings.Contains(details, "corp.internal") {
				t.Errorf("audit details reflect the remote reply: %s", details)
			}
		})
	}
}
