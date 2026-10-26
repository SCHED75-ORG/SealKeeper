package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strings"
)

// sendStages maps the prefixes SMTPSender.Send wraps its errors with to
// the stage names FailureStatus reports. Keep in sync with Send.
var sendStages = []struct{ prefix, stage string }{
	{"mailer: dial ", "dial"},
	{"mailer: HELO: ", "helo"},
	{"mailer: STARTTLS: ", "starttls"},
	{"mailer: AUTH: ", "auth"},
	{"mailer: MAIL FROM: ", "mail_from"},
	{"mailer: RCPT TO: ", "rcpt_to"},
	{"mailer: DATA: ", "data"},
	{"mailer: write body: ", "data"},
	{"mailer: close DATA: ", "data"},
}

// FailureStatus reduces a Send error to a short status that is safe to show
// in the admin UI and to write to the audit log: the SMTP stage that failed
// plus, when known, the numeric reply code, a timeout or a certificate
// rejection. The remote reply text is never included — the relay host is
// admin-chosen, so echoing what it answered would turn the SMTP test into a
// banner-grabbing read primitive against any internal TCP service. The full
// error belongs in the server log only.
func FailureStatus(err error) string {
	if err == nil {
		return ""
	}
	stage := "failed"
	msg := err.Error()
	for _, s := range sendStages {
		if strings.HasPrefix(msg, s.prefix) {
			stage = s.stage
			break
		}
	}
	var tpErr *textproto.Error
	var certErr *tls.CertificateVerificationError
	var netErr net.Error
	switch {
	case errors.As(err, &tpErr):
		return fmt.Sprintf("%s (SMTP %d)", stage, tpErr.Code)
	case errors.As(err, &certErr):
		return stage + " (certificate rejected)"
	case errors.Is(err, context.DeadlineExceeded),
		errors.As(err, &netErr) && netErr.Timeout():
		return stage + " (timeout)"
	}
	return stage
}
