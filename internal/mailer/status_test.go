package mailer_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"testing"

	"github.com/sched75/sealkeeper/internal/mailer"
)

// A relay pointed at a non-SMTP internal service: the raw Send error carries
// what that service answered, FailureStatus must not.
func TestFailureStatusDropsRemoteReply(t *testing.T) {
	t.Parallel()
	const banner = "-ERR redis-internal requirepass hunter2"
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_, _ = fmt.Fprintf(c, "550 %s\r\n", banner)
			_ = c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	var p int
	_, _ = fmt.Sscanf(port, "%d", &p)
	s, err := mailer.NewSMTPSender(mailer.SMTPConfig{Host: "127.0.0.1", Port: p, TLS: mailer.TLSDisable})
	if err != nil {
		t.Fatal(err)
	}
	err = s.Send(context.Background(), sampleMessage(t))
	if err == nil || !strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("precondition: raw error should carry the reply, got %v", err)
	}
	got := mailer.FailureStatus(err)
	if strings.Contains(got, "hunter2") || strings.Contains(got, "redis") {
		t.Fatalf("FailureStatus = %q reflects the remote reply", got)
	}
	if got != "dial (SMTP 550)" {
		t.Fatalf("FailureStatus = %q, want %q", got, "dial (SMTP 550)")
	}
}

func TestFailureStatusShapes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{fmt.Errorf("mailer: MAIL FROM: %w", &textproto.Error{Code: 553, Msg: "x"}), "mail_from (SMTP 553)"},
		{fmt.Errorf("mailer: dial h:25: %w", context.DeadlineExceeded), "dial (timeout)"},
		{fmt.Errorf("mailer: close DATA: %w", errors.New("eof")), "data"},
		{errors.New("something else"), "failed"},
	}
	for _, c := range cases {
		if got := mailer.FailureStatus(c.err); got != c.want {
			t.Errorf("FailureStatus(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}
