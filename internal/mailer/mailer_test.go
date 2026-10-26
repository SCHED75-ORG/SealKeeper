package mailer_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/mail"
	"github.com/sched75/sealkeeper/internal/mailcapture"
	"github.com/sched75/sealkeeper/internal/mailer"
)

// fakeSMTP is a tiny in-process SMTP server good enough for unit tests. It
// understands HELO/EHLO, optional AUTH PLAIN/LOGIN, MAIL FROM, RCPT TO,
// DATA + . terminator, and QUIT. Captures the recorded exchanges into the
// struct so test assertions stay simple.
type fakeSMTP struct {
	listener net.Listener
	supports map[string]bool // capability map advertised in EHLO

	mu        sync.Mutex
	received  []recordedMail
	authCreds []string // base64 'username\0username\0password' fragments seen
}

type recordedMail struct {
	From    string
	To      []string
	Data    string
	Helo    string
	UsedTLS bool
}

func newFakeSMTP(t *testing.T, caps ...string) *fakeSMTP {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	supports := map[string]bool{}
	for _, c := range caps {
		supports[strings.ToUpper(c)] = true
	}
	f := &fakeSMTP{listener: l, supports: supports}
	t.Cleanup(func() { _ = l.Close() })
	go f.acceptLoop()
	return f
}

func (f *fakeSMTP) Addr() string { return f.listener.Addr().String() }

func (f *fakeSMTP) Received() []recordedMail {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]recordedMail, len(f.received))
	copy(out, f.received)
	return out
}

func (f *fakeSMTP) acceptLoop() {
	for {
		c, err := f.listener.Accept()
		if err != nil {
			return
		}
		go f.handle(c)
	}
}

func (f *fakeSMTP) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	rw := bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
	write := func(s string) {
		_, _ = rw.WriteString(s + "\r\n")
		_ = rw.Flush()
	}

	write("220 fake.smtp.test ESMTP ready")

	var (
		current recordedMail
	)
	for {
		line, err := rw.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		head := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(head, "EHLO"), strings.HasPrefix(head, "HELO"):
			current.Helo = strings.TrimSpace(line[4:])
			write("250-fake.smtp.test")
			if f.supports["STARTTLS"] {
				write("250-STARTTLS")
			}
			if f.supports["AUTH"] {
				write("250-AUTH PLAIN LOGIN")
			}
			write("250 SIZE 10240000")
		case strings.HasPrefix(head, "AUTH PLAIN"):
			parts := strings.SplitN(line, " ", 3)
			if len(parts) == 3 {
				f.mu.Lock()
				f.authCreds = append(f.authCreds, parts[2])
				f.mu.Unlock()
			}
			write("235 2.7.0 Authentication successful")
		case strings.HasPrefix(head, "AUTH LOGIN"):
			write("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
			_, _ = rw.ReadString('\n') // username
			write("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
			_, _ = rw.ReadString('\n') // password
			write("235 2.7.0 Authentication successful")
		case strings.HasPrefix(head, "MAIL FROM:"):
			current.From = extractAngleAddr(line)
			write("250 OK")
		case strings.HasPrefix(head, "RCPT TO:"):
			current.To = append(current.To, extractAngleAddr(line))
			write("250 OK")
		case head == "DATA":
			write("354 End data with <CR><LF>.<CR><LF>")
			var data strings.Builder
			for {
				dl, err := rw.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(dl, "\r\n") == "." {
					break
				}
				data.WriteString(dl)
			}
			current.Data = data.String()
			f.mu.Lock()
			f.received = append(f.received, current)
			f.mu.Unlock()
			current = recordedMail{}
			write("250 2.0.0 Ok: queued as fake")
		case head == "RSET":
			current = recordedMail{}
			write("250 OK")
		case head == "QUIT":
			write("221 Bye")
			return
		case head == "NOOP":
			write("250 OK")
		default:
			write("502 Command not implemented")
		}
	}
}

func extractAngleAddr(line string) string {
	if i := strings.Index(line, "<"); i >= 0 {
		if j := strings.Index(line[i:], ">"); j > 0 {
			return line[i+1 : i+j]
		}
	}
	return ""
}

// dialerFor builds an SMTPDialer that connects to the fixture's address
// regardless of what `addr` the sender wants to dial — that way we don't
// have to teach the sender about ephemeral ports.
func dialerFor(t *testing.T, f *fakeSMTP) mailer.SMTPDialer {
	t.Helper()
	return func(ctx context.Context, _ string) (*smtp.Client, error) {
		d := &net.Dialer{Timeout: 5 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", f.Addr())
		if err != nil {
			return nil, err
		}
		host, _, _ := net.SplitHostPort(f.Addr())
		return smtp.NewClient(conn, host)
	}
}

func sampleMessage(t *testing.T) mail.Message {
	t.Helper()
	msg, err := mail.BuildReveal(mail.RevealInputs{
		To:              "alice@example.test",
		InstanceDomain:  "sealkeeper.test",
		RevealURL:       "https://sealkeeper.test/reveal/abc",
		ValidityMinutes: 15,
	})
	if err != nil {
		t.Fatalf("BuildReveal: %v", err)
	}
	return msg
}

// ----- NopSender / CaptureSender -------------------------------------------

func TestNopSenderName(t *testing.T) {
	t.Parallel()
	var s mailer.Sender = mailer.NopSender{}
	if s.Name() != "noop" {
		t.Errorf("Name = %q, want noop", s.Name())
	}
	if err := s.Send(context.Background(), mail.Message{}); err != nil {
		t.Errorf("Send: %v", err)
	}
}

func TestCaptureSenderStoresMessage(t *testing.T) {
	t.Parallel()
	store := mailcapture.NewStore(10)
	got := ""
	s := &mailer.CaptureSender{
		Store:             store,
		CaptureIDCallback: func(id string) { got = id },
	}
	if s.Name() != "capture" {
		t.Errorf("Name = %q", s.Name())
	}
	msg := sampleMessage(t)
	if err := s.Send(context.Background(), msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got == "" {
		t.Fatal("capture id callback never fired")
	}
	items := store.Snapshot()
	if len(items) != 1 {
		t.Fatalf("snapshot length = %d, want 1", len(items))
	}
	if items[0].To != msg.To || items[0].Subject != msg.Subject {
		t.Errorf("captured fields wrong: %+v", items[0])
	}
}

func TestCaptureSenderNilStore(t *testing.T) {
	t.Parallel()
	s := &mailer.CaptureSender{}
	if err := s.Send(context.Background(), mail.Message{}); err == nil {
		t.Error("expected error on nil store")
	}
}

// ----- SMTPSender happy path -----------------------------------------------

func TestSMTPSenderPlainSend(t *testing.T) {
	t.Parallel()
	f := newFakeSMTP(t)

	s, err := mailer.NewSMTPSender(mailer.SMTPConfig{
		Host: "127.0.0.1",
		Port: 25,
		TLS:  mailer.TLSDisable,
	})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	s = s.WithDialer(dialerFor(t, f))

	msg := sampleMessage(t)
	if err := s.Send(context.Background(), msg); err != nil {
		t.Fatalf("Send: %v", err)
	}

	recv := f.Received()
	if len(recv) != 1 {
		t.Fatalf("got %d messages, want 1", len(recv))
	}
	if recv[0].From != "noreply@sealkeeper.test" {
		t.Errorf("envelope FROM = %q", recv[0].From)
	}
	if len(recv[0].To) != 1 || recv[0].To[0] != "alice@example.test" {
		t.Errorf("envelope TO = %v", recv[0].To)
	}
	if !strings.Contains(recv[0].Data, "Subject: Vos propositions") {
		t.Errorf("DATA missing subject header: %.200s", recv[0].Data)
	}
	if !strings.Contains(recv[0].Data, "https://sealkeeper.test/reveal/abc") {
		t.Errorf("DATA missing reveal URL")
	}
}

func TestSMTPSenderAuthPlain(t *testing.T) {
	t.Parallel()
	f := newFakeSMTP(t, "AUTH", "STARTTLS")

	s, err := mailer.NewSMTPSender(mailer.SMTPConfig{
		Host:     "127.0.0.1",
		Port:     25,
		Username: "user",
		Password: "pass",
		TLS:      mailer.TLSDisable, // skip STARTTLS so the fixture stays plaintext
	})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	s = s.WithDialer(dialerFor(t, f))

	if err := s.Send(context.Background(), sampleMessage(t)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(f.authCreds) != 1 {
		t.Fatalf("got %d AUTH PLAIN attempts, want 1", len(f.authCreds))
	}
}

func TestSMTPSenderEnvelopeFromOverride(t *testing.T) {
	t.Parallel()
	f := newFakeSMTP(t)
	s, _ := mailer.NewSMTPSender(mailer.SMTPConfig{
		Host:        "127.0.0.1",
		Port:        25,
		TLS:         mailer.TLSDisable,
		FromAddress: "bounces@delivery.sealkeeper.test",
	})
	s = s.WithDialer(dialerFor(t, f))

	if err := s.Send(context.Background(), sampleMessage(t)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	recv := f.Received()
	if recv[0].From != "bounces@delivery.sealkeeper.test" {
		t.Errorf("envelope FROM not overridden: %q", recv[0].From)
	}
}

func TestSMTPSenderRequiresHost(t *testing.T) {
	t.Parallel()
	if _, err := mailer.NewSMTPSender(mailer.SMTPConfig{}); err == nil {
		t.Fatal("expected error for empty host")
	}
}

func TestSMTPSenderRejectsEmptyRecipient(t *testing.T) {
	t.Parallel()
	f := newFakeSMTP(t)
	s, _ := mailer.NewSMTPSender(mailer.SMTPConfig{
		Host: "127.0.0.1",
		Port: 25,
		TLS:  mailer.TLSDisable,
	})
	s = s.WithDialer(dialerFor(t, f))
	err := s.Send(context.Background(), mail.Message{From: "x@y", Subject: "s", Body: "b"})
	if err == nil {
		t.Fatal("expected error for empty To")
	}
}

func TestSMTPSenderContextCancellation(t *testing.T) {
	t.Parallel()
	// Dialer that hangs forever — must respect context cancellation.
	hanging := func(ctx context.Context, _ string) (*smtp.Client, error) {
		<-ctx.Done()
		return nil, errors.New("dialer cancelled: " + ctx.Err().Error())
	}
	s, _ := mailer.NewSMTPSender(mailer.SMTPConfig{
		Host:    "127.0.0.1",
		Port:    25,
		TLS:     mailer.TLSDisable,
		Timeout: 100 * time.Millisecond,
	})
	s = s.WithDialer(hanging)

	start := time.Now()
	err := s.Send(context.Background(), sampleMessage(t))
	if err == nil {
		t.Fatal("expected error from hanging dialer")
	}
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("timeout took %v — context not honoured", elapsed)
	}
}

// Sanity check on the helper.
func TestExtractAngleAddr(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"MAIL FROM:<a@b.test>":    "a@b.test",
		"RCPT TO:<x@y.test> SIZE": "x@y.test",
		"NO ANGLES":               "",
	}
	for in, want := range cases {
		if got := extractAngleAddr(in); got != want {
			t.Errorf("extractAngleAddr(%q) = %q, want %q", in, got, want)
		}
	}
	_ = fmt.Sprintf // keep fmt referenced
}

// Regression: in "auto" mode an on-path attacker could strip STARTTLS from
// the EHLO reply and the sender carried on in plaintext, handing the relay
// credentials (via the custom LOGIN auth) and every reveal link to the
// attacker.
func TestSMTPSenderAutoRefusesPlaintextToRemoteRelay(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		username string
	}{
		{name: "with credentials", username: "svc-relay"},
		{name: "without credentials"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeSMTP(t, "AUTH") // no STARTTLS: stripped by the attacker
			s, err := mailer.NewSMTPSender(mailer.SMTPConfig{
				Host:     "relay.example.test",
				Username: c.username,
				Password: "relay-secret",
				TLS:      mailer.TLSAuto,
			})
			if err != nil {
				t.Fatalf("NewSMTPSender: %v", err)
			}
			s = s.WithDialer(dialerFor(t, f))
			if err := s.Send(context.Background(), sampleMessage(t)); err == nil {
				t.Fatal("Send succeeded over plaintext to a remote relay in auto mode")
			}
			if len(f.authCreds) != 0 {
				t.Errorf("credentials sent in clear: %v", f.authCreds)
			}
			if len(f.Received()) != 0 {
				t.Error("message delivered in clear")
			}
		})
	}
}

func TestSMTPSenderNeverAuthenticatesInClearToRemoteRelay(t *testing.T) {
	t.Parallel()
	f := newFakeSMTP(t, "AUTH")
	s, err := mailer.NewSMTPSender(mailer.SMTPConfig{
		Host:     "relay.example.test",
		Username: "svc-relay",
		Password: "relay-secret",
		TLS:      mailer.TLSDisable, // explicit plaintext still must not leak creds
	})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	s = s.WithDialer(dialerFor(t, f))
	if err := s.Send(context.Background(), sampleMessage(t)); err == nil {
		t.Fatal("Send authenticated over plaintext to a remote relay")
	}
	if len(f.authCreds) != 0 {
		t.Errorf("credentials sent in clear: %v", f.authCreds)
	}
}

func TestSMTPSenderAutoAllowsPlaintextLoopbackRelay(t *testing.T) {
	t.Parallel()
	f := newFakeSMTP(t)
	s, err := mailer.NewSMTPSender(mailer.SMTPConfig{Host: "127.0.0.1", TLS: mailer.TLSAuto})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	s = s.WithDialer(dialerFor(t, f))
	if err := s.Send(context.Background(), sampleMessage(t)); err != nil {
		t.Fatalf("Send to loopback relay: %v", err)
	}
}
