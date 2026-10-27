// Package mailer is the seam between the request pipeline and whichever
// transport actually puts a mail on the wire (SMTP, eval-mode capture queue,
// or a no-op in tests).
//
// PRD: FR-B.14..19 specify the message shape; module D §3.6 specifies the
// SMTP envelope. internal/mail builds the Message; this package gets it to
// its destination.
package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	stdmail "net/mail"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/sched75/sealkeeper/internal/mail"
	"github.com/sched75/sealkeeper/internal/mailcapture"
)

// Sender is the only interface the request handler talks to. Implementations
// are concrete senders (SMTP, capture queue, no-op).
type Sender interface {
	// Send delivers msg or returns an error. The implementation MUST honour
	// the deadline carried by ctx.
	Send(ctx context.Context, msg mail.Message) error
	// Name is used in logs and audit entries; e.g. "smtp", "capture", "noop".
	Name() string
}

// NopSender discards everything. Useful for tests or for shipping a build
// where SMTP is intentionally disabled.
type NopSender struct{}

func (NopSender) Send(context.Context, mail.Message) error { return nil }
func (NopSender) Name() string                             { return "noop" }

// CaptureSender writes into the in-memory mailcapture store that backs the
// /__captured_mail eval-mode endpoint (FR-B.17). The Sender returns the
// capture id via the optional CaptureIDCallback if set.
type CaptureSender struct {
	Store             *mailcapture.Store
	CaptureIDCallback func(id string)
}

// Send stores the full RFC 822 body so the captured queue is a faithful
// mirror of what a real SMTP relay would have received.
func (c *CaptureSender) Send(_ context.Context, msg mail.Message) error {
	if c == nil || c.Store == nil {
		return errors.New("mailer.CaptureSender: nil store")
	}
	id := c.Store.Capture(msg.To, msg.Subject, msg.String())
	if c.CaptureIDCallback != nil {
		c.CaptureIDCallback(id)
	}
	return nil
}

func (*CaptureSender) Name() string { return "capture" }

// TLSMode controls the TLS behaviour of [SMTPSender].
type TLSMode string

const (
	// TLSAuto upgrades with STARTTLS. It falls back to plaintext only for a
	// loopback relay (a local MTA sidecar); for any other host a server that
	// does not advertise STARTTLS is refused, because an on-path attacker can
	// strip the capability and read the relay credentials and reveal links.
	TLSAuto TLSMode = "auto"
	// TLSStartTLS requires the server to support STARTTLS; the sender aborts
	// when the advertised capabilities do not include it.
	TLSStartTLS TLSMode = "starttls"
	// TLSImplicit opens a TLS connection at TCP layer (port 465 style).
	TLSImplicit TLSMode = "implicit"
	// TLSDisable forces plaintext. Use only against a relay on a private
	// network you trust.
	TLSDisable TLSMode = "disable"
)

// SMTPConfig configures the SMTP sender.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	// FromAddress overrides the envelope FROM. When empty the address parsed
	// from the message's From: header is used.
	FromAddress string
	TLS         TLSMode
	// Timeout caps the entire SMTP transaction (dial → auth → DATA → quit).
	Timeout time.Duration
	// InsecureSkipVerify disables certificate validation. Off by default;
	// intentionally exposed so on-prem relays with private CAs are usable.
	InsecureSkipVerify bool
	// ServerName overrides the TLS SNI/verification hostname. Defaults to Host.
	ServerName string
}

// SMTPSender talks to a real relay.
type SMTPSender struct {
	cfg    SMTPConfig
	dialer SMTPDialer // injectable for tests
}

// SMTPDialer is the dial primitive — extracted so tests can hand in a fake.
// A dialer must keep ctx in force on the returned client's connection for the
// whole transaction (see bindConnToContext), since net/smtp ignores contexts.
type SMTPDialer func(ctx context.Context, addr string) (*smtp.Client, error)

// NewSMTPSender returns a Sender for the configured relay.
func NewSMTPSender(cfg SMTPConfig) (*SMTPSender, error) {
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, errors.New("mailer.NewSMTPSender: empty host")
	}
	if cfg.Port == 0 {
		switch cfg.TLS {
		case TLSImplicit:
			cfg.Port = 465
		default:
			cfg.Port = 587
		}
	}
	switch cfg.TLS {
	case "":
		cfg.TLS = TLSAuto
	case TLSAuto, TLSStartTLS, TLSImplicit, TLSDisable:
	default:
		// Refuse here rather than fail every Send with "unknown TLS mode".
		return nil, fmt.Errorf("mailer.NewSMTPSender: unknown TLS mode %q", cfg.TLS)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.ServerName == "" {
		cfg.ServerName = cfg.Host
	}

	var dialer SMTPDialer = defaultDial
	if cfg.TLS == TLSImplicit {
		dialer = defaultTLSDial(cfg.ServerName, cfg.InsecureSkipVerify, cfg.Timeout)
	}
	return &SMTPSender{cfg: cfg, dialer: dialer}, nil
}

// WithDialer returns a copy of the sender using the given dialer — tests use
// this to point the sender at an in-process SMTP fixture.
func (s *SMTPSender) WithDialer(d SMTPDialer) *SMTPSender {
	c := *s
	c.dialer = d
	return &c
}

func (s *SMTPSender) Name() string { return "smtp" }

// Send opens a fresh SMTP transaction, optionally upgrades to TLS, optionally
// authenticates, and ships the message. One connection per message — fine
// for the v0.1 traffic profile; pooling lands when usage justifies it.
func (s *SMTPSender) Send(ctx context.Context, msg mail.Message) error {
	if msg.To == "" {
		return errors.New("mailer: empty recipient")
	}

	// Envelope FROM: prefer config override, fall back to the message's From:
	envelopeFrom := s.cfg.FromAddress
	if envelopeFrom == "" {
		from, err := stdmail.ParseAddress(msg.From)
		if err != nil {
			return fmt.Errorf("mailer: parse From header %q: %w", msg.From, err)
		}
		envelopeFrom = from.Address
	}

	envelopeTo, err := stdmail.ParseAddress(msg.To)
	if err != nil {
		return fmt.Errorf("mailer: parse To header %q: %w", msg.To, err)
	}

	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	client, err := s.dialer(ctx, addr)
	if err != nil {
		return fmt.Errorf("mailer: dial %s: %w", addr, err)
	}
	defer func() { _ = client.Close() }()

	if err := client.Hello(localHostname()); err != nil {
		return fmt.Errorf("mailer: HELO: %w", err)
	}

	if err := s.maybeStartTLS(client); err != nil {
		return fmt.Errorf("mailer: STARTTLS: %w", err)
	}

	if err := s.maybeAuth(client); err != nil {
		return fmt.Errorf("mailer: AUTH: %w", err)
	}

	if err := client.Mail(envelopeFrom); err != nil {
		return fmt.Errorf("mailer: MAIL FROM: %w", err)
	}
	if err := client.Rcpt(envelopeTo.Address); err != nil {
		return fmt.Errorf("mailer: RCPT TO: %w", err)
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("mailer: DATA: %w", err)
	}
	if _, err := wc.Write([]byte(msg.String())); err != nil {
		_ = wc.Close()
		return fmt.Errorf("mailer: write body: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("mailer: close DATA: %w", err)
	}
	return client.Quit()
}

func (s *SMTPSender) maybeStartTLS(client *smtp.Client) error {
	switch s.cfg.TLS {
	case TLSDisable, TLSImplicit:
		return nil // implicit already happened during dial; disable means nothing to do
	case TLSStartTLS:
		ok, _ := client.Extension("STARTTLS")
		if !ok {
			return errors.New("server does not advertise STARTTLS")
		}
		return client.StartTLS(s.tlsConfig())
	case TLSAuto:
		if ok, _ := client.Extension("STARTTLS"); ok {
			return client.StartTLS(s.tlsConfig())
		}
		if isLoopbackHost(s.cfg.Host) {
			return nil
		}
		return errors.New("server does not advertise STARTTLS; refusing plaintext to a non-loopback relay (set TLS mode to \"disable\" to allow it explicitly)")
	}
	return fmt.Errorf("unknown TLS mode %q", s.cfg.TLS)
}

func (s *SMTPSender) maybeAuth(client *smtp.Client) error {
	if s.cfg.Username == "" {
		return nil
	}
	// Never send relay credentials in clear to a remote host, whatever the
	// TLS mode. net/smtp's PlainAuth has this guard; our LOGIN impl did not.
	if _, tlsOK := client.TLSConnectionState(); !tlsOK && !isLoopbackHost(s.cfg.Host) {
		return errors.New("refusing to send credentials over an unencrypted connection")
	}
	ok, mechs := client.Extension("AUTH")
	if !ok {
		return errors.New("server does not advertise AUTH")
	}
	var auth smtp.Auth
	switch {
	case strings.Contains(mechs, "PLAIN"):
		auth = smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
	case strings.Contains(mechs, "LOGIN"):
		// stdlib doesn't expose LOGIN — Pull in our own (tiny) impl below.
		auth = loginAuth{username: s.cfg.Username, password: s.cfg.Password}
	default:
		return fmt.Errorf("no supported AUTH mechanism (server: %s)", mechs)
	}
	return client.Auth(auth)
}

func (s *SMTPSender) tlsConfig() *tls.Config {
	return &tls.Config{
		ServerName:         s.cfg.ServerName,
		InsecureSkipVerify: s.cfg.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}
}

// ----- LOGIN auth (stdlib net/smtp only ships PLAIN and CRAM-MD5) ----------

type loginAuth struct {
	username, password string
}

func (a loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS && !isLoopbackHost(server.Name) {
		return "", nil, errors.New("unencrypted connection")
	}
	return "LOGIN", nil, nil
}

// isLoopbackHost reports whether host names the local machine.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
func (a loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch strings.ToLower(strings.TrimSpace(string(fromServer))) {
	case "username:":
		return []byte(a.username), nil
	case "password:":
		return []byte(a.password), nil
	default:
		return nil, fmt.Errorf("unexpected LOGIN challenge %q", string(fromServer))
	}
}

// ----- default dialer -------------------------------------------------------

// bindConnToContext makes ctx govern the whole SMTP transaction on conn, not
// just the dial: net/smtp has no context support, so a relay that accepts TCP
// and then stalls would otherwise block every later read or write forever.
// The conn gets ctx's deadline (Send derives it as min(caller deadline,
// now+Timeout)), and is closed when ctx is cancelled so a blocked read
// returns at once. Send cancels its ctx on return, which also closes conn.
func bindConnToContext(ctx context.Context, conn net.Conn) error {
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return err
		}
	}
	context.AfterFunc(ctx, func() { _ = conn.Close() })
	return nil
}

// defaultDial honours context cancellation by using net.Dialer, and binds the
// connection to ctx for the rest of the transaction.
func defaultDial(ctx context.Context, addr string) (*smtp.Client, error) {
	d := &net.Dialer{Timeout: 30 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if err := bindConnToContext(ctx, conn); err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(addr)
	return smtp.NewClient(conn, host)
}

// defaultTLSDial dials directly with TLS — used when TLSImplicit is chosen
// (typically port 465). Tests can swap by overriding SMTPSender.dialer.
func defaultTLSDial(serverName string, insecure bool, timeout time.Duration) SMTPDialer {
	return func(ctx context.Context, addr string) (*smtp.Client, error) {
		d := &net.Dialer{Timeout: timeout}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		if err := bindConnToContext(ctx, conn); err != nil {
			return nil, err
		}
		host, _, _ := net.SplitHostPort(addr)
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: insecure,
			MinVersion:         tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return smtp.NewClient(tlsConn, host)
	}
}

// localHostname returns the value used in the EHLO/HELO greeting. Some
// relays reject empty / `localhost`; we use the OS hostname when available
// and fall back to `sealkeeper.local` as a stable default.
func localHostname() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "sealkeeper.local"
}
