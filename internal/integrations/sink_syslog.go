package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// SyslogConfig describes an RFC 5424 syslog target.
type SyslogConfig struct {
	Address    string `json:"address"`            // "host:port"
	Network    string `json:"network,omitempty"`  // "udp" (default) or "tcp"
	Facility   int    `json:"facility,omitempty"` // 0..23, default 1 (user)
	Hostname   string `json:"hostname,omitempty"` // overrides os.Hostname()
	AppName    string `json:"app_name,omitempty"` // default "sealkeeper"
	TimeoutSec int    `json:"timeout_sec,omitempty"`
}

type syslogSink struct {
	name string
	cfg  SyslogConfig
	pol  NetPolicy
}

func newSyslogSink(name string, cfg SyslogConfig, pol NetPolicy) *syslogSink {
	return &syslogSink{name: name, cfg: cfg, pol: pol}
}

func (s *syslogSink) Name() string { return s.name }
func (s *syslogSink) Kind() Kind   { return KindSyslog }

// Send formats the event as a RFC 5424 message and writes it on a fresh
// UDP/TCP socket. No connection pooling — the v0.1 dispatcher emits at
// most a few events per second, so the syscall overhead is negligible
// and keepalive bugs become impossible.
func (s *syslogSink) Send(ctx context.Context, ev Event) error {
	if strings.TrimSpace(s.cfg.Address) == "" {
		return fmt.Errorf("syslog: address required")
	}
	network := s.cfg.Network
	if network == "" {
		network = "udp"
	}
	if network != "udp" && network != "tcp" {
		return fmt.Errorf("syslog: invalid network %q", network)
	}

	host := defaultStr(s.cfg.Hostname, defaultHostname())
	app := defaultStr(s.cfg.AppName, "sealkeeper")
	severity := severityForEvent(ev.EventType)
	facility := s.cfg.Facility
	if facility < 0 || facility > 23 {
		facility = 1 // user-level
	}
	pri := facility*8 + severity

	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}

	// RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
	msg := fmt.Sprintf("<%d>1 %s %s %s %d %s - %s",
		pri,
		ev.OccurredAt.UTC().Format(time.RFC3339Nano),
		host,
		app,
		os.Getpid(),
		nilDash(ev.EventType),
		string(body),
	)

	timeout := time.Duration(s.cfg.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	// Guarded dialer: the resolved IP is checked against the outbound
	// policy at connect time (SSRF guard, DNS-rebinding safe).
	conn, err := s.pol.dialer(timeout).DialContext(ctx, network, s.cfg.Address)
	if err != nil {
		return fmt.Errorf("syslog: dial %s/%s: %w", network, s.cfg.Address, err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	out := []byte(msg)
	if network == "tcp" {
		// RFC 6587 non-transparent framing — newline terminator.
		out = append(out, '\n')
	}
	if _, err := conn.Write(out); err != nil {
		return fmt.Errorf("syslog: write: %w", err)
	}
	return nil
}

// severityForEvent maps audit event types to RFC 5424 severities. Anything
// related to a failed login / rate limit / domain block is "warning"; the
// rest is "informational".
func severityForEvent(eventType string) int {
	switch {
	case strings.Contains(eventType, "failed"),
		strings.Contains(eventType, "blocked"),
		strings.Contains(eventType, "rate_limit"),
		strings.Contains(eventType, "locked"):
		return 4 // warning
	default:
		return 6 // informational
	}
}

func defaultHostname() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "sealkeeper.local"
}

func nilDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
