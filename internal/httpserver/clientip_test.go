package httpserver

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/sched75/sealkeeper/internal/config"
)

func newClientIPServer(t *testing.T, cidrs ...string) *Server {
	t.Helper()
	cfg := config.Defaults()
	cfg.TrustedProxyCIDRs = cidrs
	return New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestClientIP(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		trusted []string
		remote  string
		xff     []string
		want    string
	}{
		{name: "no proxy configured ignores spoofed XFF", remote: "203.0.113.7:5555", xff: []string{"1.2.3.4"}, want: "203.0.113.7"},
		{name: "untrusted peer ignores XFF", trusted: []string{"172.16.0.0/12"}, remote: "203.0.113.7:5555", xff: []string{"1.2.3.4"}, want: "203.0.113.7"},
		{name: "trusted peer without XFF", trusted: []string{"172.16.0.0/12"}, remote: "172.18.0.2:5555", want: "172.18.0.2"},
		{name: "trusted peer single hop", trusted: []string{"172.16.0.0/12"}, remote: "172.18.0.2:5555", xff: []string{"198.51.100.9"}, want: "198.51.100.9"},
		{name: "client-prepended entries are skipped", trusted: []string{"172.16.0.0/12"}, remote: "172.18.0.2:5555", xff: []string{"1.2.3.4, 198.51.100.9"}, want: "198.51.100.9"},
		{name: "chained trusted proxies", trusted: []string{"172.16.0.0/12", "10.0.0.0/8"}, remote: "172.18.0.2:5555", xff: []string{"1.2.3.4, 198.51.100.9, 10.1.2.3"}, want: "198.51.100.9"},
		{name: "multiple XFF header lines", trusted: []string{"172.16.0.0/12"}, remote: "172.18.0.2:5555", xff: []string{"1.2.3.4", "198.51.100.9"}, want: "198.51.100.9"},
		{name: "malformed hop stops at last vouched address", trusted: []string{"172.16.0.0/12"}, remote: "172.18.0.2:5555", xff: []string{"not-an-ip"}, want: "172.18.0.2"},
		{name: "bare IP trusted entry", trusted: []string{"127.0.0.1"}, remote: "127.0.0.1:5555", xff: []string{"198.51.100.9"}, want: "198.51.100.9"},
		{name: "ipv6 peer", trusted: []string{"fd00::/8"}, remote: "[fd00::1]:5555", xff: []string{"2001:db8::42"}, want: "2001:db8::42"},
		{name: "ipv4-mapped peer", trusted: []string{"172.16.0.0/12"}, remote: "[::ffff:172.18.0.2]:5555", xff: []string{"198.51.100.9"}, want: "198.51.100.9"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s := newClientIPServer(t, c.trusted...)
			r := httptest.NewRequest("POST", "/api/v1/request", nil)
			r.RemoteAddr = c.remote
			for _, v := range c.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := s.clientIP(r); got != c.want {
				t.Errorf("clientIP = %q, want %q", got, c.want)
			}
		})
	}
}

func TestNew_InvalidTrustedProxyTrustsNobody(t *testing.T) {
	t.Parallel()
	s := newClientIPServer(t, "not-a-cidr")
	r := httptest.NewRequest("POST", "/api/v1/request", nil)
	r.RemoteAddr = "172.18.0.2:5555"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := s.clientIP(r); got != "172.18.0.2" {
		t.Errorf("clientIP = %q, want peer address", got)
	}
}
