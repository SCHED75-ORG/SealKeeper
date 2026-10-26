package integrations

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// ErrDestinationBlocked is returned (wrapped) when a sink tries to reach an
// address the outbound policy refuses (SSRF guard, SK-22).
var ErrDestinationBlocked = errors.New("integrations: destination address blocked")

// NetPolicy is the outbound address policy applied to every sink dial.
//
// The check runs inside net.Dialer.Control, i.e. on the IP the socket is
// about to connect to *after* DNS resolution. A hostname that resolves to a
// public IP during validation and to 169.254.169.254 at send time (DNS
// rebinding) is therefore still refused.
//
// Always refused: loopback, link-local (incl. 169.254.169.254 cloud
// metadata), unspecified, multicast, broadcast, 0.0.0.0/8 and the
// well-known metadata endpoints that live in otherwise "private" ranges
// (fd00:ec2::254, 100.100.100.200). Refused unless AllowPrivate: RFC 1918,
// ULA fc00::/7 and CGNAT 100.64.0.0/10 (SK_INTEGRATIONS_ALLOW_PRIVATE).
//
// HTTP sinks must use https unless AllowPlainHTTP (set in eval mode only):
// a plain http sink would carry audit events and its own credentials in
// clear.
type NetPolicy struct {
	AllowPrivate   bool
	AllowPlainHTTP bool

	// allowLoopback is a test-only escape hatch so httptest servers on
	// 127.0.0.1 stay reachable. Unexported: production code cannot set it.
	allowLoopback bool
}

var (
	alwaysBlockedPrefixes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("255.255.255.255/32"),
		netip.MustParsePrefix("100.100.100.200/32"), // Alibaba metadata (inside CGNAT)
		netip.MustParsePrefix("fd00:ec2::254/128"),  // AWS IMDS IPv6 (inside ULA)
	}
	privatePrefixes = []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"), // CGNAT, RFC 6598
	}
)

// checkAddr reports whether `ip` may be dialled under the policy.
func (p NetPolicy) checkAddr(ip netip.Addr) error {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return fmt.Errorf("%w: invalid address", ErrDestinationBlocked)
	}
	if ip.IsLoopback() && p.allowLoopback {
		return nil
	}
	switch {
	case ip.IsLoopback(), ip.IsUnspecified(), ip.IsMulticast(),
		ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsInterfaceLocalMulticast():
		return fmt.Errorf("%w: %s (loopback/link-local/unspecified/multicast)", ErrDestinationBlocked, ip)
	}
	for _, pfx := range alwaysBlockedPrefixes {
		if pfx.Contains(ip) {
			return fmt.Errorf("%w: %s (reserved/metadata)", ErrDestinationBlocked, ip)
		}
	}
	private := ip.IsPrivate()
	for _, pfx := range privatePrefixes {
		if pfx.Contains(ip) {
			private = true
		}
	}
	if private && !p.AllowPrivate {
		return fmt.Errorf("%w: %s (private range; set SK_INTEGRATIONS_ALLOW_PRIVATE=true to allow)",
			ErrDestinationBlocked, ip)
	}
	return nil
}

// control is the net.Dialer.Control hook. `address` is the resolved
// "ip:port" the socket is about to connect to.
func (p NetPolicy) control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %q", ErrDestinationBlocked, address)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: %q is not an IP", ErrDestinationBlocked, host)
	}
	return p.checkAddr(ip)
}

// dialer returns a net.Dialer that enforces the policy on every connect.
func (p NetPolicy) dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Control: p.control}
}

// httpClient builds the HTTP client used by HTTP sinks: guarded dialer, no
// proxy (a proxy would make the guard check the proxy instead of the real
// destination), no redirects (a 3xx would otherwise re-target the request,
// replaying the custom headers to an arbitrary host).
func (p NetPolicy) httpClient(timeoutSec int) *http.Client {
	if timeoutSec <= 0 {
		timeoutSec = 10
	}
	timeout := time.Duration(timeoutSec) * time.Second
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           p.dialer(timeout).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
