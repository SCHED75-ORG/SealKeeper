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
// ULA fc00::/7, CGNAT 100.64.0.0/10 and the RFC 8215 local-use NAT64
// prefix 64:ff9b:1::/48 (SK_INTEGRATIONS_ALLOW_PRIVATE).
//
// IPv6 forms that the network translates back to an embedded IPv4 (NAT64
// 64:ff9b::/96 and 64:ff9b:1::/48, 6to4 2002::/16) are judged on that
// embedded IPv4 too, so [64:ff9b::a9fe:a9fe] is refused like
// 169.254.169.254.
type NetPolicy struct {
	AllowPrivate bool

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
		nat64LocalPrefix,
	}

	nat64WellKnownPrefix = netip.MustParsePrefix("64:ff9b::/96")   // RFC 6052
	nat64LocalPrefix     = netip.MustParsePrefix("64:ff9b:1::/48") // RFC 8215
	sixToFourPrefix      = netip.MustParsePrefix("2002::/16")      // RFC 3056
	thisNetworkPrefix    = netip.MustParsePrefix("0.0.0.0/8")
)

// embeddedIPv4 returns the IPv4 destinations an IPv6 address is translated
// to by NAT64 or 6to4 relays. The RFC 8215 local-use prefix may be deployed
// with any RFC 6052 prefix length >= /48, so every candidate layout is
// returned; a single blocked candidate refuses the address.
func embeddedIPv4(ip netip.Addr) []netip.Addr {
	if !ip.Is6() {
		return nil
	}
	b := ip.As16()
	v4 := func(i ...int) netip.Addr {
		return netip.AddrFrom4([4]byte{b[i[0]], b[i[1]], b[i[2]], b[i[3]]})
	}
	switch {
	case nat64WellKnownPrefix.Contains(ip):
		return []netip.Addr{v4(12, 13, 14, 15)}
	case nat64LocalPrefix.Contains(ip):
		// RFC 6052 section 2.2 layouts; byte 8 (u-octet) is skipped. The
		// zero padding of one layout reads as 0.0.0.0/8 in another, and no
		// translator forwards to 0.0.0.0/8: drop those guesses so they do
		// not refuse every address under the prefix.
		var out []netip.Addr
		for _, c := range []netip.Addr{
			v4(6, 7, 9, 10),    // /48
			v4(7, 9, 10, 11),   // /56
			v4(9, 10, 11, 12),  // /64
			v4(12, 13, 14, 15), // /96
		} {
			if !thisNetworkPrefix.Contains(c) {
				out = append(out, c)
			}
		}
		return out
	case sixToFourPrefix.Contains(ip):
		return []netip.Addr{v4(2, 3, 4, 5)}
	}
	return nil
}

// checkAddr reports whether `ip` may be dialled under the policy.
func (p NetPolicy) checkAddr(ip netip.Addr) error {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return fmt.Errorf("%w: invalid address", ErrDestinationBlocked)
	}
	for _, v4 := range embeddedIPv4(ip) {
		if err := p.checkAddr(v4); err != nil {
			return fmt.Errorf("%w (embedded in %s)", err, ip)
		}
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
