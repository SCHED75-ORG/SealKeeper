// Command healthcheck is a tiny self-contained probe baked into the distroless
// runtime image. The image ships no curl or wget, so the Docker / Kubernetes
// HEALTHCHECK and the smoke tests rely on this binary.
//
// It performs a single GET against HEALTHCHECK_URL (default
// http://127.0.0.1:8443/healthz) and exits 0 on HTTP 200, 1 otherwise.
//
// The probe only ever talks to the local process: the target host must be a
// loopback address (or "localhost"), every dialled address is re-checked
// against loopback, redirects are never followed (a 3xx is a failure) and
// proxy environment variables are ignored. A health probe that could be
// steered off-box would be an in-container SSRF primitive.
package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"syscall"
	"time"
)

const defaultTarget = "http://127.0.0.1:8443/healthz"

var errNotLoopback = errors.New("healthcheck: target is not a loopback address")

func main() {
	os.Exit(run(os.Getenv("HEALTHCHECK_URL")))
}

// run probes target (defaultTarget when empty) and returns the exit code.
func run(target string) int {
	if target == "" {
		target = defaultTarget
	}
	if err := probe(target); err != nil {
		return 1
	}
	return 0
}

// probe GETs target and returns nil only on a direct HTTP 200 from loopback.
func probe(target string) error {
	u, err := checkTarget(target)
	if err != nil {
		return err
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second, Control: loopbackOnly}
	cli := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			Proxy:             nil,
			DialContext:       dialer.DialContext,
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	r, err := cli.Get(u.String())
	if err != nil {
		return err
	}
	_ = r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: status %d", r.StatusCode)
	}
	return nil
}

// checkTarget accepts only http(s) URLs whose host is a loopback IP literal
// or "localhost" (the dial-time check covers what localhost resolves to).
func checkTarget(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("healthcheck: unsupported scheme %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "localhost" {
		return u, nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return u, nil
	}
	return nil, errNotLoopback
}

// loopbackOnly is a net.Dialer Control hook refusing any non-loopback peer.
func loopbackOnly(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return errNotLoopback
}
