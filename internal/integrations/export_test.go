package integrations

import (
	"net/netip"
	"time"
)

// TestPolicy lets httptest servers (plain http on 127.0.0.1) through the
// SSRF guard and the https requirement. Only compiled into this package's
// tests.
var TestPolicy = NetPolicy{allowLoopback: true, AllowPlainHTTP: true}

// CheckAddr exposes NetPolicy.checkAddr to the external test package.
func (p NetPolicy) CheckAddr(ip netip.Addr) error { return p.checkAddr(ip) }

// SetRefreshEvery shortens the sink-list cache for tests.
func (d *Dispatcher) SetRefreshEvery(v time.Duration) { d.refreshEvery = v }

// IntegrationAAD exposes the per-row AAD for the encryption tests.
func IntegrationAAD(id int64) []byte { return integrationAAD(id) }
