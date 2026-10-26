package integrations_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sched75/sealkeeper/internal/integrations"
	"github.com/sched75/sealkeeper/internal/storage"
)

// ----- SK-19: dispatcher isolation + priority -------------------------------

// recordingServer counts deliveries per event_type.
type recordingServer struct {
	srv   *httptest.Server
	mu    sync.Mutex
	types []string
}

func newRecordingServer(t *testing.T, delay <-chan struct{}) *recordingServer {
	t.Helper()
	rs := &recordingServer{}
	rs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if delay != nil {
			select {
			case <-delay:
			case <-r.Context().Done():
				return
			}
		}
		var ev integrations.Event
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &ev)
		rs.mu.Lock()
		rs.types = append(rs.types, ev.EventType)
		rs.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(rs.srv.Close)
	return rs
}

func (rs *recordingServer) has(eventType string) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for _, t := range rs.types {
		if t == eventType {
			return true
		}
	}
	return false
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

func mkWebhook(t *testing.T, repo *integrations.Repo, name, url string) {
	t.Helper()
	_, err := repo.Create(context.Background(), integrations.CreateInputs{
		Name: name, Kind: integrations.KindWebhook, Enabled: true,
		ConfigJSON: `{"url":"` + url + `","timeout_sec":10}`,
	}, nil)
	if err != nil {
		t.Fatalf("Create %q: %v", name, err)
	}
}

// Regression (SK-19): one black-holed sink plus an unauthenticated
// request.rate_limited flood used to starve every other sink — the single
// worker waited on the slow sink for each event and the shared buffer
// dropped admin.login_failed.
func TestDispatcherSlowSinkDoesNotStarveHealthySink(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	block := make(chan struct{})
	slow := newRecordingServer(t, block)
	t.Cleanup(func() { close(block) }) // runs before slow.srv.Close (LIFO)
	healthy := newRecordingServer(t, nil)
	mkWebhook(t, repo, "slow", slow.srv.URL)
	mkWebhook(t, repo, "soc-healthy", healthy.srv.URL)

	d := integrations.NewDispatcher(repo, nil, 256, 10*time.Second).WithNetPolicy(integrations.TestPolicy)
	d.Start(context.Background())
	t.Cleanup(d.Stop)

	for i := 0; i < 1000; i++ {
		d.Push(integrations.NewEvent(int64(i), "request.rate_limited", "", "", nil, "", "", time.Now()))
	}
	d.Push(integrations.NewEvent(1001, "admin.login_failed", "mallory", "", nil, "", "", time.Now()))

	if !waitFor(t, 5*time.Second, func() bool { return healthy.has("admin.login_failed") }) {
		t.Fatalf("healthy sink never received admin.login_failed; stats=%+v", d.Stats())
	}
}

// Regression (SK-19): a bulk flood that fills the intake buffer must not
// cause a security event pushed afterwards to be dropped.
func TestDispatcherSecurityEventSurvivesBulkFlood(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	rs := newRecordingServer(t, nil)
	mkWebhook(t, repo, "siem", rs.srv.URL)

	d := integrations.NewDispatcher(repo, nil, 8, 5*time.Second).WithNetPolicy(integrations.TestPolicy)
	// Not started yet: intake fills up.
	for i := 0; i < 500; i++ {
		d.Push(integrations.NewEvent(int64(i), "request.rate_limited", "", "", nil, "", "", time.Now()))
	}
	d.Push(integrations.NewEvent(501, "admin.login_failed", "mallory", "", nil, "", "", time.Now()))
	if st := d.Stats(); st.DropsSecurity != 0 || st.DropsBulk == 0 {
		t.Fatalf("Stats = %+v, want bulk drops only", st)
	}
	d.Start(context.Background())
	t.Cleanup(d.Stop)
	if !waitFor(t, 5*time.Second, func() bool { return rs.has("admin.login_failed") }) {
		t.Fatalf("admin.login_failed lost behind bulk flood; stats=%+v", d.Stats())
	}
}

// Drops are surfaced to the sink itself once it recovers, and exported as
// Prometheus counters.
func TestDispatcherDropNoticeAndMetrics(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	release := make(chan struct{})
	rs := newRecordingServer(t, release)
	mkWebhook(t, repo, "stuck", rs.srv.URL)

	d := integrations.NewDispatcher(repo, nil, 1, 10*time.Second).WithNetPolicy(integrations.TestPolicy)
	d.Start(context.Background())
	t.Cleanup(d.Stop)

	for i := 0; i < 50; i++ {
		d.Push(integrations.NewEvent(int64(i), "request.rate_limited", "", "", nil, "", "", time.Now()))
		time.Sleep(time.Millisecond)
	}
	if !waitFor(t, 3*time.Second, func() bool { return d.Stats().DropsBulk > 0 }) {
		t.Fatalf("expected per-sink drops; stats=%+v", d.Stats())
	}
	close(release)
	if !waitFor(t, 5*time.Second, func() bool { return rs.has(integrations.EventDropsNotice) }) {
		t.Fatalf("sink never received %s", integrations.EventDropsNotice)
	}

	reg := prometheus.NewRegistry()
	if err := reg.Register(d); err != nil {
		t.Fatalf("Register: %v", err)
	}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	found := false
	for _, mf := range mfs {
		if mf.GetName() != "sealkeeper_integrations_events_dropped_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetValue() == "bulk" && m.GetCounter().GetValue() > 0 {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("sealkeeper_integrations_events_dropped_total{lane=bulk} not exported")
	}
}

// ----- integrations-audit-data#5: strict filters ----------------------------

func TestCreateRejectsMalformedFilters(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	cases := []struct{ name, filters string }{
		{"string instead of array", `{"event_types":"admin."}`},
		{"typo key", `{"event_type":["admin."]}`},
		{"blank entry", `{"event_types":[""]}`},
		{"number entries", `{"event_types":[1,2]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := r.Create(context.Background(), integrations.CreateInputs{
				Name: "f-" + c.name, Kind: integrations.KindWebhook, Enabled: true,
				ConfigJSON:  `{"url":"https://siem.example.test/in"}`,
				FiltersJSON: c.filters,
			}, nil)
			if !errors.Is(err, integrations.ErrInvalidConfig) {
				t.Fatalf("err = %v, want ErrInvalidConfig", err)
			}
		})
	}
	if _, err := r.Create(context.Background(), integrations.CreateInputs{
		Name: "ok", Kind: integrations.KindWebhook,
		ConfigJSON:  `{"url":"https://siem.example.test/in"}`,
		FiltersJSON: `{"event_types":["admin.","request.rate_limited"]}`,
	}, nil); err != nil {
		t.Fatalf("valid filter rejected: %v", err)
	}
}

// A malformed filter already stored (pre-validation row) fails closed: the
// sink receives nothing instead of everything.
func TestDispatcherMalformedStoredFilterFailsClosed(t *testing.T) {
	t.Parallel()
	repo, db := newRepoDB(t)
	rs := newRecordingServer(t, nil)
	row, err := repo.Create(context.Background(), integrations.CreateInputs{
		Name: "chatops", Kind: integrations.KindWebhook, Enabled: true,
		ConfigJSON:  `{"url":"` + rs.srv.URL + `"}`,
		FiltersJSON: `{"event_types":["admin."]}`,
	}, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := db.Exec(storage.Rebind(db, `UPDATE integrations SET filters_json = ? WHERE id = ?`),
		`{"event_types":"admin."}`, row.ID); err != nil {
		t.Fatalf("corrupt filter: %v", err)
	}
	d := integrations.NewDispatcher(repo, nil, 8, 2*time.Second).WithNetPolicy(integrations.TestPolicy)
	d.Start(context.Background())
	t.Cleanup(d.Stop)
	d.Push(integrations.NewEvent(1, "token.issued", "user@example.test", "ref", nil, "", "", time.Now()))
	d.Push(integrations.NewEvent(2, "admin.login", "alice", "", nil, "", "", time.Now()))
	time.Sleep(300 * time.Millisecond)
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if len(rs.types) != 0 {
		t.Fatalf("sink with malformed filter received %v, want nothing", rs.types)
	}
}

// ----- SK-22: SSRF guard -----------------------------------------------------

func TestNetPolicyAddressClasses(t *testing.T) {
	t.Parallel()
	cases := []struct {
		ip                  string
		strict, withPrivate bool // allowed?
	}{
		{"127.0.0.1", false, false},
		{"::1", false, false},
		{"::ffff:127.0.0.1", false, false},
		{"169.254.169.254", false, false},
		{"fe80::1", false, false},
		{"0.0.0.0", false, false},
		{"0.1.2.3", false, false},
		{"::", false, false},
		{"224.0.0.1", false, false},
		{"255.255.255.255", false, false},
		{"fd00:ec2::254", false, false},
		{"100.100.100.200", false, false},
		{"10.1.2.3", false, true},
		{"172.16.0.1", false, true},
		{"192.168.1.10", false, true},
		{"100.64.0.1", false, true},
		{"fd12:3456::1", false, true},
		{"8.8.8.8", true, true},
		{"2001:4860:4860::8888", true, true},
	}
	for _, c := range cases {
		ip := netip.MustParseAddr(c.ip)
		if got := (integrations.NetPolicy{}).CheckAddr(ip) == nil; got != c.strict {
			t.Errorf("strict %s allowed=%v, want %v", c.ip, got, c.strict)
		}
		if got := (integrations.NetPolicy{AllowPrivate: true}).CheckAddr(ip) == nil; got != c.withPrivate {
			t.Errorf("allow-private %s allowed=%v, want %v", c.ip, got, c.withPrivate)
		}
	}
}

// Regression: IPv6 forms that the network translates back to an embedded
// IPv4 destination (NAT64 well-known prefix, RFC 8215 local-use prefix,
// 6to4) used to be treated as ordinary public IPv6, so [64:ff9b::a9fe:a9fe]
// reached the cloud metadata endpoint on a NAT64 network. The embedded
// IPv4 must get the same verdict as the bare IPv4.
func TestNetPolicyIPv4EmbeddedInIPv6(t *testing.T) {
	t.Parallel()
	cases := []struct {
		ip                  string
		strict, withPrivate bool // allowed?
	}{
		// NAT64 well-known prefix 64:ff9b::/96 (RFC 6052).
		{"64:ff9b::a9fe:a9fe", false, false}, // 169.254.169.254
		{"64:ff9b::7f00:1", false, false},    // 127.0.0.1
		{"64:ff9b::6464:64c8", false, false}, // 100.100.100.200
		{"64:ff9b::a00:5", false, true},      // 10.0.0.5
		{"64:ff9b::c0a8:10a", false, true},   // 192.168.1.10
		{"64:ff9b::808:808", true, true},     // 8.8.8.8
		// RFC 8215 local-use prefix 64:ff9b:1::/48: local by design, and
		// any RFC 6052 embedding of a blocked IPv4 is always refused.
		{"64:ff9b:1::a9fe:a9fe", false, false},      // /96 embedding
		{"64:ff9b:1:a9fe:a9:fe00::", false, false},  // /48 embedding
		{"64:ff9b:1:ff7f:0:1::", false, false},      // /56 embedding
		{"64:ff9b:1:ffff:7f:0:100:0", false, false}, // /64 embedding
		{"64:ff9b:1::808:808", false, true},         // public, but local-use prefix
		{"64:ff9b:1:808:8:800::", false, true},      // 8.8.8.8, /48 embedding
		// 6to4 2002::/16: IPv4 in bits 16..47.
		{"2002:a9fe:a9fe::1", false, false}, // 169.254.169.254
		{"2002:7f00:1::1", false, false},    // 127.0.0.1
		{"2002:a00:5::1", false, true},      // 10.0.0.5
		{"2002:808:808::1", true, true},     // 8.8.8.8
	}
	for _, c := range cases {
		ip := netip.MustParseAddr(c.ip)
		if got := (integrations.NetPolicy{}).CheckAddr(ip) == nil; got != c.strict {
			t.Errorf("strict %s allowed=%v, want %v", c.ip, got, c.strict)
		}
		if got := (integrations.NetPolicy{AllowPrivate: true}).CheckAddr(ip) == nil; got != c.withPrivate {
			t.Errorf("allow-private %s allowed=%v, want %v", c.ip, got, c.withPrivate)
		}
	}
}

// Regression (SK-22): a webhook to loopback (here reached through the
// "localhost" hostname, so the check is on the resolved IP) used to be
// dialled. It must be refused before any byte leaves the process.
func TestWebhookRefusesLoopbackByDefault(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	for _, u := range []string{srv.URL, "http://localhost:" + port + "/x"} {
		sink, err := integrations.BuildSink(integrations.Integration{
			Name: "ssrf", Kind: integrations.KindWebhook,
			ConfigJSON: json.RawMessage(`{"url":"` + u + `"}`),
		}, integrations.NetPolicy{AllowPrivate: true})
		if err != nil {
			t.Fatalf("BuildSink: %v", err)
		}
		err = sink.Send(context.Background(), integrations.NewEvent(0, "x", "", "", nil, "", "", time.Now()))
		if !errors.Is(err, integrations.ErrDestinationBlocked) {
			t.Fatalf("%s: err = %v, want ErrDestinationBlocked", u, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("loopback server was reached %d times", hits.Load())
	}
}

func TestSyslogRefusesLoopbackByDefault(t *testing.T) {
	t.Parallel()
	sink, err := integrations.BuildSink(integrations.Integration{
		Name: "rsys", Kind: integrations.KindSyslog,
		ConfigJSON: json.RawMessage(`{"address":"127.0.0.1:514","network":"udp"}`),
	}, integrations.NetPolicy{})
	if err != nil {
		t.Fatalf("BuildSink: %v", err)
	}
	err = sink.Send(context.Background(), integrations.NewEvent(0, "x", "", "", nil, "", "", time.Now()))
	if !errors.Is(err, integrations.ErrDestinationBlocked) {
		t.Fatalf("err = %v, want ErrDestinationBlocked", err)
	}
}

// Regression (SK-22): redirects used to be followed, replaying the POST
// body and custom headers (X-Api-Key) to the redirect target.
func TestWebhookDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	var victimHits atomic.Int64
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		victimHits.Add(1)
	}))
	t.Cleanup(victim.Close)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, victim.URL+"/latest/meta-data/", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirector.Close)

	sink, err := integrations.BuildSink(integrations.Integration{
		Name: "redir", Kind: integrations.KindWebhook,
		ConfigJSON: json.RawMessage(`{"url":"` + redirector.URL + `","headers":{"X-Api-Key":"siem-key"}}`),
	}, integrations.TestPolicy)
	if err != nil {
		t.Fatalf("BuildSink: %v", err)
	}
	err = sink.Send(context.Background(), integrations.NewEvent(0, "x", "", "", nil, "", "", time.Now()))
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("err = %v, want HTTP 307 surfaced as error", err)
	}
	if victimHits.Load() != 0 {
		t.Fatalf("redirect target was reached %d times", victimHits.Load())
	}
}

// Regression (SK-22): up to 512 bytes of the remote body used to be echoed
// into the error (admin UI + audit), giving an SSRF read primitive.
func TestTestSinkErrorCarriesStatusOnly(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"internal_secret":"db-password=hunter2"}`))
	}))
	t.Cleanup(srv.Close)
	row := integrations.Integration{
		Name: "leaky", Kind: integrations.KindWebhook,
		ConfigJSON: json.RawMessage(`{"url":"` + srv.URL + `"}`),
	}
	err := integrations.TestSink(context.Background(), row, "sealkeeper.test", integrations.TestPolicy)
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("err = %v, want HTTP 403", err)
	}
	if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "internal_secret") {
		t.Fatalf("err = %q reflects the response body", err)
	}
}

// Regression (SK-22): Sentinel workspace_id was spliced into the hostname,
// so "attacker.host/x?" sent the signed request elsewhere.
func TestSentinelWorkspaceIDMustBeGUID(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	for _, ws := range []string{"127.0.0.1:8080/steal?x=", "evil.example", ""} {
		_, err := integrations.BuildSink(integrations.Integration{
			Name: "s", Kind: integrations.KindSentinel,
			ConfigJSON: json.RawMessage(`{"workspace_id":"` + ws + `","shared_key":"a2V5"}`),
		}, integrations.NetPolicy{})
		if !errors.Is(err, integrations.ErrInvalidConfig) {
			t.Errorf("BuildSink(workspace_id=%q) err = %v, want ErrInvalidConfig", ws, err)
		}
		_, err = r.Create(context.Background(), integrations.CreateInputs{
			Name: "s-" + ws, Kind: integrations.KindSentinel,
			ConfigJSON: `{"workspace_id":"` + ws + `","shared_key":"a2V5"}`,
		}, nil)
		if !errors.Is(err, integrations.ErrInvalidConfig) {
			t.Errorf("Create(workspace_id=%q) err = %v, want ErrInvalidConfig", ws, err)
		}
	}
	if _, err := integrations.BuildSink(integrations.Integration{
		Name: "ok", Kind: integrations.KindSentinel,
		ConfigJSON: json.RawMessage(`{"workspace_id":"0b0c1e2d-3f4a-5b6c-7d8e-9f0a1b2c3d4e","shared_key":"a2V5"}`),
	}, integrations.NetPolicy{}); err != nil {
		t.Fatalf("valid GUID rejected: %v", err)
	}
}

func TestCreateRejectsNonHTTPURL(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	for _, u := range []string{"file:///etc/passwd", "gopher://x", "https://user:pw@siem.example.test/", "/relative"} {
		_, err := r.Create(context.Background(), integrations.CreateInputs{
			Name: u, Kind: integrations.KindWebhook, ConfigJSON: `{"url":"` + u + `"}`,
		}, nil)
		if !errors.Is(err, integrations.ErrInvalidConfig) {
			t.Errorf("Create(url=%q) err = %v, want ErrInvalidConfig", u, err)
		}
	}
}

// ----- SK-23: credentials sealed at rest -------------------------------------

// Regression (SK-23 / FR-E.56): integration credentials used to be stored
// as clear JSON in config_json.
func TestCreateSealsCredentialsAtRest(t *testing.T) {
	t.Parallel()
	repo, db := newRepoDB(t)
	const secret = "s3cr3t-bearer-token"
	row, err := repo.Create(context.Background(), integrations.CreateInputs{
		Name: "siem", Kind: integrations.KindWebhook, Enabled: true,
		ConfigJSON: `{"url":"https://siem.example.test/in","bearer_token":"` + secret + `"}`,
	}, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	var clear string
	var enc []byte
	if err := db.QueryRow(storage.Rebind(db, `SELECT config_json, config_enc FROM integrations WHERE id = ?`),
		row.ID).Scan(&clear, &enc); err != nil {
		t.Fatalf("raw select: %v", err)
	}
	if strings.Contains(clear, secret) || strings.Contains(string(enc), secret) {
		t.Fatalf("secret stored in clear: config_json=%q", clear)
	}
	if len(enc) == 0 {
		t.Fatal("config_enc empty")
	}
	got, err := repo.Get(context.Background(), row.ID)
	if err != nil || got.ConfigErr != nil {
		t.Fatalf("Get: %v / %v", err, got.ConfigErr)
	}
	if !strings.Contains(string(got.ConfigJSON), secret) || !got.Enabled {
		t.Fatalf("round-trip lost config or enabled flag: %+v", got)
	}
}

// Rows written before migration 0015 are sealed in place at boot, and a
// sealed blob is bound to its row (AAD) — copied to another row it fails.
func TestSealLegacyConfigsAndAADBinding(t *testing.T) {
	t.Parallel()
	repo, db := newRepoDB(t)
	ctx := context.Background()
	const secret = "legacy-hec-token"
	now := time.Now().UTC()
	if _, err := db.Exec(storage.Rebind(db, `INSERT INTO integrations
		(name, kind, enabled, config_json, filters_json, created_at, updated_at)
		VALUES (?, ?, ?, ?, '{}', ?, ?)`),
		"legacy", "splunk", true,
		`{"url":"https://hec.example.test/services/collector","token":"`+secret+`"}`, now, now); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	n, err := repo.SealLegacyConfigs(ctx)
	if err != nil || n != 1 {
		t.Fatalf("SealLegacyConfigs = %d, %v; want 1, nil", n, err)
	}
	if n, _ := repo.SealLegacyConfigs(ctx); n != 0 {
		t.Fatalf("second SealLegacyConfigs sealed %d rows, want 0 (idempotent)", n)
	}
	var clear string
	if err := db.QueryRow(`SELECT config_json FROM integrations WHERE name = 'legacy'`).Scan(&clear); err != nil {
		t.Fatalf("raw select: %v", err)
	}
	if strings.Contains(clear, secret) {
		t.Fatalf("legacy secret still in clear: %q", clear)
	}
	list, err := repo.List(ctx)
	if err != nil || len(list) != 1 || !strings.Contains(string(list[0].ConfigJSON), secret) {
		t.Fatalf("List after seal = %+v, %v", list, err)
	}

	other, err := repo.Create(ctx, integrations.CreateInputs{
		Name: "other", Kind: integrations.KindWebhook,
		ConfigJSON: `{"url":"https://other.example.test/in"}`,
	}, nil)
	if err != nil {
		t.Fatalf("Create other: %v", err)
	}
	if _, err := db.Exec(storage.Rebind(db, `UPDATE integrations SET config_enc =
		(SELECT config_enc FROM integrations WHERE name = 'legacy') WHERE id = ?`), other.ID); err != nil {
		t.Fatalf("copy blob: %v", err)
	}
	got, err := repo.Get(ctx, other.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ConfigErr == nil {
		t.Fatal("blob copied from another row decrypted; AAD not bound to row id")
	}
	if _, err := integrations.BuildSink(got, integrations.NetPolicy{}); !errors.Is(err, integrations.ErrInvalidConfig) {
		t.Fatalf("BuildSink on undecryptable row err = %v, want ErrInvalidConfig", err)
	}
}
