package integrations_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/cryptobox"
	"github.com/sched75/sealkeeper/internal/integrations"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
)

// ----- Filters --------------------------------------------------------------

func TestFiltersEmptyForwardsEverything(t *testing.T) {
	t.Parallel()
	f := integrations.Filters{}
	for _, evt := range []string{"admin.login", "token.issued", "request.rate_limited"} {
		if !f.Matches(evt) {
			t.Errorf("empty filter rejected %q", evt)
		}
	}
}

func TestFiltersPrefixAndExact(t *testing.T) {
	t.Parallel()
	f := integrations.Filters{EventTypes: []string{"admin.", "request.rate_limited"}}
	cases := map[string]bool{
		"admin.login":            true,
		"admin.password_changed": true,
		"request.rate_limited":   true,
		"request.accepted":       false,
		"token.issued":           false,
	}
	for evt, want := range cases {
		if got := f.Matches(evt); got != want {
			t.Errorf("Matches(%q) = %v, want %v", evt, got, want)
		}
	}
}

// ----- Repo CRUD ------------------------------------------------------------

func newRepo(t *testing.T) *integrations.Repo {
	t.Helper()
	r, _ := newRepoDB(t)
	return r
}

func newRepoDB(t *testing.T) (*integrations.Repo, *sql.DB) {
	t.Helper()
	dsn := storagetest.DSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), storagetest.SetupTimeout)
	defer cancel()
	s, err := storage.Open(ctx, storage.Options{DSN: dsn})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	box, err := cryptobox.New("integrations-test-master-secret")
	if err != nil {
		t.Fatalf("cryptobox.New: %v", err)
	}
	return integrations.NewRepo(s.DB(), box).WithNetPolicy(integrations.TestPolicy), s.DB()
}

func TestCreateRejectsBadKind(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	_, err := r.Create(context.Background(), integrations.CreateInputs{
		Name: "x", Kind: integrations.Kind("foo"), Enabled: true,
	}, nil)
	if !errors.Is(err, integrations.ErrInvalidKind) {
		t.Fatalf("err = %v, want ErrInvalidKind", err)
	}
}

func TestCreateRejectsBadConfigJSON(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	_, err := r.Create(context.Background(), integrations.CreateInputs{
		Name: "x", Kind: integrations.KindWebhook, ConfigJSON: "{not json",
	}, nil)
	if !errors.Is(err, integrations.ErrInvalidConfig) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
}

func TestCreateAndListEnabled(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()

	_, _ = r.Create(ctx, integrations.CreateInputs{
		Name: "siem", Kind: integrations.KindWebhook, Enabled: true,
		ConfigJSON: `{"url":"https://example.test/in"}`,
	}, nil)
	_, _ = r.Create(ctx, integrations.CreateInputs{
		Name: "off", Kind: integrations.KindWebhook, Enabled: false,
		ConfigJSON: `{"url":"https://other.test/in"}`,
	}, nil)
	list, err := r.ListEnabled(ctx)
	if err != nil {
		t.Fatalf("ListEnabled: %v", err)
	}
	if len(list) != 1 || list[0].Name != "siem" {
		t.Fatalf("ListEnabled = %v", list)
	}
}

func TestDuplicateRejected(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	_, err := r.Create(ctx, integrations.CreateInputs{
		Name: "dup", Kind: integrations.KindWebhook,
		ConfigJSON: `{"url":"https://x.test"}`,
	}, nil)
	if err != nil {
		t.Fatalf("first Create: %v", err)
	}
	_, err = r.Create(ctx, integrations.CreateInputs{
		Name: "dup", Kind: integrations.KindSplunk,
		ConfigJSON: `{"url":"https://x.test","token":"t"}`,
	}, nil)
	if !errors.Is(err, integrations.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}

// ----- HTTP webhook sink ----------------------------------------------------

func TestWebhookSinkSendsJSON(t *testing.T) {
	t.Parallel()

	var got struct {
		mu     sync.Mutex
		body   []byte
		auth   string
		method string
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got.mu.Lock()
		got.body = body
		got.auth = r.Header.Get("Authorization")
		got.method = r.Method
		got.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	row := integrations.Integration{
		Name: "test",
		Kind: integrations.KindWebhook,
		ConfigJSON: json.RawMessage(`{
			"url": "` + srv.URL + `",
			"bearer_token": "secret-token",
			"timeout_sec": 3
		}`),
	}
	sink, err := integrations.BuildSink(row, integrations.TestPolicy)
	if err != nil {
		t.Fatalf("BuildSink: %v", err)
	}
	ev := integrations.NewEvent(1, "admin.login", "alice", "", json.RawMessage(`{"ip":"1.2.3.4"}`),
		"abc123", "sealkeeper.test", time.Now())
	if err := sink.Send(context.Background(), ev); err != nil {
		t.Fatalf("Send: %v", err)
	}

	got.mu.Lock()
	defer got.mu.Unlock()
	if got.method != http.MethodPost {
		t.Errorf("method = %q, want POST", got.method)
	}
	if got.auth != "Bearer secret-token" {
		t.Errorf("Authorization = %q", got.auth)
	}
	if !strings.Contains(string(got.body), `"event_type":"admin.login"`) {
		t.Errorf("body missing event_type: %s", string(got.body))
	}
}

func TestWebhookSinkSurfacesHTTPErrors(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("nope"))
	}))
	t.Cleanup(srv.Close)
	sink, _ := integrations.BuildSink(integrations.Integration{
		Name:       "bad",
		Kind:       integrations.KindWebhook,
		ConfigJSON: json.RawMessage(`{"url":"` + srv.URL + `"}`),
	}, integrations.TestPolicy)
	err := sink.Send(context.Background(), integrations.NewEvent(0, "x", "", "", nil, "", "", time.Now()))
	if err == nil || !strings.Contains(err.Error(), "HTTP 400") {
		t.Fatalf("err = %v, want HTTP 400", err)
	}
	if strings.Contains(err.Error(), "nope") {
		t.Fatalf("err = %v leaks the remote response body", err)
	}
}

// ----- Splunk envelope ------------------------------------------------------

func TestSplunkSinkBuildsHECEnvelope(t *testing.T) {
	t.Parallel()
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = r.Header.Get("Authorization") + "\n" + string(body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	row := integrations.Integration{
		Name: "splunk-test",
		Kind: integrations.KindSplunk,
		ConfigJSON: json.RawMessage(`{
			"url": "` + srv.URL + `",
			"token": "hec-token",
			"index": "audit",
			"sourcetype": "sk:audit"
		}`),
	}
	sink, err := integrations.BuildSink(row, integrations.TestPolicy)
	if err != nil {
		t.Fatalf("BuildSink: %v", err)
	}
	if err := sink.Send(context.Background(), integrations.NewEvent(7, "admin.login", "alice", "", nil, "", "sealkeeper.test", time.Now())); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.HasPrefix(seen, "Splunk hec-token\n") {
		t.Errorf("Authorization = %q", seen)
	}
	if !strings.Contains(seen, `"sourcetype":"sk:audit"`) || !strings.Contains(seen, `"index":"audit"`) {
		t.Errorf("envelope missing fields: %s", seen)
	}
}

// ----- Syslog sink ----------------------------------------------------------

func TestSyslogSinkWritesRFC5424UDP(t *testing.T) {
	t.Parallel()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	addr := pc.LocalAddr().String()

	row := integrations.Integration{
		Name: "rsys",
		Kind: integrations.KindSyslog,
		ConfigJSON: json.RawMessage(`{
			"address": "` + addr + `",
			"network": "udp",
			"app_name": "sealkeeper-test"
		}`),
	}
	sink, err := integrations.BuildSink(row, integrations.TestPolicy)
	if err != nil {
		t.Fatalf("BuildSink: %v", err)
	}
	ev := integrations.NewEvent(42, "request.rate_limited", "alice@example.test", "", json.RawMessage(`{"dim":"email"}`), "h", "sealkeeper.test", time.Now())
	if err := sink.Send(context.Background(), ev); err != nil {
		t.Fatalf("Send: %v", err)
	}

	buf := make([]byte, 4096)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	got := string(buf[:n])
	if !strings.HasPrefix(got, "<") {
		t.Fatalf("missing PRI prefix: %q", got)
	}
	if !strings.Contains(got, "sealkeeper-test") {
		t.Errorf("missing app name: %q", got)
	}
	if !strings.Contains(got, "request.rate_limited") {
		t.Errorf("missing MSGID: %q", got)
	}
	if !strings.Contains(got, `"event_type":"request.rate_limited"`) {
		t.Errorf("missing JSON body: %q", got)
	}
}

// ----- Dispatcher fan-out --------------------------------------------------

func TestDispatcherFansOutToEnabledOnly(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	ctx := context.Background()

	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	mkRow := func(name string, enabled bool) {
		_, err := repo.Create(ctx, integrations.CreateInputs{
			Name: name, Kind: integrations.KindWebhook, Enabled: enabled,
			ConfigJSON: `{"url":"` + srv.URL + `","timeout_sec":2}`,
		}, nil)
		if err != nil {
			t.Fatalf("Create %q: %v", name, err)
		}
	}
	mkRow("on-1", true)
	mkRow("on-2", true)
	mkRow("off", false)

	d := integrations.NewDispatcher(repo, nil, 8, 2*time.Second).WithNetPolicy(integrations.TestPolicy)
	d.Start(ctx)
	t.Cleanup(d.Stop)

	d.Push(integrations.NewEvent(1, "admin.login", "", "", nil, "", "", time.Now()))

	// Allow workers to fan out.
	for i := 0; i < 50; i++ {
		if hits.Load() >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("hits = %d, want 2 (only enabled rows)", got)
	}
	stats := d.Stats()
	if stats.Delivered != 2 {
		t.Errorf("Delivered = %d, want 2", stats.Delivered)
	}
}

func TestDispatcherDropsOnFullBuffer(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	d := integrations.NewDispatcher(repo, nil, 1, time.Second)
	// Don't Start — the bulk lane stays full so subsequent Pushes drop.
	d.Push(integrations.NewEvent(1, "request.rate_limited", "", "", nil, "", "", time.Now())) // fills buffer
	for i := 0; i < 5; i++ {
		d.Push(integrations.NewEvent(int64(i+2), "request.rate_limited", "", "", nil, "", "", time.Now()))
	}
	st := d.Stats()
	if st.Drops < 5 || st.DropsBulk < 5 || st.DropsSecurity != 0 {
		t.Fatalf("Stats = %+v, want ≥ 5 bulk drops and no security drop", st)
	}
}

func TestTestSinkSyntheticEvent(t *testing.T) {
	t.Parallel()
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	row := integrations.Integration{
		Name: "tester", Kind: integrations.KindWebhook,
		ConfigJSON: json.RawMessage(`{"url":"` + srv.URL + `"}`),
	}
	if err := integrations.TestSink(context.Background(), row, "sealkeeper.test", integrations.TestPolicy); err != nil {
		t.Fatalf("TestSink: %v", err)
	}
	if !strings.Contains(got, `"event_type":"integration.test"`) {
		t.Errorf("body missing test event: %s", got)
	}
}
