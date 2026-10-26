package integrations

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ----- Webhook (generic JSON POST) ------------------------------------------

// WebhookConfig is the JSON shape stored in integrations.config_json for
// Kind = "webhook".
type WebhookConfig struct {
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers,omitempty"`
	BearerToken string            `json:"bearer_token,omitempty"`
	BasicUser   string            `json:"basic_user,omitempty"`
	BasicPass   string            `json:"basic_pass,omitempty"`
	TimeoutSec  int               `json:"timeout_sec,omitempty"`
}

type webhookSink struct {
	name string
	cfg  WebhookConfig
	c    *http.Client
}

func newWebhookSink(name string, cfg WebhookConfig, pol NetPolicy) *webhookSink {
	return &webhookSink{name: name, cfg: cfg, c: pol.httpClient(cfg.TimeoutSec)}
}

func (s *webhookSink) Name() string { return s.name }
func (s *webhookSink) Kind() Kind   { return KindWebhook }

func (s *webhookSink) Send(ctx context.Context, ev Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SealKeeper/audit-dispatcher")
	for k, v := range s.cfg.Headers {
		req.Header.Set(k, v)
	}
	switch {
	case s.cfg.BearerToken != "":
		req.Header.Set("Authorization", "Bearer "+s.cfg.BearerToken)
	case s.cfg.BasicUser != "":
		creds := s.cfg.BasicUser + ":" + s.cfg.BasicPass
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	}
	return doRequest(s.c, req, "webhook")
}

// ----- Splunk HEC -----------------------------------------------------------

// SplunkConfig stores the HEC endpoint + token. URL must point to the
// /services/collector path of the HEC instance.
type SplunkConfig struct {
	URL         string `json:"url"`
	Token       string `json:"token"`
	Index       string `json:"index,omitempty"`
	Sourcetype  string `json:"sourcetype,omitempty"`
	Source      string `json:"source,omitempty"`
	TimeoutSec  int    `json:"timeout_sec,omitempty"`
	InsecureTLS bool   `json:"insecure_tls,omitempty"`
}

type splunkSink struct {
	name string
	cfg  SplunkConfig
	c    *http.Client
}

func newSplunkSink(name string, cfg SplunkConfig, pol NetPolicy) *splunkSink {
	return &splunkSink{name: name, cfg: cfg, c: pol.httpClient(cfg.TimeoutSec)}
}

func (s *splunkSink) Name() string { return s.name }
func (s *splunkSink) Kind() Kind   { return KindSplunk }

// Splunk HEC envelope per https://docs.splunk.com/Documentation/Splunk/latest/Data/FormateventsforHTTPEventCollector
type splunkEnvelope struct {
	Time       float64 `json:"time"`
	Index      string  `json:"index,omitempty"`
	Sourcetype string  `json:"sourcetype,omitempty"`
	Source     string  `json:"source,omitempty"`
	Event      Event   `json:"event"`
}

func (s *splunkSink) Send(ctx context.Context, ev Event) error {
	env := splunkEnvelope{
		Time:       float64(ev.OccurredAt.UTC().UnixNano()) / 1e9,
		Index:      s.cfg.Index,
		Sourcetype: defaultStr(s.cfg.Sourcetype, "sealkeeper:audit"),
		Source:     defaultStr(s.cfg.Source, "sealkeeper"),
		Event:      ev,
	}
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Splunk "+s.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	return doRequest(s.c, req, "splunk")
}

// ----- Microsoft Sentinel (Log Analytics Data Collector API) ----------------

// SentinelConfig — workspace_id + shared_key. Uses the legacy Data
// Collector API which is HMAC-SHA256-signed; the new Logs Ingestion API
// (DCR-based) lands when v0.2 adds Azure SDK support.
type SentinelConfig struct {
	WorkspaceID string `json:"workspace_id"`
	SharedKey   string `json:"shared_key"` // base64 — the workspace primary or secondary key
	LogType     string `json:"log_type"`   // table suffix; ends up as <LogType>_CL
	TimeoutSec  int    `json:"timeout_sec,omitempty"`
}

type sentinelSink struct {
	name string
	cfg  SentinelConfig
	c    *http.Client
	now  func() time.Time // testable
}

func newSentinelSink(name string, cfg SentinelConfig, pol NetPolicy) *sentinelSink {
	return &sentinelSink{name: name, cfg: cfg, c: pol.httpClient(cfg.TimeoutSec), now: time.Now}
}

func (s *sentinelSink) Name() string { return s.name }
func (s *sentinelSink) Kind() Kind   { return KindSentinel }

func (s *sentinelSink) Send(ctx context.Context, ev Event) error {
	body, err := json.Marshal([]Event{ev})
	if err != nil {
		return err
	}
	rfcDate := s.now().UTC().Format(http.TimeFormat)
	logType := defaultStr(s.cfg.LogType, "SealKeeperAudit")

	stringToSign := fmt.Sprintf("POST\n%d\napplication/json\nx-ms-date:%s\n/api/logs",
		len(body), rfcDate)
	decodedKey, err := base64.StdEncoding.DecodeString(s.cfg.SharedKey)
	if err != nil {
		return fmt.Errorf("sentinel: shared_key not base64: %w", err)
	}
	mac := hmac.New(sha256.New, decodedKey)
	_, _ = mac.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if !sentinelWorkspaceRe.MatchString(s.cfg.WorkspaceID) {
		return fmt.Errorf("%w: sentinel: workspace_id must be a GUID", ErrInvalidConfig)
	}
	endpoint := fmt.Sprintf("https://%s.ods.opinsights.azure.com/api/logs?api-version=2016-04-01", s.cfg.WorkspaceID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Log-Type", logType)
	req.Header.Set("x-ms-date", rfcDate)
	req.Header.Set("Authorization", fmt.Sprintf("SharedKey %s:%s", s.cfg.WorkspaceID, signature))
	req.Header.Set("time-generated-field", "occurred_at")
	return doRequest(s.c, req, "sentinel")
}

// ----- Elasticsearch (_bulk) ------------------------------------------------

// ElasticConfig points at the Elasticsearch host + index. We use the _bulk
// endpoint with a single index action so it works the same against a
// single-document POST and a future batched dispatcher.
type ElasticConfig struct {
	URL         string `json:"url"`   // base host, e.g. https://es.example.com
	Index       string `json:"index"` // datastream or index name
	APIKey      string `json:"api_key,omitempty"`
	BearerToken string `json:"bearer_token,omitempty"`
	TimeoutSec  int    `json:"timeout_sec,omitempty"`
}

type elasticSink struct {
	name string
	cfg  ElasticConfig
	c    *http.Client
}

func newElasticSink(name string, cfg ElasticConfig, pol NetPolicy) *elasticSink {
	return &elasticSink{name: name, cfg: cfg, c: pol.httpClient(cfg.TimeoutSec)}
}

func (s *elasticSink) Name() string { return s.name }
func (s *elasticSink) Kind() Kind   { return KindElastic }

func (s *elasticSink) Send(ctx context.Context, ev Event) error {
	index := defaultStr(s.cfg.Index, "sealkeeper-audit")
	action, err := json.Marshal(map[string]any{
		"index": map[string]any{"_index": index},
	})
	if err != nil {
		return err
	}
	doc, err := json.Marshal(elasticDoc(ev))
	if err != nil {
		return err
	}
	// _bulk wants action\ndoc\n. We assemble into a fresh buffer so gocritic
	// doesn't flag the action-append as an unassigned in-place mutation.
	body := make([]byte, 0, len(action)+len(doc)+2)
	body = append(body, action...)
	body = append(body, '\n')
	body = append(body, doc...)
	body = append(body, '\n')

	endpoint := strings.TrimRight(s.cfg.URL, "/") + "/_bulk"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	switch {
	case s.cfg.APIKey != "":
		req.Header.Set("Authorization", "ApiKey "+s.cfg.APIKey)
	case s.cfg.BearerToken != "":
		req.Header.Set("Authorization", "Bearer "+s.cfg.BearerToken)
	}
	return doRequest(s.c, req, "elastic")
}

// elasticDoc maps Event to ECS-flavoured fields (FR-C.85 mentions Elastic
// (ECS)). Keep it minimal: @timestamp + nested event fields.
func elasticDoc(ev Event) map[string]any {
	return map[string]any{
		"@timestamp": ev.OccurredAt.UTC().Format(time.RFC3339Nano),
		"event": map[string]any{
			"kind":     "event",
			"category": []string{"authentication", "process"},
			"action":   ev.EventType,
			"id":       fmt.Sprintf("%d", ev.SequenceNo),
			"hash":     ev.EntryHash,
		},
		"user":     map[string]any{"name": ev.Actor},
		"target":   ev.Target,
		"details":  ev.Details,
		"source":   ev.Source,
		"observer": map[string]any{"name": ev.InstanceDomain},
	}
}

// ----- shared helpers -------------------------------------------------------

// doRequest performs the call and maps any non-2xx answer to an error that
// carries the status code only. The response body is never surfaced: the
// error text reaches the admin UI and the audit log (and from there every
// other sink), so echoing it would turn a sink into an SSRF read primitive.
// Redirects are not followed (see NetPolicy.httpClient) and count as errors.
func doRequest(c *http.Client, req *http.Request, label string) error {
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("%s: do: %w", label, err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Drain (bounded) so keepalive works, without retaining anything.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s: HTTP %d", label, resp.StatusCode)
	}
	return nil
}

// closeIdle releases pooled connections of a sink's HTTP client when the
// dispatcher retires it (config change, deletion).
func closeIdle(c *http.Client) {
	if c != nil {
		c.CloseIdleConnections()
	}
}

func (s *webhookSink) closeIdle()  { closeIdle(s.c) }
func (s *splunkSink) closeIdle()   { closeIdle(s.c) }
func (s *sentinelSink) closeIdle() { closeIdle(s.c) }
func (s *elasticSink) closeIdle()  { closeIdle(s.c) }

// sentinelWorkspaceRe matches a Log Analytics workspace ID (a GUID). The ID
// is spliced into the ingestion hostname, so anything else ("evil.host/x?")
// would redirect the signed request to an arbitrary host.
var sentinelWorkspaceRe = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// validateHTTPURL accepts absolute http(s) URLs with a host and no userinfo.
func validateHTTPURL(raw, label string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("%w: %s: url: %s", ErrInvalidConfig, label, err.Error())
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: %s: url scheme must be http or https", ErrInvalidConfig, label)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("%w: %s: url has no host", ErrInvalidConfig, label)
	}
	if u.User != nil {
		return fmt.Errorf("%w: %s: credentials in url are not allowed (use the token fields)", ErrInvalidConfig, label)
	}
	return nil
}

func defaultStr(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
