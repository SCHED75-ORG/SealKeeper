package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// Event is the canonical shape forwarded to every Sink. It mirrors the
// audit_log row plus instance metadata that helps downstream SIEMs route
// the event correctly.
type Event struct {
	SequenceNo     int64           `json:"sequence_no"`
	OccurredAt     time.Time       `json:"occurred_at"`
	EventType      string          `json:"event_type"`
	Actor          string          `json:"actor,omitempty"`
	Target         string          `json:"target,omitempty"`
	Details        json.RawMessage `json:"details,omitempty"`
	EntryHash      string          `json:"entry_hash,omitempty"`
	InstanceDomain string          `json:"instance_domain"`
	Source         string          `json:"source"` // always "sealkeeper"
}

// NewEvent builds an Event with the common envelope fields populated.
func NewEvent(seq int64, eventType, actor, target string, details json.RawMessage,
	entryHash, instance string, occurred time.Time) Event {
	return Event{
		SequenceNo:     seq,
		OccurredAt:     occurred.UTC(),
		EventType:      eventType,
		Actor:          actor,
		Target:         target,
		Details:        details,
		EntryHash:      entryHash,
		InstanceDomain: instance,
		Source:         "sealkeeper",
	}
}

// Sink is the only interface the dispatcher cares about.
type Sink interface {
	Name() string
	Kind() Kind
	Send(ctx context.Context, ev Event) error
}

// BuildSink returns a Sink for the given Integration row. Every network
// connection the sink opens is checked against `pol` (SSRF guard). Returns
// ErrInvalidKind for unknown kinds and ErrInvalidConfig when the row's
// config cannot be parsed, fails validation, or could not be decrypted.
func BuildSink(row Integration, pol NetPolicy) (Sink, error) {
	if row.ConfigErr != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidConfig, row.ConfigErr.Error())
	}
	if err := validateKindConfig(row.Kind, row.ConfigJSON, pol); err != nil {
		return nil, err
	}
	switch row.Kind {
	case KindWebhook:
		var cfg WebhookConfig
		_ = unmarshalConfig(row.ConfigJSON, &cfg) // validated above
		return newWebhookSink(row.Name, cfg, pol), nil
	case KindSplunk:
		var cfg SplunkConfig
		_ = unmarshalConfig(row.ConfigJSON, &cfg)
		return newSplunkSink(row.Name, cfg, pol), nil
	case KindSentinel:
		var cfg SentinelConfig
		_ = unmarshalConfig(row.ConfigJSON, &cfg)
		return newSentinelSink(row.Name, cfg, pol), nil
	case KindElastic:
		var cfg ElasticConfig
		_ = unmarshalConfig(row.ConfigJSON, &cfg)
		return newElasticSink(row.Name, cfg, pol), nil
	case KindSyslog:
		var cfg SyslogConfig
		_ = unmarshalConfig(row.ConfigJSON, &cfg)
		return newSyslogSink(row.Name, cfg, pol), nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrInvalidKind, row.Kind)
	}
}

// validateKindConfig parses `raw` into the kind's config struct and checks
// the fields that steer where the sink connects: http(s) URL with a host,
// Sentinel workspace GUID, syslog host:port + network. HTTP sinks need an
// https URL unless pol.AllowPlainHTTP (eval mode). Run at Create and again
// at BuildSink so rows stored before the check cannot bypass it.
func validateKindConfig(kind Kind, raw json.RawMessage, pol NetPolicy) error {
	switch kind {
	case KindWebhook:
		var cfg WebhookConfig
		if err := unmarshalConfig(raw, &cfg); err != nil {
			return err
		}
		return validateHTTPURL(cfg.URL, "webhook", pol.AllowPlainHTTP)
	case KindSplunk:
		return validateSplunkConfig(raw, pol)
	case KindSentinel:
		return validateSentinelConfig(raw)
	case KindElastic:
		var cfg ElasticConfig
		if err := unmarshalConfig(raw, &cfg); err != nil {
			return err
		}
		return validateHTTPURL(cfg.URL, "elastic", pol.AllowPlainHTTP)
	case KindSyslog:
		return validateSyslogConfig(raw)
	default:
		return fmt.Errorf("%w: %q", ErrInvalidKind, kind)
	}
}

// validateSplunkConfig refuses insecure_tls and checks the HEC URL.
func validateSplunkConfig(raw json.RawMessage, pol NetPolicy) error {
	var cfg SplunkConfig
	if err := unmarshalConfig(raw, &cfg); err != nil {
		return err
	}
	if cfg.InsecureTLS {
		// Never honoured: refuse rather than let the operator believe
		// certificate verification is off.
		return fmt.Errorf("%w: splunk: insecure_tls is not supported (certificates are always verified)", ErrInvalidConfig)
	}
	return validateHTTPURL(cfg.URL, "splunk", pol.AllowPlainHTTP)
}

// validateSentinelConfig requires the workspace ID to be a GUID.
func validateSentinelConfig(raw json.RawMessage) error {
	var cfg SentinelConfig
	if err := unmarshalConfig(raw, &cfg); err != nil {
		return err
	}
	if !sentinelWorkspaceRe.MatchString(cfg.WorkspaceID) {
		return fmt.Errorf("%w: sentinel: workspace_id must be a GUID", ErrInvalidConfig)
	}
	return nil
}

// validateSyslogConfig requires a host:port address and a udp/tcp (or
// empty) network.
func validateSyslogConfig(raw json.RawMessage) error {
	var cfg SyslogConfig
	if err := unmarshalConfig(raw, &cfg); err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(cfg.Address))
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("%w: syslog: address must be host:port", ErrInvalidConfig)
	}
	if cfg.Network != "" && cfg.Network != "udp" && cfg.Network != "tcp" {
		return fmt.Errorf("%w: syslog: network must be udp or tcp", ErrInvalidConfig)
	}
	return nil
}

func unmarshalConfig(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidConfig, err.Error())
	}
	return nil
}
