// Package config loads SealKeeper runtime configuration from environment
// variables, an optional YAML file and defaults.
//
// Precedence (highest first): CLI flags handled in cmd/sealkeeper → SK_*
// environment variables → fields in SK_CONFIG_FILE → defaults defined here.
package config

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Mode is the high-level operating mode of the SealKeeper instance.
type Mode string

const (
	ModeProduction Mode = "production"
	ModeEval       Mode = "eval"
)

// Config holds the resolved runtime configuration.
type Config struct {
	Mode    Mode   `yaml:"mode"`
	BaseURL string `yaml:"base_url"`
	Listen  string `yaml:"listen"`

	DatabaseURL string `yaml:"database_url"`

	MasterSecret string `yaml:"master_secret"`

	LogFormat string `yaml:"log_format"`
	LogLevel  string `yaml:"log_level"`

	TrustedProxyCIDRs []string `yaml:"trusted_proxy_cidrs"`

	MetricsToken string `yaml:"metrics_token"`

	// MaxLibrarySizeMB caps one /admin/libraries upload (D-D.22).
	MaxLibrarySizeMB int `yaml:"max_library_size_mb"`
	// AdminSessionTTL and AdminSessionIdleTimeout are the absolute and
	// idle lifetimes of an admin console session (FR-C.6..10).
	AdminSessionTTL         time.Duration `yaml:"admin_session_ttl"`
	AdminSessionIdleTimeout time.Duration `yaml:"admin_session_idle_timeout"`

	// Deprecated: not implemented. A non-default value only produces a
	// startup warning (see Warnings). User session lifetime is set per
	// policy in /admin/policies.
	MaxActiveSessions int           `yaml:"max_active_sessions"`
	SessionTTL        time.Duration `yaml:"session_ttl"`
	// Deprecated: maintenance mode is not implemented; true is refused at
	// startup rather than silently ignored.
	MaintenanceMode bool `yaml:"maintenance_mode"`

	SwaggerUIEnabled bool `yaml:"swagger_ui_enabled"`
	DemoMode         bool `yaml:"demo_mode"`

	// Warnings lists non-fatal configuration problems (ignored knobs) for
	// the caller to log at startup.
	Warnings []string `yaml:"-"`

	// IntegrationsAllowPrivate lets outbound SIEM sinks (webhook, Splunk,
	// Sentinel, Elastic, syslog) dial RFC 1918 / ULA / CGNAT addresses.
	// Loopback, link-local (cloud metadata), unspecified and multicast
	// destinations stay refused regardless. Default false (SSRF guard).
	IntegrationsAllowPrivate bool `yaml:"integrations_allow_private"`

	// WebDir is the directory served at /static/*. The reveal page <script
	// src="/static/sealkeeper-generation.umd.js"> lives in there. Defaults
	// to the best-existing path among /app/web (in-image), ./web/dist
	// (developer build) and ./web (Docker copy target).
	WebDir string `yaml:"web_dir"`

	// InstanceDomain is the bare hostname used in the From: address and the
	// reveal-mail Message-ID. Derived from SK_BASE_URL when empty.
	InstanceDomain string `yaml:"instance_domain"`

	// MailLanguage picks the reveal and post-consultation mail templates
	// ("en" or "fr"). It is an instance setting on purpose: the request
	// form is public, so the requester's Accept-Language must not choose
	// what the target mailbox receives.
	MailLanguage string `yaml:"mail_language"`

	// Rate limits (FR-B.11..13). 0 disables the corresponding limiter.
	RateLimitEmailPerHour int `yaml:"rate_limit_email_per_hour"`
	RateLimitIPPerHour    int `yaml:"rate_limit_ip_per_hour"`

	// LibrariesDir is the on-disk directory backing /admin/libraries
	// uploads. Defaults to ./data/libraries relative to the binary's cwd.
	LibrariesDir string `yaml:"libraries_dir"`

	// SMTP relay (FR-B.14..19). When SMTPHost is empty the sender falls back
	// to in-memory capture in eval mode and to a logged no-op in production.
	SMTPHost        string        `yaml:"smtp_host"`
	SMTPPort        int           `yaml:"smtp_port"`
	SMTPUsername    string        `yaml:"smtp_username"`
	SMTPPassword    string        `yaml:"smtp_password"`
	SMTPFrom        string        `yaml:"smtp_from"`
	SMTPTLS         string        `yaml:"smtp_tls"` // auto | starttls | implicit | disable
	SMTPTimeout     time.Duration `yaml:"smtp_timeout"`
	SMTPInsecureTLS bool          `yaml:"smtp_insecure_tls"`
	SMTPServerName  string        `yaml:"smtp_server_name"`
}

// Defaults returns the baseline configuration before any override.
func Defaults() Config {
	return Config{
		Mode:                    ModeProduction,
		Listen:                  ":8443",
		LogFormat:               "json",
		LogLevel:                "info",
		MaxLibrarySizeMB:        10,
		MaxActiveSessions:       10000,
		SessionTTL:              15 * time.Minute,
		AdminSessionTTL:         8 * time.Hour,
		AdminSessionIdleTimeout: 30 * time.Minute,
		SwaggerUIEnabled:        false,
		DemoMode:                false,
		MaintenanceMode:         false,
		RateLimitEmailPerHour:   3,  // FR-B.11
		RateLimitIPPerHour:      10, // FR-B.12
		MailLanguage:            "en",
	}
}

// Load resolves configuration by applying the precedence chain.
//
// In eval mode any missing master secret and DSN are auto-provisioned so the
// 5-second docker run experience (FR-H.11..19) works with zero configuration.
func Load() (Config, error) {
	cfg := Defaults()

	if path := os.Getenv("SK_CONFIG_FILE"); path != "" {
		if err := mergeYAMLFile(&cfg, path); err != nil {
			return cfg, fmt.Errorf("config file %q: %w", path, err)
		}
	}

	if err := applyEnv(&cfg); err != nil {
		return cfg, err
	}

	if cfg.Mode == ModeEval {
		if cfg.MasterSecret == "" {
			b := make([]byte, 32)
			if _, err := rand.Read(b); err != nil {
				return cfg, fmt.Errorf("eval: cannot generate master secret: %w", err)
			}
			cfg.MasterSecret = base64.StdEncoding.EncodeToString(b)
		}
		if cfg.DatabaseURL == "" {
			cfg.DatabaseURL = "sqlite:///data/sealkeeper.db"
		}
		if cfg.BaseURL == "" {
			cfg.BaseURL = "http://localhost:8443"
		}
	}

	if cfg.WebDir == "" {
		cfg.WebDir = autodetectWebDir()
	}
	if cfg.InstanceDomain == "" {
		cfg.InstanceDomain = deriveInstanceDomain(cfg.BaseURL)
	}
	if cfg.LibrariesDir == "" {
		cfg.LibrariesDir = "data/libraries"
	}
	cfg.MailLanguage = strings.ToLower(strings.TrimSpace(cfg.MailLanguage))

	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	cfg.Warnings = cfg.deprecationWarnings()
	return cfg, nil
}

// deprecationWarnings reports knobs that are accepted for compatibility
// but have no effect, when they are set away from their default.
func (c Config) deprecationWarnings() []string {
	d := Defaults()
	var out []string
	if c.MaxActiveSessions != d.MaxActiveSessions {
		out = append(out, "SK_MAX_ACTIVE_SESSIONS / max_active_sessions is not implemented and is ignored")
	}
	if c.SessionTTL != d.SessionTTL {
		out = append(out, "SK_SESSION_TTL_SECONDS / session_ttl is ignored: the user session lifetime is set per policy in /admin/policies")
	}
	return out
}

// applyEnv overlays SK_* environment variables. A malformed number,
// boolean or duration is an error: falling back to the default would
// silently run with a setting the operator did not choose.
func applyEnv(cfg *Config) error {
	var errs []error
	getInt := func(dst *int, key string) { errs = append(errs, parseIntEnv(dst, key)) }
	getBool := func(dst *bool, key string) { errs = append(errs, parseBoolEnv(dst, key)) }
	getDurationFromSeconds := func(dst *time.Duration, key string) {
		errs = append(errs, parseSecondsEnv(dst, key))
	}

	if v, ok := os.LookupEnv("SK_MODE"); ok {
		cfg.Mode = Mode(strings.ToLower(strings.TrimSpace(v)))
	}
	getString(&cfg.BaseURL, "SK_BASE_URL")
	getString(&cfg.Listen, "SK_HTTP_LISTEN")
	getString(&cfg.DatabaseURL, "SK_DATABASE_URL")
	getString(&cfg.MasterSecret, "SK_MASTER_SECRET")
	getString(&cfg.LogFormat, "SK_LOG_FORMAT")
	getString(&cfg.LogLevel, "SK_LOG_LEVEL")
	getString(&cfg.MetricsToken, "SK_METRICS_TOKEN")

	if v, ok := os.LookupEnv("SK_TRUSTED_PROXY_CIDRS"); ok {
		cfg.TrustedProxyCIDRs = splitCSV(v)
	}

	getInt(&cfg.MaxLibrarySizeMB, "SK_MAX_LIBRARY_SIZE_MB")
	getInt(&cfg.MaxActiveSessions, "SK_MAX_ACTIVE_SESSIONS")

	getDurationFromSeconds(&cfg.SessionTTL, "SK_SESSION_TTL_SECONDS")
	getDurationFromSeconds(&cfg.AdminSessionTTL, "SK_ADMIN_SESSION_TTL_SECONDS")
	getDurationFromSeconds(&cfg.AdminSessionIdleTimeout, "SK_ADMIN_SESSION_IDLE_SECONDS")

	getBool(&cfg.SwaggerUIEnabled, "SK_SWAGGER_UI_ENABLED")
	getBool(&cfg.DemoMode, "SK_DEMO_MODE")
	getBool(&cfg.MaintenanceMode, "SK_MAINTENANCE_MODE")
	getBool(&cfg.IntegrationsAllowPrivate, "SK_INTEGRATIONS_ALLOW_PRIVATE")
	getString(&cfg.WebDir, "SK_WEB_DIR")
	getString(&cfg.InstanceDomain, "SK_INSTANCE_DOMAIN")
	getString(&cfg.MailLanguage, "SK_MAIL_LANGUAGE")
	getInt(&cfg.RateLimitEmailPerHour, "SK_RATE_LIMIT_EMAIL_PER_HOUR")
	getInt(&cfg.RateLimitIPPerHour, "SK_RATE_LIMIT_IP_PER_HOUR")
	getString(&cfg.LibrariesDir, "SK_LIBRARIES_DIR")
	getString(&cfg.SMTPHost, "SK_SMTP_HOST")
	getInt(&cfg.SMTPPort, "SK_SMTP_PORT")
	getString(&cfg.SMTPUsername, "SK_SMTP_USERNAME")
	getString(&cfg.SMTPPassword, "SK_SMTP_PASSWORD")
	getString(&cfg.SMTPFrom, "SK_SMTP_FROM")
	getString(&cfg.SMTPTLS, "SK_SMTP_TLS")
	getDurationFromSeconds(&cfg.SMTPTimeout, "SK_SMTP_TIMEOUT_SECONDS")
	getBool(&cfg.SMTPInsecureTLS, "SK_SMTP_INSECURE_TLS")
	getString(&cfg.SMTPServerName, "SK_SMTP_SERVER_NAME")
	return errors.Join(errs...)
}

// mergeYAMLFile overlays the YAML file onto cfg. Unknown keys are an
// error, so a typo such as `metric_token:` cannot silently leave the
// setting at its default.
func mergeYAMLFile(cfg *Config, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func (c Config) validate() error {
	switch c.Mode {
	case ModeProduction, ModeEval:
	default:
		return fmt.Errorf("invalid SK_MODE %q (want %q or %q)", c.Mode, ModeProduction, ModeEval)
	}

	if c.Mode == ModeProduction {
		if c.MasterSecret == "" {
			return errors.New("SK_MASTER_SECRET is required in production mode")
		}
		if err := checkMasterSecret(c.MasterSecret); err != nil {
			return err
		}
		if c.BaseURL == "" {
			return errors.New("SK_BASE_URL is required in production mode")
		}
		if c.DatabaseURL == "" {
			return errors.New("SK_DATABASE_URL is required in production mode")
		}
	}

	if !strings.HasPrefix(c.Listen, ":") && !strings.Contains(c.Listen, ":") {
		return fmt.Errorf("SK_HTTP_LISTEN must include a port, got %q", c.Listen)
	}

	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("invalid SK_LOG_LEVEL %q", c.LogLevel)
	}
	switch c.LogFormat {
	case "json", "text":
	default:
		return fmt.Errorf("invalid SK_LOG_FORMAT %q", c.LogFormat)
	}
	if _, err := c.TrustedProxyPrefixes(); err != nil {
		return err
	}
	// Keep in sync with mailtemplates.SupportedLanguages.
	switch c.MailLanguage {
	case "en", "fr":
	default:
		return fmt.Errorf("invalid SK_MAIL_LANGUAGE %q (want \"en\" or \"fr\")", c.MailLanguage)
	}
	return c.validateLimits()
}

// validateLimits checks the numeric knobs. Durations have a one-minute
// floor, which also catches a YAML duration written as a bare integer
// (read as nanoseconds).
func (c Config) validateLimits() error {
	if c.AdminSessionTTL < time.Minute {
		return fmt.Errorf("admin session TTL (SK_ADMIN_SESSION_TTL_SECONDS) must be at least 60s, got %s", c.AdminSessionTTL)
	}
	if c.AdminSessionIdleTimeout < time.Minute || c.AdminSessionIdleTimeout > c.AdminSessionTTL {
		return fmt.Errorf("admin idle timeout (SK_ADMIN_SESSION_IDLE_SECONDS) must be between 60s and the session TTL (%s), got %s",
			c.AdminSessionTTL, c.AdminSessionIdleTimeout)
	}
	if c.MaxLibrarySizeMB < 1 || c.MaxLibrarySizeMB > 1024 {
		return fmt.Errorf("SK_MAX_LIBRARY_SIZE_MB must be between 1 and 1024, got %d", c.MaxLibrarySizeMB)
	}
	if c.MaintenanceMode {
		return errors.New("SK_MAINTENANCE_MODE=true is not implemented; unset it (the instance would otherwise keep serving)")
	}
	for key, v := range map[string]int{
		"SK_RATE_LIMIT_EMAIL_PER_HOUR": c.RateLimitEmailPerHour,
		"SK_RATE_LIMIT_IP_PER_HOUR":    c.RateLimitIPPerHour,
		"SK_MAX_ACTIVE_SESSIONS":       c.MaxActiveSessions,
	} {
		if v < 0 {
			return fmt.Errorf("%s must not be negative, got %d", key, v)
		}
	}
	if c.SMTPPort < 0 || c.SMTPPort > 65535 {
		return fmt.Errorf("SK_SMTP_PORT must be a TCP port, got %d", c.SMTPPort)
	}
	if c.SMTPTimeout < 0 {
		return fmt.Errorf("SK_SMTP_TIMEOUT_SECONDS must not be negative, got %s", c.SMTPTimeout)
	}
	return nil
}

// checkMasterSecret refuses master secrets that would make the at-rest
// encryption (TOTP seeds, recovery codes, SMTP password) worthless: the
// placeholders shipped in examples, and short values. Any string used to
// be accepted and hashed into a key, so a copied example was a public key.
// Passphrases of 32+ characters stay accepted: existing installs derived
// their key from them and rejecting them would orphan the ciphertexts.
func checkMasterSecret(secret string) error {
	const hint = "SK_MASTER_SECRET must be 32 random bytes, base64-encoded (openssl rand -base64 32)"
	lower := strings.ToLower(secret)
	for _, placeholder := range []string{"replace_me", "replace-me", "changeme", "change_me", "change-me", "example"} {
		if strings.Contains(lower, placeholder) {
			return fmt.Errorf("SK_MASTER_SECRET looks like a placeholder; %s", hint)
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := enc.DecodeString(secret); err == nil && len(raw) == 32 {
			return nil
		}
	}
	if len(secret) < 32 {
		return errors.New(hint)
	}
	return nil
}

// TrustedProxyPrefixes parses TrustedProxyCIDRs (FR-H.42). A bare IP is
// accepted as a single-host prefix. Empty entries are skipped.
func (c Config) TrustedProxyPrefixes() ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(c.TrustedProxyCIDRs))
	for _, raw := range c.TrustedProxyCIDRs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "/") {
			addr, err := netip.ParseAddr(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid SK_TRUSTED_PROXY_CIDRS entry %q: %w", raw, err)
			}
			out = append(out, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid SK_TRUSTED_PROXY_CIDRS entry %q: %w", raw, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// IsEval reports whether the instance runs in evaluation mode.
func (c Config) IsEval() bool { return c.Mode == ModeEval }

// IsDemo reports whether the instance runs as a public demo (FR-H.78..81).
// Demo mode is orthogonal to eval — it can be turned on independently
// in any deployment.
func (c Config) IsDemo() bool { return c.DemoMode }

// ----- helpers --------------------------------------------------------------

func getString(dst *string, key string) {
	if v, ok := os.LookupEnv(key); ok {
		*dst = v
	}
}

func parseIntEnv(dst *int, key string) error {
	// An empty value counts as unset (e.g. `SK_SMTP_PORT=` in a .env file).
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return fmt.Errorf("%s=%q is not an integer", key, v)
	}
	*dst = n
	return nil
}

func parseBoolEnv(dst *bool, key string) error {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		*dst = true
	case "0", "false", "no", "off":
		*dst = false
	default:
		return fmt.Errorf("%s=%q is not a boolean (true/false, 1/0, yes/no, on/off)", key, v)
	}
	return nil
}

func parseSecondsEnv(dst *time.Duration, key string) error {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return fmt.Errorf("%s=%q is not a non-negative number of seconds", key, v)
	}
	*dst = time.Duration(n) * time.Second
	return nil
}

// autodetectWebDir picks the first existing path among the common locations
// the build pipeline writes the JS bundle to.
func autodetectWebDir() string {
	candidates := []string{"/app/web", "web/dist", "./web/dist", "web", "./web"}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	return ""
}

// deriveInstanceDomain extracts the bare hostname from a URL like
// https://sealkeeper.example.com → "sealkeeper.example.com". Falls back to
// "localhost" so eval mode keeps a valid From: address.
func deriveInstanceDomain(baseURL string) string {
	if baseURL == "" {
		return "localhost"
	}
	if u, err := url.Parse(baseURL); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return "localhost"
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
