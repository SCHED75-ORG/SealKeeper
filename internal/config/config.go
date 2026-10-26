// Package config loads SealKeeper runtime configuration from environment
// variables, an optional YAML file and defaults.
//
// Precedence (highest first): CLI flags handled in cmd/sealkeeper → SK_*
// environment variables → fields in SK_CONFIG_FILE → defaults defined here.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
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

	MaxLibrarySizeMB        int           `yaml:"max_library_size_mb"`
	MaxActiveSessions       int           `yaml:"max_active_sessions"`
	SessionTTL              time.Duration `yaml:"session_ttl"`
	AdminSessionTTL         time.Duration `yaml:"admin_session_ttl"`
	AdminSessionIdleTimeout time.Duration `yaml:"admin_session_idle_timeout"`

	SwaggerUIEnabled bool `yaml:"swagger_ui_enabled"`
	DemoMode         bool `yaml:"demo_mode"`
	MaintenanceMode  bool `yaml:"maintenance_mode"`

	// WebDir is the directory served at /static/*. The reveal page <script
	// src="/static/sealkeeper-generation.umd.js"> lives in there. Defaults
	// to the best-existing path among /app/web (in-image), ./web/dist
	// (developer build) and ./web (Docker copy target).
	WebDir string `yaml:"web_dir"`

	// InstanceDomain is the bare hostname used in the From: address and the
	// reveal-mail Message-ID. Derived from SK_BASE_URL when empty.
	InstanceDomain string `yaml:"instance_domain"`

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

	applyEnv(&cfg)

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

	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func applyEnv(cfg *Config) {
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
	getString(&cfg.WebDir, "SK_WEB_DIR")
	getString(&cfg.InstanceDomain, "SK_INSTANCE_DOMAIN")
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
}

func mergeYAMLFile(cfg *Config, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(b, cfg)
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

func getInt(dst *int, key string) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err == nil {
		*dst = n
	}
}

func getBool(dst *bool, key string) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		*dst = true
	case "0", "false", "no", "off":
		*dst = false
	}
}

func getDurationFromSeconds(dst *time.Duration, key string) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err == nil {
		*dst = time.Duration(n) * time.Second
	}
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
