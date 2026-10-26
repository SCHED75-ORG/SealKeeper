package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// evalEnv selects eval mode so Load needs no master secret, and points
// the DSN at a throwaway path.
func evalEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SK_MODE", "eval")
	t.Setenv("SK_CONFIG_FILE", "")
	t.Setenv("SK_DATABASE_URL", "sqlite://"+filepath.ToSlash(filepath.Join(t.TempDir(), "sk.db")))
}

// SK-34: malformed values used to fall back to the default silently.
func TestLoad_RejectsMalformedEnv(t *testing.T) {
	cases := map[string]string{
		"SK_RATE_LIMIT_IP_PER_HOUR":     "10/h",
		"SK_DEMO_MODE":                  "enabled",
		"SK_ADMIN_SESSION_IDLE_SECONDS": "5m",
		"SK_ADMIN_SESSION_TTL_SECONDS":  "-1",
		"SK_MAX_LIBRARY_SIZE_MB":        "ten",
		"SK_SMTP_INSECURE_TLS":          "maybe",
	}
	for key, val := range cases {
		t.Run(key, func(t *testing.T) {
			evalEnv(t)
			t.Setenv(key, val)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("Load() err = %v, want an error naming %s", err, key)
			}
		})
	}
}

// The mail language is an instance setting (never the requester's
// Accept-Language); an unsupported value is refused, not ignored.
func TestLoad_MailLanguage(t *testing.T) {
	evalEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MailLanguage != "en" {
		t.Errorf("default MailLanguage = %q, want en", cfg.MailLanguage)
	}
	t.Setenv("SK_MAIL_LANGUAGE", " FR ")
	if cfg, err = Load(); err != nil || cfg.MailLanguage != "fr" {
		t.Errorf("SK_MAIL_LANGUAGE=FR: %q, %v", cfg.MailLanguage, err)
	}
	t.Setenv("SK_MAIL_LANGUAGE", "de")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SK_MAIL_LANGUAGE") {
		t.Errorf("SK_MAIL_LANGUAGE=de: err = %v, want a refusal", err)
	}
}

// An unknown SMTP TLS mode used to load cleanly and only fail at send
// time ("unknown TLS mode"), silently dropping every reveal mail.
func TestLoad_SMTPTLS(t *testing.T) {
	for _, val := range []string{"STARTTLS-only", "tls", "ssl", "none", "true"} {
		t.Run("refuses "+val, func(t *testing.T) {
			evalEnv(t)
			t.Setenv("SK_SMTP_TLS", val)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SK_SMTP_TLS") {
				t.Fatalf("SK_SMTP_TLS=%q: err = %v, want a refusal naming SK_SMTP_TLS", val, err)
			}
		})
	}
	cases := map[string]string{"": "", "auto": "auto", " STARTTLS ": "starttls", "Implicit": "implicit", "disable": "disable"}
	for in, want := range cases {
		t.Run("accepts "+in, func(t *testing.T) {
			evalEnv(t)
			t.Setenv("SK_SMTP_TLS", in)
			cfg, err := Load()
			if err != nil || cfg.SMTPTLS != want {
				t.Fatalf("SK_SMTP_TLS=%q: SMTPTLS = %q, err = %v; want %q, nil", in, cfg.SMTPTLS, err, want)
			}
		})
	}
}

func TestLoad_AdminSessionKnobs(t *testing.T) {
	evalEnv(t)
	t.Setenv("SK_ADMIN_SESSION_TTL_SECONDS", "3600")
	t.Setenv("SK_ADMIN_SESSION_IDLE_SECONDS", "300")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AdminSessionTTL != time.Hour || cfg.AdminSessionIdleTimeout != 5*time.Minute {
		t.Errorf("TTL/idle = %s/%s, want 1h/5m", cfg.AdminSessionTTL, cfg.AdminSessionIdleTimeout)
	}

	t.Setenv("SK_ADMIN_SESSION_IDLE_SECONDS", "7200") // longer than the TTL
	if _, err := Load(); err == nil {
		t.Error("Load accepted an idle timeout longer than the session TTL")
	}
	t.Setenv("SK_ADMIN_SESSION_IDLE_SECONDS", "0")
	if _, err := Load(); err == nil {
		t.Error("Load accepted a zero idle timeout")
	}
}

func TestLoad_DeprecatedKnobs(t *testing.T) {
	evalEnv(t)
	t.Setenv("SK_MAINTENANCE_MODE", "true")
	if _, err := Load(); err == nil {
		t.Fatal("Load accepted SK_MAINTENANCE_MODE=true, which is not implemented")
	}

	t.Setenv("SK_MAINTENANCE_MODE", "false")
	t.Setenv("SK_MAX_ACTIVE_SESSIONS", "10000") // the shipped default: no warning
	t.Setenv("SK_SESSION_TTL_SECONDS", "900")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("Warnings = %v, want none for default values", cfg.Warnings)
	}

	t.Setenv("SK_MAX_ACTIVE_SESSIONS", "50")
	t.Setenv("SK_SESSION_TTL_SECONDS", "300")
	t.Setenv("SK_SWAGGER_UI_ENABLED", "true") // no /api/docs route exists
	if cfg, err = Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Warnings) != 3 {
		t.Errorf("Warnings = %v, want one per ignored knob", cfg.Warnings)
	}
}

// Regression: the handover doc listed `demo` as an SK_MODE value while
// validate refuses it with a message that never mentions the real toggle.
// Demo is SK_DEMO_MODE=true on top of SK_MODE=eval|production; the refusal
// must say so.
func TestLoad_DemoIsAToggleNotAMode(t *testing.T) {
	evalEnv(t)
	t.Setenv("SK_MODE", "demo")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "SK_DEMO_MODE=true") {
		t.Fatalf("Load(SK_MODE=demo) err = %v, want a refusal pointing at SK_DEMO_MODE=true", err)
	}

	t.Setenv("SK_MODE", "eval")
	t.Setenv("SK_DEMO_MODE", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load(SK_MODE=eval, SK_DEMO_MODE=true): %v", err)
	}
	if !cfg.IsDemo() || !cfg.IsEval() {
		t.Errorf("IsDemo=%v IsEval=%v, want both", cfg.IsDemo(), cfg.IsEval())
	}
}

func TestLoad_YAMLUnknownKeyRejected(t *testing.T) {
	evalEnv(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	if err := os.WriteFile(good, []byte("metrics_token: s3cret\nadmin_session_idle_timeout: 10m\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SK_CONFIG_FILE", good)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load(good): %v", err)
	}
	if cfg.MetricsToken != "s3cret" || cfg.AdminSessionIdleTimeout != 10*time.Minute {
		t.Errorf("metrics_token=%q idle=%s, want s3cret / 10m", cfg.MetricsToken, cfg.AdminSessionIdleTimeout)
	}

	typo := filepath.Join(dir, "typo.yaml")
	if err := os.WriteFile(typo, []byte("metric_token: s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SK_CONFIG_FILE", typo)
	if _, err := Load(); err == nil {
		t.Fatal("Load accepted an unknown YAML key (metric_token)")
	}

	empty := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SK_CONFIG_FILE", empty)
	if _, err := Load(); err != nil {
		t.Fatalf("Load(empty file): %v", err)
	}
}

// FR-I.29..34: the retention periods default to the PRD values, are
// configurable, and refuse values that disable expiry or would purge
// security traces before six months.
func TestLoad_Retention(t *testing.T) {
	evalEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := []int{cfg.RetentionRequestTokensDays, cfg.RetentionSessionGraceHours, cfg.RetentionAuditDays,
		cfg.RetentionCapturedMailDays, cfg.RetentionDisabledAdminDays}
	if want := []int{30, 24, 365, 7, 90}; !slices.Equal(got, want) {
		t.Fatalf("retention defaults = %v, want %v", got, want)
	}
	t.Setenv("SK_RETENTION_AUDIT_DAYS", "400")
	if cfg, err = Load(); err != nil || cfg.RetentionAuditDays != 400 {
		t.Fatalf("SK_RETENTION_AUDIT_DAYS=400: %d, %v", cfg.RetentionAuditDays, err)
	}

	for key, val := range map[string]string{
		"SK_RETENTION_AUDIT_DAYS":          "30",
		"SK_RETENTION_REQUEST_TOKENS_DAYS": "0",
		"SK_RETENTION_SESSION_GRACE_HOURS": "-1",
		"SK_RETENTION_CAPTURED_MAIL_DAYS":  "999999",
		"SK_RETENTION_DISABLED_ADMIN_DAYS": "ninety",
	} {
		t.Run(key, func(t *testing.T) {
			evalEnv(t)
			t.Setenv(key, val)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("Load() err = %v, want an error naming %s", err, key)
			}
		})
	}
}
