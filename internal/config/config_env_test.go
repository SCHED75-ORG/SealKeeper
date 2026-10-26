package config

import (
	"os"
	"path/filepath"
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
	if cfg, err = Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Warnings) != 2 {
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
