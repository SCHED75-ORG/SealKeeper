package config

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestTrustedProxyPrefixes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      []string
		want    int
		wantErr bool
	}{
		{name: "empty", in: nil, want: 0},
		{name: "cidrs and bare ip", in: []string{"172.16.0.0/12", " 127.0.0.1 ", "fd00::/8", ""}, want: 3},
		{name: "garbage", in: []string{"not-a-cidr"}, wantErr: true},
		{name: "bad mask", in: []string{"10.0.0.0/33"}, wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := Config{TrustedProxyCIDRs: c.in}.TrustedProxyPrefixes()
			if c.wantErr {
				if err == nil {
					t.Fatalf("want error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != c.want {
				t.Errorf("len = %d, want %d", len(got), c.want)
			}
		})
	}
}

func TestValidate_RejectsBadTrustedProxy(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Mode = ModeEval
	cfg.TrustedProxyCIDRs = []string{"nope"}
	if err := cfg.validate(); err == nil {
		t.Fatal("validate accepted a malformed SK_TRUSTED_PROXY_CIDRS entry")
	}
}

// Regression: any string was accepted as the production master secret,
// including the REPLACE_ME placeholder shipped in k8s/secret.example.yaml,
// then any 32-byte key (all zeros) and any 32+ character passphrase
// ("aaaa…", "SealKeeperProductionMasterKey") whatever its entropy.
func TestValidate_MasterSecret(t *testing.T) {
	t.Parallel()
	b64 := base64.StdEncoding.EncodeToString
	seq := make([]byte, 32)
	for i := range seq {
		seq[i] = byte(i)
	}
	cases := []struct {
		name, secret string
		ok           bool
	}{
		{"base64 32 random bytes", "TDtH5oMKTZdiG00fTrwpUK5vA2HPz2LwJiI2mHxk+X0=", true},
		{"hex 32 random bytes (legacy passphrase)", "9e6b6314054ad9a2d51754117cd8b5f83b2e5d98c68a28d6a1773e16b33e8686", true},
		{"random passphrase (legacy)", "vT7#qLm2!xRz9@kWp4$bNc8&hYd3*fGs", true},
		{"random words passphrase (legacy)", "Quarzite-Flombique-Vertrandu-Pelsor-9qX", true},
		{"random digits (legacy)", "40719386255103874692018573640295", true},
		{"shipped placeholder", "REPLACE_ME_WITH_BASE64_32_BYTES", false},
		{"changeme", "changeme-changeme-changeme-changeme", false},
		{"short", "hunter2", false},
		{"base64 16 bytes", "AAAAAAAAAAAAAAAAAAAAAA==", false},
		{"all-zero key", b64(make([]byte, 32)), false},
		{"repeated 4-byte key", b64(bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 8)), false},
		{"repeated 16-byte key", b64(bytes.Repeat([]byte{0x9a, 0x01, 0xf3, 0x77, 0x10, 0xc4, 0x5e, 0xbb, 0x02, 0xe9, 0x6d, 0x38, 0xa1, 0x4f, 0x80, 0xd5}, 2)), false},
		{"sequential key", b64(seq), false},
		{"hand-typed repeating base64", "q83vEjRWeJq83vEjRWeJq83vEjRWeJq83vEjRWeJq8M=", false},
		{"base64 of a phrase", b64([]byte("sealkeeper production master key")), false},
		{"word salad that decodes to 32 bytes", "SealKeeperProductionMasterKeyForAcmeCorp202", false},
		{"one repeated char", strings.Repeat("a", 40), false},
		{"short block repeated", strings.Repeat("abcdefgh", 4), false},
		{"keyboard walk", "qwertyuiopasdfghjklzxcvbnm1234567890", false},
		{"product words with separators", "sealkeeper-production-master-key", false},
		{"product words concatenated", "sealkeeperproductionmasterkey2026", false},
		{"product words, case and leet", "S3alK33per_Pr0duct10n_M4ster_K3y!", false},
		{"product words, leading digits", "2026sealkeeper2026production2026", false},
		{"instance name", "sk-acme-corp-production-secret-2026", false},
		{"dictionary passphrase", "secret dragon summer monkey password", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			err := productionConfig(c.secret).validate()
			if (err == nil) != c.ok {
				t.Fatalf("validate() err = %v, want ok=%v", err, c.ok)
			}
		})
	}
}

// Random values in every documented shape must clear the floor: a false
// refusal would stop a correctly configured production instance.
func TestValidate_RandomMasterSecretsAccepted(t *testing.T) {
	t.Parallel()
	const alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for i := 0; i < 200; i++ {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		pass := make([]byte, 32)
		for j := range pass {
			pass[j] = alnum[int(key[j])%len(alnum)]
		}
		for _, secret := range []string{
			base64.StdEncoding.EncodeToString(key),
			base64.RawURLEncoding.EncodeToString(key),
			hex.EncodeToString(key),
			hex.EncodeToString(key[:16]),
			string(pass),
		} {
			if err := productionConfig(secret).validate(); err != nil {
				t.Fatalf("random secret %q refused: %v", secret, err)
			}
		}
	}
}

// Eval mode keeps minting its own key and never runs the production check.
func TestValidate_EvalMasterSecretUnchecked(t *testing.T) {
	t.Parallel()
	cfg := productionConfig(strings.Repeat("a", 40))
	cfg.Mode = ModeEval
	if err := cfg.validate(); err != nil {
		t.Fatalf("eval validate() = %v, want nil", err)
	}
}

func productionConfig(secret string) Config {
	cfg := Defaults()
	cfg.MasterSecret = secret
	cfg.BaseURL = "https://sk.acme-corp.test"
	cfg.InstanceDomain = "sk.acme-corp.test"
	cfg.DatabaseURL = "sqlite://x.db"
	return cfg
}

// SK_INTEGRATIONS_ALLOW_PRIVATE defaults to false (SSRF guard on) and is
// flipped only by an explicit env value.
func TestIntegrationsAllowPrivateEnv(t *testing.T) {
	cfg := Defaults()
	if cfg.IntegrationsAllowPrivate {
		t.Fatal("IntegrationsAllowPrivate defaults to true; want false")
	}
	t.Setenv("SK_INTEGRATIONS_ALLOW_PRIVATE", "true")
	applyEnv(&cfg)
	if !cfg.IntegrationsAllowPrivate {
		t.Fatal("SK_INTEGRATIONS_ALLOW_PRIVATE=true not applied")
	}
}
