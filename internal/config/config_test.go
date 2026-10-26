package config

import "testing"

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
// including the REPLACE_ME placeholder shipped in k8s/secret.example.yaml.
func TestValidate_MasterSecret(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, secret string
		ok           bool
	}{
		{"base64 32 bytes", "q83vEjRWeJq83vEjRWeJq83vEjRWeJq83vEjRWeJq8M=", true},
		{"long passphrase (legacy)", "correct horse battery staple and then some more", true},
		{"shipped placeholder", "REPLACE_ME_WITH_BASE64_32_BYTES", false},
		{"changeme", "changeme-changeme-changeme-changeme", false},
		{"short", "hunter2", false},
		{"base64 16 bytes", "AAAAAAAAAAAAAAAAAAAAAA==", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			cfg := Defaults()
			cfg.MasterSecret = c.secret
			cfg.BaseURL = "https://sk.example.test"
			cfg.DatabaseURL = "sqlite://x.db"
			err := cfg.validate()
			if (err == nil) != c.ok {
				t.Fatalf("validate() err = %v, want ok=%v", err, c.ok)
			}
		})
	}
}
