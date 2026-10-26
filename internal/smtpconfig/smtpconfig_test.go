package smtpconfig_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sched75/sealkeeper/internal/cryptobox"
	"github.com/sched75/sealkeeper/internal/smtpconfig"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
)

func newRepo(t *testing.T) *smtpconfig.Repo {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), storagetest.SetupTimeout)
	defer cancel()
	s, err := storage.Open(ctx, storage.Options{DSN: storagetest.DSN(t)})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	box, err := cryptobox.New("smtpconfig-test-master-secret")
	if err != nil {
		t.Fatalf("cryptobox.New: %v", err)
	}
	return smtpconfig.NewRepo(s.DB(), box)
}

func TestUpdateGetRoundTrip(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()

	if _, err := r.Get(ctx); !errors.Is(err, smtpconfig.ErrNotConfigured) {
		t.Fatalf("fresh Get err = %v, want ErrNotConfigured", err)
	}

	in := smtpconfig.UpdateInputs{
		Host: "smtp.example.com", Port: 2525, Username: "relay", Password: "s3cret",
		FromAddr: "noreply@example.com", TLSMode: "starttls", ServerName: "smtp.example.com",
		InsecureTLS: true, TimeoutSeconds: 12,
	}
	if err := r.Update(ctx, in, nil); err != nil {
		t.Fatalf("Update (insert): %v", err)
	}
	c, err := r.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if c.Host != in.Host || c.Port != 2525 || c.Password != "s3cret" || !c.InsecureTLS || c.TimeoutSeconds != 12 {
		t.Fatalf("Get = %+v, want the saved inputs", c)
	}

	// Second save takes the UPDATE path and flips the boolean back.
	in.InsecureTLS = false
	in.Password = ""
	in.KeepPassword = true
	if err := r.Update(ctx, in, nil); err != nil {
		t.Fatalf("Update (update): %v", err)
	}
	c, err = r.Get(ctx)
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if c.InsecureTLS || c.Password != "s3cret" {
		t.Fatalf("after update InsecureTLS = %v, Password kept = %v", c.InsecureTLS, c.Password == "s3cret")
	}

	// Empty host clears the override.
	if err := r.Update(ctx, smtpconfig.UpdateInputs{}, nil); err != nil {
		t.Fatalf("Update (clear): %v", err)
	}
	if _, err := r.Get(ctx); !errors.Is(err, smtpconfig.ErrNotConfigured) {
		t.Fatalf("Get after clear err = %v, want ErrNotConfigured", err)
	}
}

// Regression (SK-23): KeepPassword used to carry the stored relay password
// over to whatever host/port/user/TLS mode the form submitted, so an admin
// could retarget the relay at smtp.attacker.example and harvest it.
func TestKeepPasswordRefusedWhenRelayRetargeted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := smtpconfig.UpdateInputs{
		Host: "smtp.office365.com", Port: 587, Username: "svc-sk@corp.eu",
		Password: "Corp-Relay-Secret!", FromAddr: "sk@corp.eu", TLSMode: "starttls",
	}
	cases := []struct {
		name   string
		mutate func(*smtpconfig.UpdateInputs)
	}{
		{"host", func(in *smtpconfig.UpdateInputs) { in.Host = "smtp.attacker.example" }},
		{"port", func(in *smtpconfig.UpdateInputs) { in.Port = 25 }},
		{"username", func(in *smtpconfig.UpdateInputs) { in.Username = "other@corp.eu" }},
		{"tls mode", func(in *smtpconfig.UpdateInputs) { in.TLSMode = "disable" }},
		{"server name", func(in *smtpconfig.UpdateInputs) { in.ServerName = "smtp.attacker.example" }},
		{"insecure tls on", func(in *smtpconfig.UpdateInputs) { in.InsecureTLS = true }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			r := newRepo(t)
			if err := r.Update(ctx, base, nil); err != nil {
				t.Fatalf("seed Update: %v", err)
			}
			in := base
			in.Password = ""
			in.KeepPassword = true
			c.mutate(&in)
			if err := r.Update(ctx, in, nil); !errors.Is(err, smtpconfig.ErrPasswordRequired) {
				t.Fatalf("retargeted Update err = %v, want ErrPasswordRequired", err)
			}
			got, err := r.Get(ctx)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if got.Host != base.Host || got.Port != base.Port || got.TLSMode != base.TLSMode {
				t.Fatalf("refused Update still changed the row: %+v", got)
			}

			// Re-entering the password makes the same change acceptable.
			in.Password = "New-Secret-For-New-Relay"
			if err := r.Update(ctx, in, nil); err != nil {
				t.Fatalf("Update with new password: %v", err)
			}
			got, err = r.Get(ctx)
			if err != nil || got.Password != "New-Secret-For-New-Relay" {
				t.Fatalf("Get after re-entry = %+v, %v", got, err)
			}
		})
	}

	// Unchanged destination (only From / timeout edited) keeps the password.
	r := newRepo(t)
	if err := r.Update(ctx, base, nil); err != nil {
		t.Fatalf("seed Update: %v", err)
	}
	in := base
	in.Password = ""
	in.KeepPassword = true
	in.FromAddr = "noreply@corp.eu"
	in.TimeoutSeconds = 45
	if err := r.Update(ctx, in, nil); err != nil {
		t.Fatalf("same-destination Update: %v", err)
	}
	if got, _ := r.Get(ctx); got.Password != base.Password {
		t.Fatalf("password not kept for unchanged destination")
	}
}
