package smtpconfig_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/cryptobox"
	"github.com/sched75/sealkeeper/internal/smtpconfig"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
)

func newRepo(t *testing.T) *smtpconfig.Repo {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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
