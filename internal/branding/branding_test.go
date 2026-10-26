package branding_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/branding"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
)

func newRepo(t *testing.T) *branding.Repo {
	t.Helper()
	dsn := storagetest.DSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := storage.Open(ctx, storage.Options{DSN: dsn})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return branding.NewRepo(s.DB())
}

func TestGetCreatesDefaultRow(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	row, err := r.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if row.InstanceName != "SealKeeper" {
		t.Errorf("InstanceName = %q, want SealKeeper", row.InstanceName)
	}
	if row.PrimaryColor != "#7A1F2B" {
		t.Errorf("PrimaryColor = %q, want #7A1F2B", row.PrimaryColor)
	}
	if row.HasLogo {
		t.Error("HasLogo should be false on a fresh row")
	}
}

func TestUpdateValidates(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	if err := r.Update(ctx, branding.UpdateInputs{InstanceName: ""}, nil); !errors.Is(err, branding.ErrInvalidName) {
		t.Errorf("empty name err = %v, want ErrInvalidName", err)
	}
	if err := r.Update(ctx, branding.UpdateInputs{
		InstanceName: "X", PrimaryColor: "blue", SecondaryColor: "#FFFFFF", TertiaryColor: "#000000",
	}, nil); !errors.Is(err, branding.ErrInvalidColor) {
		t.Errorf("bad color err = %v, want ErrInvalidColor", err)
	}
	if err := r.Update(ctx, branding.UpdateInputs{
		InstanceName: "X", PrimaryColor: "#XYZ123", SecondaryColor: "#FFFFFF", TertiaryColor: "#000000",
	}, nil); !errors.Is(err, branding.ErrInvalidColor) {
		t.Errorf("non-hex color err = %v, want ErrInvalidColor", err)
	}
}

func TestUpdateRoundTrip(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	in := branding.UpdateInputs{
		InstanceName:   "Acme Corp",
		PrimaryColor:   "#ff0080",
		SecondaryColor: "#00FF00",
		TertiaryColor:  "#0000FF",
		ContactURL:     "https://example.com/help",
	}
	if err := r.Update(ctx, in, nil); err != nil {
		t.Fatalf("Update: %v", err)
	}
	row, err := r.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if row.InstanceName != "Acme Corp" {
		t.Errorf("InstanceName = %q", row.InstanceName)
	}
	// Colours are stored upper-cased for consistency.
	if row.PrimaryColor != "#FF0080" {
		t.Errorf("PrimaryColor = %q, want #FF0080", row.PrimaryColor)
	}
	if row.ContactURL != "https://example.com/help" {
		t.Errorf("ContactURL = %q", row.ContactURL)
	}
}

func TestSetLogoRejectsBadMIME(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	err := r.SetLogo(context.Background(), "image/jpeg", []byte("x"), nil)
	if !errors.Is(err, branding.ErrInvalidLogo) {
		t.Fatalf("err = %v, want ErrInvalidLogo", err)
	}
}

func TestSetLogoRejectsOversized(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	big := bytes.Repeat([]byte{0}, branding.MaxLogoBytes+1)
	err := r.SetLogo(context.Background(), "image/png", big, nil)
	if !errors.Is(err, branding.ErrLogoTooLarge) {
		t.Fatalf("err = %v, want ErrLogoTooLarge", err)
	}
}

func TestSetAndReadLogo(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	want := []byte("\x89PNG\r\n\x1a\nfake png bytes")
	if err := r.SetLogo(ctx, "image/png", want, nil); err != nil {
		t.Fatalf("SetLogo: %v", err)
	}
	row, err := r.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !row.HasLogo || row.LogoMIME != "image/png" {
		t.Errorf("HasLogo=%v MIME=%q", row.HasLogo, row.LogoMIME)
	}
	got, mime, err := r.Logo(ctx)
	if err != nil {
		t.Fatalf("Logo: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Logo bytes mismatch")
	}
	if mime != "image/png" {
		t.Errorf("Logo mime = %q", mime)
	}
}

func TestClearLogo(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	if err := r.SetLogo(ctx, "image/svg+xml", []byte("<svg/>"), nil); err != nil {
		t.Fatalf("SetLogo: %v", err)
	}
	if err := r.ClearLogo(ctx, nil); err != nil {
		t.Fatalf("ClearLogo: %v", err)
	}
	if _, _, err := r.Logo(ctx); !errors.Is(err, branding.ErrInvalidLogo) {
		t.Fatalf("post-clear Logo err = %v, want ErrInvalidLogo", err)
	}
	row, _ := r.Get(ctx)
	if row.HasLogo {
		t.Error("HasLogo should be false after ClearLogo")
	}
}
