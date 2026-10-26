package webauthn_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
	"github.com/sched75/sealkeeper/internal/webauthn"
)

func newRepo(t *testing.T) *webauthn.Repo {
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

	repo, err := webauthn.NewRepo(s.DB(), webauthn.Config{
		RPID:          "sealkeeper.test",
		RPDisplayName: "SealKeeper test",
		Origins:       []string{"https://sealkeeper.test"},
	})
	if err != nil {
		t.Fatalf("NewRepo: %v", err)
	}
	return repo
}

func TestNewRepoRequiresRPID(t *testing.T) {
	t.Parallel()
	if _, err := webauthn.NewRepo(nil, webauthn.Config{Origins: []string{"https://x.test"}}); err == nil {
		t.Fatal("expected error when RPID is missing")
	}
	if _, err := webauthn.NewRepo(nil, webauthn.Config{RPID: "x.test"}); err == nil {
		t.Fatal("expected error when origins are missing")
	}
}

func TestListEmpty(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	got, err := r.List(context.Background(), 42)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("List returned %d rows on a fresh repo", len(got))
	}
}

func TestBeginRegistrationValidatesInputs(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	_, _, err := r.BeginRegistration(ctx, webauthn.AdminIdentity{ID: 1, Email: "a@b.test"}, "  ")
	if !errors.Is(err, webauthn.ErrInvalidName) {
		t.Fatalf("blank name err = %v, want ErrInvalidName", err)
	}
}

func TestBeginRegistrationProducesOptions(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	opts, sess, err := r.BeginRegistration(context.Background(),
		webauthn.AdminIdentity{ID: 7, Email: "ops@sealkeeper.test"}, "YubiKey")
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if len(opts) == 0 {
		t.Error("empty options")
	}
	if len(sess) == 0 {
		t.Error("empty session")
	}
}

func TestRenameAndDeleteNotFound(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	if err := r.Rename(ctx, 1, "missing", "  "); !errors.Is(err, webauthn.ErrInvalidName) {
		t.Errorf("blank name err = %v, want ErrInvalidName", err)
	}
	if err := r.Rename(ctx, 1, "missing", "still missing"); !errors.Is(err, webauthn.ErrNotFound) {
		t.Errorf("Rename of missing row err = %v, want ErrNotFound", err)
	}
	if err := r.Delete(ctx, 1, "missing"); !errors.Is(err, webauthn.ErrNotFound) {
		t.Errorf("Delete of missing row err = %v, want ErrNotFound", err)
	}
}

func TestHasCredentialsEmpty(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	has, err := r.HasCredentials(context.Background(), 42)
	if err != nil {
		t.Fatalf("HasCredentials: %v", err)
	}
	if has {
		t.Error("HasCredentials returned true on a fresh repo")
	}
}

func TestBeginLoginRequiresCredentials(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	_, _, err := r.BeginLogin(context.Background(), webauthn.AdminIdentity{ID: 1, Email: "x@y"})
	if !errors.Is(err, webauthn.ErrNotFound) {
		t.Errorf("BeginLogin without creds err = %v, want ErrNotFound", err)
	}
}

func TestFinishLoginRequiresSession(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	_, err := r.FinishLogin(context.Background(),
		webauthn.AdminIdentity{ID: 1, Email: "x@y"}, nil, nil)
	if !errors.Is(err, webauthn.ErrSessionMissing) {
		t.Errorf("FinishLogin without session err = %v, want ErrSessionMissing", err)
	}
}
