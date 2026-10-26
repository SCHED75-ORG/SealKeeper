package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
)

// migrated opens a fresh database on the dialect selected by TEST_PG_DSN
// (SQLite by default) and applies every migration.
func migrated(t *testing.T) storage.Store {
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
	return s
}

func insertAdmin(t *testing.T, db storage.Store, email string) int64 {
	t.Helper()
	now := time.Now().UTC()
	id, err := storage.InsertReturningID(context.Background(), db.DB(),
		`INSERT INTO admins (email, password_hash, force_password_change, force_totp_enroll, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		email, "x", true, false, now, now)
	if err != nil {
		t.Fatalf("insert admin %s: %v", email, err)
	}
	return id
}

func TestInsertReturningIDYieldsSequentialIDs(t *testing.T) {
	t.Parallel()
	s := migrated(t)
	a := insertAdmin(t, s, "a@example.com")
	b := insertAdmin(t, s, "b@example.com")
	if a <= 0 || b != a+1 {
		t.Fatalf("ids = %d, %d; want positive and consecutive", a, b)
	}
	var email string
	if err := s.DB().QueryRowContext(context.Background(),
		storage.Rebind(s.DB(), `SELECT email FROM admins WHERE id = ?`), b).Scan(&email); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if email != "b@example.com" {
		t.Fatalf("id %d holds %q, want b@example.com", b, email)
	}
}

func TestBooleanColumnsRoundTrip(t *testing.T) {
	t.Parallel()
	s := migrated(t)
	id := insertAdmin(t, s, "bool@example.com")
	var forcePwd, forceTOTP bool
	if err := s.DB().QueryRowContext(context.Background(),
		storage.Rebind(s.DB(), `SELECT force_password_change, force_totp_enroll FROM admins WHERE id = ?`), id).
		Scan(&forcePwd, &forceTOTP); err != nil {
		t.Fatalf("scan bools: %v", err)
	}
	if !forcePwd || forceTOTP {
		t.Fatalf("got (%v, %v), want (true, false)", forcePwd, forceTOTP)
	}
	var n int64
	if err := s.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM admins WHERE force_password_change = TRUE AND force_totp_enroll = FALSE`).
		Scan(&n); err != nil {
		t.Fatalf("TRUE/FALSE literals: %v", err)
	}
	if n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}
}

func TestIsUniqueViolation(t *testing.T) {
	t.Parallel()
	s := migrated(t)
	ctx := context.Background()
	insertAdmin(t, s, "dup@example.com")
	now := time.Now().UTC()
	_, err := storage.InsertReturningID(ctx, s.DB(),
		`INSERT INTO admins (email, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)`,
		"dup@example.com", "x", now, now)
	if !storage.IsUniqueViolation(err) {
		t.Fatalf("duplicate email: IsUniqueViolation(%v) = false, want true", err)
	}

	// A foreign-key failure is not a uniqueness conflict on either dialect.
	_, err = s.DB().ExecContext(ctx,
		storage.Rebind(s.DB(), `INSERT INTO admin_sessions
			(token, admin_id, issued_at, expires_at, idle_expires_at, csrf_token)
			VALUES (?, ?, ?, ?, ?, ?)`),
		"tok-orphan", int64(999999), now, now, now, "csrf")
	if err == nil {
		t.Fatal("session for a missing admin was accepted; foreign keys are not enforced")
	}
	if storage.IsUniqueViolation(err) {
		t.Fatalf("FK failure classified as unique violation: %v", err)
	}
}

// Deleting an admin cascades to its sessions on both dialects — SQLite only
// honours ON DELETE CASCADE with PRAGMA foreign_keys on.
func TestForeignKeyCascade(t *testing.T) {
	t.Parallel()
	s := migrated(t)
	ctx := context.Background()
	id := insertAdmin(t, s, "cascade@example.com")
	now := time.Now().UTC()
	if _, err := s.DB().ExecContext(ctx,
		storage.Rebind(s.DB(), `INSERT INTO admin_sessions
			(token, admin_id, issued_at, expires_at, idle_expires_at, csrf_token)
			VALUES (?, ?, ?, ?, ?, ?)`),
		"tok-cascade", id, now, now, now, "csrf"); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	if _, err := s.DB().ExecContext(ctx, storage.Rebind(s.DB(), `DELETE FROM admins WHERE id = ?`), id); err != nil {
		t.Fatalf("delete admin: %v", err)
	}
	var n int64
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_sessions`).Scan(&n); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if n != 0 {
		t.Fatalf("%d session(s) survived their admin's deletion, want 0", n)
	}
}
