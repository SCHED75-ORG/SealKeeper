// Package storagetest hands repository tests a fresh, empty database.
//
// By default that is a SQLite file under t.TempDir(). When TEST_PG_DSN is
// set (a Postgres URL whose role may CREATE DATABASE), each call creates a
// throw-away database on that server instead and drops it on cleanup, so
// the whole repo suite can be replayed against Postgres:
//
//	TEST_PG_DSN=postgres://postgres:pw@127.0.0.1:5432/postgres?sslmode=disable go test ./...
package storagetest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // "pgx" driver for the admin connection
)

// DSN returns a storage.Open DSN pointing at a fresh, empty database.
func DSN(t testing.TB) string {
	t.Helper()
	admin := os.Getenv("TEST_PG_DSN")
	if admin == "" {
		return "sqlite://" + filepath.ToSlash(filepath.Join(t.TempDir(), "test.db"))
	}

	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("storagetest: rand: %v", err)
	}
	name := "sk_test_" + hex.EncodeToString(buf)

	u, err := url.Parse(admin)
	if err != nil {
		t.Fatalf("storagetest: TEST_PG_DSN: %v", err)
	}
	db, err := sql.Open("pgx", admin)
	if err != nil {
		t.Fatalf("storagetest: open admin connection: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// name is hex-only, so interpolating it is safe.
	if _, err := db.ExecContext(ctx, "CREATE DATABASE "+name); err != nil {
		_ = db.Close()
		t.Fatalf("storagetest: create database: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = db.ExecContext(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		_ = db.Close()
	})

	u.Path = "/" + name
	return u.String()
}
