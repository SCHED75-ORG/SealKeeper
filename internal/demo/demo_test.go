package demo_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/audit"
	"github.com/sched75/sealkeeper/internal/demo"
	"github.com/sched75/sealkeeper/internal/libraries"
	"github.com/sched75/sealkeeper/internal/mailcapture"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
)

func openStore(t *testing.T) storage.Store {
	t.Helper()
	dsn := storagetest.DSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), storagetest.SetupTimeout)
	defer cancel()
	s, err := storage.Open(ctx, storage.Options{DSN: dsn})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestResetOnceWipesAdminState(t *testing.T) {
	t.Parallel()
	s := openStore(t)
	db := s.DB()
	ctx := context.Background()

	// Seed a row in each table that the resetter should wipe. We don't
	// care about referential integrity here — we just want non-empty
	// rows to assert against after the reset.
	if _, err := db.ExecContext(ctx, `INSERT INTO domains (name) VALUES ('example.com')`); err != nil {
		t.Fatalf("seed domains: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO captured_mail (to_addr, subject, body) VALUES ('x@y.test','s','b')`); err != nil {
		t.Fatalf("seed captured_mail: %v", err)
	}

	r := demo.NewResetter(db, nil, time.Hour)
	if err := r.ResetOnce(ctx); err != nil {
		t.Fatalf("ResetOnce: %v", err)
	}

	for _, table := range []string{"domains", "captured_mail"} {
		var n int64
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%s left with %d rows after reset", table, n)
		}
	}
}

// Regression (SK-24): the reset left admins, branding, smtp_config and kv
// alone, so the first visitor's password, backdoor accounts and phishing
// branding survived every reset. They must return to the boot snapshot.
func TestResetOnceRestoresBootSnapshot(t *testing.T) {
	t.Parallel()
	s := openStore(t)
	db := s.DB()
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, storage.Rebind(db, q), args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	// Operator-seeded state at boot.
	exec(`INSERT INTO admins (email, password_hash) VALUES ('admin@localhost', '$2a$10$operatorHash')`)
	exec(`INSERT INTO branding (id, instance_name, contact_url) VALUES (1, 'SealKeeper demo', '')`)
	mails := mailcapture.NewStore(10)
	r := demo.NewResetter(db, nil, time.Hour).WithMailStore(mails)
	if err := r.Snapshot(ctx); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// A visitor takes the demo over.
	exec(`UPDATE admins SET password_hash = '$2a$10$visitorChosenHash', totp_secret_enc = ? WHERE email = 'admin@localhost'`, []byte{1, 2})
	exec(`INSERT INTO admins (email, password_hash) VALUES ('backdoor@attacker.example', '$2a$10$x')`)
	exec(`UPDATE branding SET instance_name = 'IT Helpdesk', contact_url = 'https://phish.attacker.example/login' WHERE id = 1`)
	exec(`INSERT INTO smtp_config (id, host) VALUES (1, 'relay.attacker.example')`)
	exec(`INSERT INTO kv (key, value) VALUES ('planted', ?)`, []byte("x"))
	mails.CaptureFor("visitor", "victim@example.test", "s", "reveal link")

	if err := r.ResetOnce(ctx); err != nil {
		t.Fatalf("ResetOnce: %v", err)
	}

	var admins int
	var hash string
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admins`).Scan(&admins); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT password_hash FROM admins WHERE email = 'admin@localhost'`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if admins != 1 || hash != "$2a$10$operatorHash" {
		t.Errorf("admins=%d bootstrap hash=%q, want 1 / operator hash", admins, hash)
	}
	var totp []byte
	if err := db.QueryRowContext(ctx, `SELECT totp_secret_enc FROM admins WHERE email = 'admin@localhost'`).Scan(&totp); err != nil {
		t.Fatal(err)
	}
	if totp != nil {
		t.Errorf("visitor-enrolled TOTP secret survived the reset")
	}
	var name, contact string
	if err := db.QueryRowContext(ctx, `SELECT instance_name, contact_url FROM branding WHERE id = 1`).Scan(&name, &contact); err != nil {
		t.Fatal(err)
	}
	if name != "SealKeeper demo" || contact != "" {
		t.Errorf("branding = %q / %q, want the boot snapshot", name, contact)
	}
	for _, table := range []string{"smtp_config", "kv"} {
		var n int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s left with %d visitor rows after reset", table, n)
		}
	}
	if n := len(mails.Snapshot()); n != 0 {
		t.Errorf("captured mail queue kept %d mails after reset", n)
	}

	// A second cycle restores the same state (the snapshot is reusable).
	exec(`UPDATE admins SET password_hash = '$2a$10$again' WHERE email = 'admin@localhost'`)
	if err := r.ResetOnce(ctx); err != nil {
		t.Fatalf("second ResetOnce: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT password_hash FROM admins WHERE email = 'admin@localhost'`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash != "$2a$10$operatorHash" {
		t.Errorf("second reset: hash=%q", hash)
	}
}

func TestRunHonoursContextCancel(t *testing.T) {
	t.Parallel()
	s := openStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	r := demo.NewResetter(s.DB(), nil, 10*time.Millisecond)
	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()
	time.Sleep(35 * time.Millisecond) // let a couple of ticks fire
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

// The reset wipes audit_log; the head anchor must be reset with it, or the
// next integrity check reports the wipe as a truncated tail.
func TestResetOnceLeavesAuditChainIntact(t *testing.T) {
	t.Parallel()
	s := openStore(t)
	ctx := context.Background()
	ar := audit.NewRepo(s.DB(), make([]byte, audit.KeySize))
	for i := 0; i < 3; i++ {
		if _, err := ar.Append(ctx, "domain.created", "admin@localhost", "", nil); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	if err := demo.NewResetter(s.DB(), nil, time.Hour).ResetOnce(ctx); err != nil {
		t.Fatalf("ResetOnce: %v", err)
	}
	if bad, err := ar.VerifyChain(ctx); err != nil || bad != 0 {
		t.Fatalf("after reset: VerifyChain = %d, %v; want intact", bad, err)
	}
	if _, err := ar.Append(ctx, "admin.login", "admin@localhost", "", nil); err != nil {
		t.Fatalf("Append after reset: %v", err)
	}
	if bad, err := ar.VerifyChain(ctx); err != nil || bad != 0 {
		t.Fatalf("after reset + append: VerifyChain = %d, %v; want intact", bad, err)
	}
}

// Regression: the reset deleted non-system library rows but left their
// files on disk, so uploaded dictionaries outlived every reset as orphans.
func TestResetOnceRemovesNonSystemLibraryFiles(t *testing.T) {
	t.Parallel()
	s := openStore(t)
	ctx := context.Background()
	dir := t.TempDir()
	libs, err := libraries.NewRepo(s.DB(), dir)
	if err != nil {
		t.Fatalf("NewRepo: %v", err)
	}
	upload := func(name, body string, system bool) libraries.Library {
		t.Helper()
		lib, _, err := libs.Upload(ctx, libraries.UploadInputs{
			Name: name, Kind: libraries.KindDictionary, Language: "fr",
			System: system, Content: strings.NewReader(body),
		})
		if err != nil {
			t.Fatalf("Upload %s: %v", name, err)
		}
		return lib
	}
	sys := upload("system", "alpha\nbravo\ncharlie\n", true)
	user := upload("visitor", "delta\necho\nfoxtrot\n", false)
	// A file a previous reset already orphaned (no row any more).
	stale := filepath.Join(dir, strings.Repeat("ab", 32)+".txt")
	if err := os.WriteFile(stale, []byte("golf\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Anything that is not a library blob is left alone.
	other := filepath.Join(dir, "README")
	if err := os.WriteFile(other, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := demo.NewResetter(s.DB(), nil, time.Hour).WithLibrariesDir(dir).ResetOnce(ctx); err != nil {
		t.Fatalf("ResetOnce: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, user.FilePath)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("non-system library file survived the reset (stat err = %v)", err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("orphaned library file survived the reset (stat err = %v)", err)
	}
	for _, keep := range []string{filepath.Join(dir, sys.FilePath), other} {
		if _, err := os.Stat(keep); err != nil {
			t.Errorf("%s removed by the reset: %v", keep, err)
		}
	}
	if _, err := libs.Get(ctx, sys.ID); err != nil {
		t.Errorf("system library row: %v", err)
	}
}
