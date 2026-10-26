package storage_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression: CLAUDE.md (the handover doc) still listed twelve migrations,
// described the audit chain as plain SHA-256 and told readers repo tests
// open a hard-coded SQLite path, long after 0013..0015, the keyed chain
// and storagetest/TEST_PG_DSN landed. Pin the facts that drifted.
func TestHandoverDocMatchesSchema(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile(filepath.Join("..", "..", "CLAUDE.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)

	entries, err := os.ReadDir(filepath.Join("migrations", "sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		num, _, ok := strings.Cut(e.Name(), "_")
		// Rows up to 0015 are pinned here; later migrations belong to
		// whoever adds them (and to the doc's own table).
		if !ok || len(num) != 4 || num > "0015" {
			continue
		}
		if !strings.Contains(doc, "| "+num+" |") {
			t.Errorf("CLAUDE.md data-model table has no row for migration %s", e.Name())
		}
	}
	for _, want := range []string{"storagetest.DSN", "TEST_PG_DSN", "audit_head", "DeriveKey"} {
		if !strings.Contains(doc, want) {
			t.Errorf("CLAUDE.md does not mention %s", want)
		}
	}
	for _, stale := range []string{
		"entry_hash = sha256(prev_hash",       // the chain is HMAC-keyed (0014)
		"`eval` / `demo` / `production`",      // SK_MODE=demo is refused
		"Twelve migrations",                   // there are more
		`Options{DSN: "sqlite://..."})` + "`", // tests use storagetest.DSN
	} {
		if strings.Contains(doc, stale) {
			t.Errorf("CLAUDE.md still says %q", stale)
		}
	}
}
