package audit_test

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/sched75/sealkeeper/internal/audit"
)

// Actor and target come from request input on several paths; a caller that
// forgets to bound them must not be able to write megabytes into a row the
// chain forbids deleting. The cap keeps UTF-8 valid and the chain intact.
func TestAppendCapsActorAndTarget(t *testing.T) {
	t.Parallel()
	r, s := newRepo(t)
	ctx := context.Background()

	huge := strings.Repeat("é", 1<<19) // 1 MiB of two-byte runes
	e, err := r.Append(ctx, "admin.login_failed", huge, "x"+huge, nil)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	for name, v := range map[string]string{"actor": e.Actor, "target": e.Target} {
		if len(v) > audit.MaxFieldBytes || !utf8.ValidString(v) {
			t.Errorf("returned %s: %d bytes, valid UTF-8 %v; want <= %d", name, len(v), utf8.ValidString(v), audit.MaxFieldBytes)
		}
	}
	var actor, target string
	if err := s.DB().QueryRowContext(ctx,
		`SELECT actor, target FROM audit_log WHERE sequence_no = 1`).Scan(&actor, &target); err != nil {
		t.Fatal(err)
	}
	if actor != e.Actor || target != e.Target {
		t.Errorf("stored row differs from returned entry: %d/%d vs %d/%d bytes", len(actor), len(target), len(e.Actor), len(e.Target))
	}
	if bad, err := r.VerifyChain(ctx); err != nil || bad != 0 {
		t.Fatalf("VerifyChain = %d, %v; want 0, nil", bad, err)
	}
}
