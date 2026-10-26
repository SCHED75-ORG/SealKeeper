package main

import (
	"testing"

	"github.com/sched75/sealkeeper/internal/admin"
)

// Generated bootstrap / reset-password passwords go through
// ResetForBootstrap, which enforces the operator policy: every draw must
// clear it. Before the redraw loop, about 0.3% of draws lacked a third
// character class and made `admin reset-password` fail.
func TestRandomPasswordAlwaysClearsPolicy(t *testing.T) {
	t.Parallel()
	for i := 0; i < 3000; i++ {
		pwd, err := randomPassword(20)
		if err != nil {
			t.Fatalf("randomPassword: %v", err)
		}
		if len(pwd) != 20 {
			t.Fatalf("len = %d, want 20", len(pwd))
		}
		if err := admin.ValidateAdminPassword(pwd); err != nil {
			t.Fatalf("draw %d %v", i, err)
		}
	}
}
