package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression: PRD FR-M.4 claimed that 16 characters + 3 classes
// "guarantees >= 100 bits", but "Password1234567!" clears both and
// estimates far below 100 bits. The B3 gate is the entropy estimator; the
// PRD must say so instead of promising the length/class floor suffices.
func TestPRDMatchesPasswordEstimator(t *testing.T) {
	t.Parallel()
	const weak = "Password1234567!"
	if len([]rune(weak)) < AdminPasswordMinLength || countClasses(weak) < AdminPasswordMinClasses {
		t.Fatal("precondition: sample must clear the length and class floor")
	}
	if bits := EstimatePasswordEntropy(weak); bits >= AdminPasswordMinEntropyBits {
		t.Fatalf("precondition: sample estimated at %.0f bits", bits)
	}

	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "prd", "M-admin-accounts.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	if strings.Contains(doc, "garantit un seuil d'entropie") {
		t.Error("FR-M.4 still claims length + classes guarantee the entropy floor")
	}
	for _, want := range []string{"EstimatePasswordEntropy", "AdminPasswordMinEntropyBits", "WeakPasswordError"} {
		if !strings.Contains(doc, want) {
			t.Errorf("M-admin-accounts.md does not reference %s", want)
		}
	}
}
