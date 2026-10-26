package admin_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sched75/sealkeeper/internal/admin"
)

func TestValidateAdminPassword(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		pwd  string
		ok   bool
	}{
		{"empty", "", false},
		{"too short", "Short1!Pass", false},                   // 11 chars
		{"long but one class", "aaaaaaaaaaaaaaaaaaaa", false}, // 20 lowercase
		{"long with two classes", "aaaaaaaaaaaaaaaa11", false},
		// SK-20: these all satisfy length + classes, yet are among the
		// first candidates any guesser tries.
		{"product name + year", "Sealkeeper2026!!", false},
		{"common password + sequence", "Password1234567!", false},
		{"keyboard walk + sequence", "Azerty123456789!", false},
		{"repeated character", "Aaaaaaaaaaaaaaa1", false},
		{"leetspeak common password twice", "P@ssw0rd-P@ssw0rd!", false},
		{"dictionary words + year", "Strong-Admin-2026!", false},
		{"french words + repeat", "passe robuste 4242 administrateur", false},
		{"qwerty walk", "Qwertyuiop123456!", false},
		{"random 16 chars, 4 classes", "kV7#qL9!xT2@mR4$", true},
		{"random 20 chars", "x7Kp#9vLq2!mZ8wR4tYc", true},
		{"french passphrase with digits + symbols", "Cathédrale-bronze-44", true},
		{"uncommon words passphrase", "Tortue-violette-Grimpe-87-cerises", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			err := admin.ValidateAdminPassword(c.pwd)
			if c.ok && err != nil {
				t.Errorf("expected nil, got %v", err)
			}
			if !c.ok && err == nil {
				t.Errorf("expected ErrPasswordTooWeak, got nil")
			}
			if err != nil && !errors.Is(err, admin.ErrPasswordTooWeak) {
				t.Errorf("err = %v, want ErrPasswordTooWeak wrap", err)
			}
		})
	}
}

func TestValidateAdminPasswordUsesContext(t *testing.T) {
	t.Parallel()
	// Strong on its own, but built from the operator's email and the
	// instance domain, which an attacker knows.
	pwd := "Jean.Dupont+Acme-Corp!42"
	if err := admin.ValidateAdminPassword(pwd); err != nil {
		t.Fatalf("without context: %v, want nil", err)
	}
	err := admin.ValidateAdminPassword(pwd, "jean.dupont@acme-corp.fr", "sealkeeper.acme-corp.fr")
	if !errors.Is(err, admin.ErrPasswordTooWeak) {
		t.Fatalf("with context: %v, want ErrPasswordTooWeak", err)
	}
	if !strings.Contains(admin.PasswordWeaknessCodes(err), admin.WeakContext) {
		t.Errorf("codes = %q, want %q", admin.PasswordWeaknessCodes(err), admin.WeakContext)
	}
}

func TestWeakPasswordErrorExplainsWithoutLeaking(t *testing.T) {
	t.Parallel()
	err := admin.ValidateAdminPassword("Sealkeeper2026!!")
	if err == nil {
		t.Fatal("want error")
	}
	msg := err.Error()
	for _, want := range []string{"bits", "product name", "year"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q lacks %q", msg, want)
		}
	}
	for _, leak := range []string{"Sealkeeper", "2026"} {
		if strings.Contains(msg, leak) {
			t.Errorf("message %q quotes the password fragment %q", msg, leak)
		}
	}
	if got := admin.DescribePasswordWeakness("year,<script>,bogus"); got != "contains a year" {
		t.Errorf("DescribePasswordWeakness = %q, unknown codes must be dropped", got)
	}
}

func TestEstimateIgnoresBytesPastBcryptLimit(t *testing.T) {
	t.Parallel()
	// bcrypt reads 72 bytes; a weak prefix padded with random-looking
	// characters past that point must not be credited for them.
	pwd := strings.Repeat("Aa1!", 18) + "x7Kp#9vLq2!mZ8wR4tYcQ3$nB6&"
	if bits := admin.EstimatePasswordEntropy(pwd); bits >= admin.AdminPasswordMinEntropyBits {
		t.Errorf("estimate = %.1f bits, want < %d", bits, admin.AdminPasswordMinEntropyBits)
	}
}

func TestChangePasswordRejectsWeak(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	ctx := context.Background()
	a, err := r.Create(ctx, "ops@example.test", "Strong-Bootstrap-2026!")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := r.ChangePassword(ctx, a.ID, "short"); !errors.Is(err, admin.ErrPasswordTooWeak) {
		t.Errorf("ChangePassword(short) = %v, want ErrPasswordTooWeak", err)
	}
	if err := r.ChangePassword(ctx, a.ID, "Sealkeeper2026!!"); !errors.Is(err, admin.ErrPasswordTooWeak) {
		t.Errorf("ChangePassword(Sealkeeper2026!!) = %v, want ErrPasswordTooWeak", err)
	}
	// The operator's own email is attacker-known context.
	if err := r.ChangePassword(ctx, a.ID, "Ops@Example.Test#9Zq"); !errors.Is(err, admin.ErrPasswordTooWeak) {
		t.Errorf("ChangePassword(email-based) = %v, want ErrPasswordTooWeak", err)
	}
	if err := r.ChangePassword(ctx, a.ID, "x7Kp#9vLq2!mZ8wR4tYc"); err != nil {
		t.Errorf("ChangePassword(strong) = %v, want nil", err)
	}
}

func TestChangePasswordUsesInstanceContext(t *testing.T) {
	t.Parallel()
	r := newRepo(t).WithPasswordContext("vault.contoso-bank.fr")
	ctx := context.Background()
	a, err := r.Create(ctx, "ops@example.test", "Strong-Bootstrap-2026!")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := r.ChangePassword(ctx, a.ID, "Contoso-Bank#Vault!7"); !errors.Is(err, admin.ErrPasswordTooWeak) {
		t.Errorf("ChangePassword(instance-based) = %v, want ErrPasswordTooWeak", err)
	}
}
