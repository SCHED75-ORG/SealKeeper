package admin

import (
	"errors"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Regression: the unknown-email path compared against an invalid 58-char
// literal that bcrypt rejected without hashing, so unknown emails answered
// ~60 ms faster than real ones and admin accounts could be enumerated.
func TestDummyBcryptHashCostsLikeARealOne(t *testing.T) {
	t.Parallel()
	cost, err := bcrypt.Cost(dummyBcryptHash())
	if err != nil {
		t.Fatalf("dummy hash is not a valid bcrypt hash: %v", err)
	}
	if cost != bcrypt.DefaultCost {
		t.Fatalf("dummy hash cost = %d, want bcrypt.DefaultCost (%d)", cost, bcrypt.DefaultCost)
	}
	if err := bcrypt.CompareHashAndPassword(dummyBcryptHash(), []byte("guess")); !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		t.Fatalf("compare err = %v, want ErrMismatchedHashAndPassword (full hash computed)", err)
	}
}
