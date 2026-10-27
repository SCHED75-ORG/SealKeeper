package admin

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/sched75/sealkeeper/internal/strength"
)

// ErrPasswordTooWeak is returned by ValidateAdminPassword when an admin-
// supplied password does not meet the ANSSI B3 floor that the console
// applies to every operator account. The concrete error is a
// *WeakPasswordError that explains why.
//
// PRD: FR-M.4. Operator accounts are an instance-wide credential — they
// must be at least as strong as the strongest tier of generated user
// password.
var ErrPasswordTooWeak = errors.New("admin: password below ANSSI B3 floor")

// AdminPasswordMinLength is the floor we surface to the UI (minlength).
// Length alone proves nothing about strength: the entropy estimate
// below is what enforces B3.
const AdminPasswordMinLength = 16

// AdminPasswordMinClasses is how many of the four character classes
// (lower, upper, digit, symbol) a password must mix (FR-M.4).
const AdminPasswordMinClasses = 3

// AdminPasswordMinEntropyBits is the ANSSI B3 floor (FR-M.4, FR-A.G3.3),
// applied to the estimated guessing entropy, not to length × log2(charset).
const AdminPasswordMinEntropyBits = 100

// bcryptMaxBytes is where bcrypt stops reading its input. Characters past
// it never reach the hash, so they earn no entropy credit.
const bcryptMaxBytes = 72

// Weakness codes. They name a category, never a fragment of the password,
// so they are safe to put in a redirect URL or a log line.
const (
	WeakTooShort   = "too_short"
	WeakFewClasses = "few_classes"
	WeakCommon     = strength.Common
	WeakDictionary = strength.Dictionary
	WeakContext    = strength.Context
	WeakYear       = strength.Year
	WeakSequence   = strength.Sequence
	WeakKeyboard   = strength.Keyboard
	WeakRepeat     = strength.Repeat
	WeakEntropy    = "entropy"
)

var weaknessText = map[string]string{
	WeakTooShort:   fmt.Sprintf("minimum %d characters", AdminPasswordMinLength),
	WeakFewClasses: fmt.Sprintf("mix at least %d of lower-case, upper-case, digits and symbols", AdminPasswordMinClasses),
	WeakCommon:     "contains a commonly used password",
	WeakDictionary: "contains a dictionary word",
	WeakContext:    "contains the product name, the instance name or your email address",
	WeakYear:       "contains a year",
	WeakSequence:   "contains a character sequence (abc, 123…)",
	WeakKeyboard:   "contains a keyboard pattern (qwerty, azerty…)",
	WeakRepeat:     "contains a repeated character or block",
	WeakEntropy:    "too predictable overall",
}

// WeakPasswordError explains why ValidateAdminPassword refused a
// candidate. errors.Is(err, ErrPasswordTooWeak) holds. Its message never
// quotes the password.
type WeakPasswordError struct {
	Codes []string // weakness codes, see Weak* constants
	Bits  float64  // estimated guessing entropy (0 when not computed)
}

func (e *WeakPasswordError) Error() string {
	var b strings.Builder
	b.WriteString(ErrPasswordTooWeak.Error())
	b.WriteString(": ")
	if e.Bits > 0 {
		fmt.Fprintf(&b, "estimated %.0f bits of guessing entropy, %d required", e.Bits, AdminPasswordMinEntropyBits)
		if len(e.Codes) > 0 {
			b.WriteString(" — ")
		}
	}
	b.WriteString(DescribePasswordWeakness(strings.Join(e.Codes, ",")))
	return b.String()
}

// Unwrap lets errors.Is match ErrPasswordTooWeak.
func (e *WeakPasswordError) Unwrap() error { return ErrPasswordTooWeak }

// PasswordWeaknessCodes returns the comma-separated weakness codes carried
// by err, or "" when err is not a *WeakPasswordError.
func PasswordWeaknessCodes(err error) string {
	var w *WeakPasswordError
	if errors.As(err, &w) {
		return strings.Join(w.Codes, ",")
	}
	return ""
}

// DescribePasswordWeakness turns comma-separated weakness codes into an
// operator-facing sentence. Unknown codes are dropped, so the result is
// safe to render from a query parameter.
func DescribePasswordWeakness(codes string) string {
	var parts []string
	for _, c := range strings.Split(codes, ",") {
		if t, ok := weaknessText[strings.TrimSpace(c)]; ok {
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, "; ")
}

// ValidateAdminPassword returns nil when the candidate clears the B3
// policy, or a *WeakPasswordError (wrapping ErrPasswordTooWeak) otherwise.
//
// Besides the FR-M.4 length and class floor, the candidate's guessing
// entropy is estimated (EstimatePasswordEntropy) and must reach
// AdminPasswordMinEntropyBits. userInputs are strings the attacker can be
// assumed to know — the operator's email, the instance domain — and are
// matched like dictionary words that cost almost nothing to guess.
func ValidateAdminPassword(s string, userInputs ...string) error {
	if utf8.RuneCountInString(s) < AdminPasswordMinLength {
		return &WeakPasswordError{Codes: []string{WeakTooShort}}
	}
	if countClasses(s) < AdminPasswordMinClasses {
		return &WeakPasswordError{Codes: []string{WeakFewClasses}}
	}
	if strength.IsCommon(s) {
		return &WeakPasswordError{Codes: []string{WeakCommon}}
	}
	bits, codes := strength.Estimate(truncateUTF8(s, bcryptMaxBytes), userInputs...)
	if bits < AdminPasswordMinEntropyBits {
		if len(codes) == 0 {
			codes = []string{WeakEntropy}
		}
		return &WeakPasswordError{Codes: codes, Bits: bits}
	}
	return nil
}

// EstimatePasswordEntropy returns a conservative estimate, in bits, of
// the number of guesses an attacker needs to find s. It is the small
// zxcvbn-style matcher of strength.Estimate: the password is split into the cheapest sequence
// of segments, where a segment is either one brute-forced character
// (log2 of the character pool) or a predictable pattern — common
// password, dictionary word (case and leetspeak variants included),
// product/instance/email word, year, alphabetic or numeric sequence,
// keyboard walk, or repetition — charged at what it costs an attacker
// who knows the pattern. Only the first 72 bytes count, as bcrypt
// ignores the rest.
func EstimatePasswordEntropy(s string, userInputs ...string) float64 {
	bits, _ := strength.Estimate(truncateUTF8(s, bcryptMaxBytes), userInputs...)
	return bits
}

func countClasses(s string) int {
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range s {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r), unicode.IsSymbol(r), unicode.IsSpace(r):
			hasSymbol = true
		}
	}
	classes := 0
	for _, ok := range []bool{hasLower, hasUpper, hasDigit, hasSymbol} {
		if ok {
			classes++
		}
	}
	return classes
}

// truncateUTF8 keeps the longest prefix of s that fits in max bytes
// without splitting a rune.
func truncateUTF8(s string, max int) string {
	if len(s) > max {
		cut := max
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	return s
}
