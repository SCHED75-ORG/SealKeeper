// Package totp implements RFC 6238 (Time-based One-Time Password) for the
// admin console.
//
// Defaults: 6 digits, 30-second period, HMAC-SHA1 (matching Google
// Authenticator / Authy / 1Password / Bitwarden / FreeOTP). The verifier
// accepts the previous and next 30-second windows to tolerate ±30s of
// clock drift between the server and the user's phone.
//
// PRD: FR-C.4 (mandatory TOTP enrollment), FR-C.5 (QR code via otpauth URL +
// 8 recovery codes).
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	defaultDigits = 6
	defaultPeriod = 30 // seconds
	secretBytes   = 20 // RFC 4226 recommends ≥160 bits
	driftWindows  = 1  // accept t-1, t, t+1
)

// Secret is a base32-encoded TOTP shared secret.
type Secret string

// NewSecret generates a fresh 160-bit secret and returns it as a base32
// string (no padding) suitable for the otpauth:// URI.
func NewSecret() (Secret, error) {
	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("totp.NewSecret: %w", err)
	}
	return Secret(strings.TrimRight(base32.StdEncoding.EncodeToString(buf), "=")), nil
}

// Bytes decodes the base32 secret into raw bytes.
func (s Secret) Bytes() ([]byte, error) {
	padded := string(s)
	if pad := len(padded) % 8; pad != 0 {
		padded += strings.Repeat("=", 8-pad)
	}
	return base32.StdEncoding.DecodeString(padded)
}

// Generate computes the 6-digit code for the given UTC time and secret.
func Generate(secret Secret, at time.Time) (string, error) {
	raw, err := secret.Bytes()
	if err != nil {
		return "", fmt.Errorf("totp.Generate: decode secret: %w", err)
	}
	return generate(raw, at.UTC().Unix()/defaultPeriod), nil
}

// Verify checks `code` against `secret` at `at`, tolerating ±1 30s window.
// Callers that must reject replays use VerifyStep and remember the step.
func Verify(secret Secret, code string, at time.Time) (bool, error) {
	_, ok, err := VerifyStep(secret, code, at)
	return ok, err
}

// VerifyStep is Verify that also returns the time-step the code matched, so
// the caller can refuse any later code for the same or an earlier step.
func VerifyStep(secret Secret, code string, at time.Time) (int64, bool, error) {
	raw, err := secret.Bytes()
	if err != nil {
		return 0, false, fmt.Errorf("totp.Verify: decode secret: %w", err)
	}
	want := strings.TrimSpace(code)
	if len(want) != defaultDigits {
		return 0, false, nil
	}
	step := at.UTC().Unix() / defaultPeriod
	for delta := -driftWindows; delta <= driftWindows; delta++ {
		if constantTimeEqual(generate(raw, step+int64(delta)), want) {
			return step + int64(delta), true, nil
		}
	}
	return 0, false, nil
}

// Otpauth returns the otpauth://totp/ URL suitable for QR-code rendering.
//
//	otpauth://totp/<Issuer>:<Account>?secret=<SECRET>&issuer=<Issuer>&algorithm=SHA1&digits=6&period=30
func Otpauth(secret Secret, issuer, account string) string {
	if issuer == "" {
		issuer = "SealKeeper"
	}
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{
		"secret":    {string(secret)},
		"issuer":    {issuer},
		"algorithm": {"SHA1"},
		"digits":    {fmt.Sprintf("%d", defaultDigits)},
		"period":    {fmt.Sprintf("%d", defaultPeriod)},
	}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// NewRecoveryCodes generates `n` recovery codes, each formatted as two
// 5-character base32-ish groups separated by a dash (e.g. "AB3K9-7M2VX").
// Returned codes are unique and contain 50 bits of entropy each.
func NewRecoveryCodes(n int) ([]string, error) {
	if n <= 0 {
		n = 8 // FR-C.5
	}
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // 32 chars, ambiguous omitted
	out := make([]string, 0, n)
	seen := make(map[string]struct{}, n)
	for len(out) < n {
		buf := make([]byte, 10)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		var b strings.Builder
		for i, x := range buf {
			if i == 5 {
				b.WriteByte('-')
			}
			b.WriteByte(alphabet[int(x)%len(alphabet)])
		}
		code := b.String()
		if _, dup := seen[code]; dup {
			continue
		}
		seen[code] = struct{}{}
		out = append(out, code)
	}
	return out, nil
}

// ConsumeRecovery looks up `code` (case- and whitespace-insensitive) in
// `codes`, removes it, and returns (newCodes, true) on hit. Useful when the
// caller fetches the stored recovery codes, calls this, and writes the
// shorter list back.
func ConsumeRecovery(codes []string, code string) ([]string, bool) {
	want := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), " ", ""))
	for i, c := range codes {
		if strings.EqualFold(strings.TrimSpace(c), want) {
			return append(append([]string(nil), codes[:i]...), codes[i+1:]...), true
		}
	}
	return codes, false
}

// ----- internals ------------------------------------------------------------

func generate(secret []byte, counter int64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(buf[:])
	hash := mac.Sum(nil)

	// RFC 4226 dynamic truncation.
	offset := int(hash[len(hash)-1] & 0x0f)
	code := int(hash[offset]&0x7f)<<24 |
		int(hash[offset+1])<<16 |
		int(hash[offset+2])<<8 |
		int(hash[offset+3])
	code %= pow10(defaultDigits)
	return fmt.Sprintf("%0*d", defaultDigits, code)
}

func pow10(n int) int {
	x := 1
	for i := 0; i < n; i++ {
		x *= 10
	}
	return x
}

// constantTimeEqual reports whether a and b are equal in constant time.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return hmac.Equal([]byte(a), []byte(b))
}

// ErrInvalidCode is returned by higher-level callers when verification
// rejects the supplied code; kept here so the package owns the canonical
// sentinel.
var ErrInvalidCode = errors.New("totp: invalid code")
