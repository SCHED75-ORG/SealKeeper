package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode"

	"github.com/sched75/sealkeeper/internal/strength"
)

const masterSecretHint = "SK_MASTER_SECRET must be 32 random bytes, base64-encoded (openssl rand -base64 32)"

// checkMasterSecret refuses master secrets that would make the at-rest
// encryption (TOTP seeds, recovery codes, SMTP password) and the MAC keys
// derived from it (audit chain, IP pseudonyms) worthless: the placeholders
// shipped in examples, short values, and values that were made by hand
// rather than drawn at random. context lists strings an attacker knows
// (instance domain, base URL).
//
// The value is read the way it was most likely produced. Hex (letters and
// digits) and base64 (upper, lower and digits, 24+ bytes) are decoded and
// the bytes must look uniformly random (checkKeyBytes): a phrase, a
// pattern or a counter that was merely encoded is refused. Every value
// must then read as random characters (checkSecretText): no repeated
// block, no run of words, and an estimated guessing entropy of at least
// masterSecretMinBits.
//
// Each statistical test refuses only what a uniformly random value would
// show with probability below randomFailBound, so `openssl rand -base64
// 32`, `openssl rand -hex 32` and random legacy passphrases of 32+
// characters are never refused in practice (the ~80 tests together stay
// under 1e-8). Hand-made legacy passphrases (dictionary words, the product
// name, a block typed three times) are refused: see the upgrade note in
// QUICKSTART.md.
func checkMasterSecret(secret string, context ...string) error {
	lower := strings.ToLower(secret)
	for _, placeholder := range []string{"replace_me", "replace-me", "changeme", "change_me", "change-me", "example"} {
		if strings.Contains(lower, placeholder) {
			return fmt.Errorf("SK_MASTER_SECRET looks like a placeholder; %s", masterSecretHint)
		}
	}
	if len(secret) < 32 { // a base64 32-byte key is 43+ characters
		return errors.New(masterSecretHint)
	}
	if raw, form := decodeMasterSecret(secret); raw != nil {
		if err := checkKeyBytes(raw, context); err != nil {
			return fmt.Errorf("SK_MASTER_SECRET decodes (%s) to %w; %s", form, err, masterSecretHint)
		}
	}
	if err := checkSecretText(secret, isHexValue(secret), context); err != nil {
		return fmt.Errorf("SK_MASTER_SECRET %w; %s", err, masterSecretHint)
	}
	return nil
}

// randomFailBound is the most often a uniformly random value may fail any
// single statistical test below.
const randomFailBound = 1e-10

// masterSecretMinBits is the floor on the estimated guessing entropy, an
// estimate that assumes the attacker knows the pattern. Hand-made values
// (product words, repeats, a few dictionary words) score under 60; random
// values of 32+ characters score above it with a wide margin, even
// digits-only (no draw under 69 in 100 000; hex 115+, base64 245+).
const masterSecretMinBits = 64

// maxAnalysed caps how much of a value the tests read (bytes or
// characters): a value whose first 256 are random is strong, and the
// estimator is cubic in its input.
const maxAnalysed = 256

// masterSecretContext are the words an operator reaches for when naming a
// key by hand; the estimator charges them almost nothing.
var masterSecretContext = []string{
	"production", "prod", "staging", "master", "secret", "key", "passphrase", "password", "instance",
}

// decodeMasterSecret returns the bytes a hex or base64 value encodes, and
// which form it was read as. Only values whose alphabet a random encoding
// would fill are decoded: a random hex string mixes letters and digits, a
// random base64 one upper case, lower case and digits. A lower-case
// passphrase that happens to be valid base64 decodes to skewed bytes, and
// testing those as random would refuse it for nothing.
func decodeMasterSecret(secret string) ([]byte, string) {
	if isHexValue(secret) {
		raw, err := hex.DecodeString(secret[:len(secret)&^1])
		if err == nil {
			return raw, "hex"
		}
	}
	if !hasClasses(secret, unicode.IsUpper, unicode.IsLower, unicode.IsDigit) {
		return nil, ""
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := enc.DecodeString(secret); err == nil && len(raw) >= 24 {
			return raw, "base64"
		}
	}
	return nil, ""
}

func isHexValue(s string) bool {
	if len(s) < 32 || !hasClasses(s, unicode.IsLetter, unicode.IsDigit) {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}

func hasClasses(s string, classes ...func(rune) bool) bool {
	for _, in := range classes {
		if strings.IndexFunc(s, in) < 0 {
			return false
		}
	}
	return true
}

// checkKeyBytes refuses decoded bytes that were not drawn at random: too
// few distinct values, a value or block repeated at some offset (zeros, a
// 17-byte pattern, a counter after a zero run), an arithmetic or quadratic
// progression, or more printable or letter bytes than chance allows
// (an encoded phrase, even with a few bytes changed). The bytes are then
// read as text (byteText) and must not pair up like words or be cheap to
// guess: that catches a short phrase with a byte or two changed, which
// the counts above are too coarse to see in 16 bytes.
func checkKeyBytes(raw []byte, context []string) error {
	if len(raw) > maxAnalysed {
		raw = raw[:maxAnalysed]
	}
	n := len(raw)
	if fewDistinct(raw) {
		return errors.New("a degenerate key (too few distinct bytes)")
	}
	if s := periodicShift(raw, 1.0/256); s > 0 {
		return errors.New("a degenerate key (repeated bytes or block)")
	}
	d1 := diffs(raw)
	if rareRun(n, longestEqualRun(d1)) || rareRun(n, longestEqualRun(diffs(d1))) {
		return errors.New("a degenerate key (sequential bytes)")
	}
	printable, letters := 0, 0
	for _, b := range raw {
		if b >= 0x20 && b <= 0x7e {
			printable++
		}
		if b == ' ' || (b|0x20 >= 'a' && b|0x20 <= 'z') {
			letters++
		}
	}
	if binomialTail(n, printable, 95.0/256) < randomFailBound || binomialTail(n, letters, 53.0/256) < randomFailBound {
		return errors.New("text, not random bytes")
	}
	if err := checkWords(byteText(raw), context); err != nil {
		return errors.New("text, not random bytes")
	}
	return nil
}

// byteText reads raw as text: printable ASCII as itself, any other byte
// as a non-ASCII rune, which the estimator charges like a character from
// a large pool and which breaks a run of letters.
func byteText(raw []byte) string {
	out := make([]rune, len(raw))
	for i, b := range raw {
		out[i] = rune(b)
		if b < 0x20 || b > 0x7e {
			out[i] = 0x100 + rune(b)
		}
	}
	return string(out)
}

// fewDistinct reports whether raw holds so few distinct byte values that
// uniform bytes would do so with probability below randomFailBound (18 or
// fewer of 32: a random key holds ~30).
func fewDistinct(raw []byte) bool {
	var seen [256]bool
	distinct := 0
	for _, b := range raw {
		if !seen[b] {
			seen[b] = true
			distinct++
		}
	}
	// p[j]: probability that the bytes drawn so far hold j distinct values.
	p := make([]float64, len(raw)+1)
	p[0] = 1
	for i := 0; i < len(raw); i++ {
		for j := i + 1; j > 0; j-- {
			p[j] = p[j]*float64(j)/256 + p[j-1]*float64(257-j)/256
		}
		p[0] = 0
	}
	cdf := 0.0
	for j := 0; j <= distinct; j++ {
		cdf += p[j]
	}
	return cdf < randomFailBound
}

// periodicShift returns the first offset s at which x[i] == x[i+s] holds
// more often than chance allows when each symbol matches with probability
// p, or 0. It catches a repeated value, a repeated block of any length
// and a block repeated with something in between.
func periodicShift[T comparable](x []T, p float64) int {
	for s := 1; s < len(x); s++ {
		matches := 0
		for i := 0; i+s < len(x); i++ {
			if x[i] == x[i+s] {
				matches++
			}
		}
		if binomialTail(len(x)-s, matches, p) < randomFailBound {
			return s
		}
	}
	return 0
}

func diffs(x []byte) []byte {
	if len(x) < 2 {
		return nil
	}
	out := make([]byte, len(x)-1)
	for i := range out {
		out[i] = x[i+1] - x[i]
	}
	return out
}

// longestEqualRun is the length of the longest run of equal consecutive
// values in x.
func longestEqualRun(x []byte) int {
	best, run := 0, 0
	for i := range x {
		if i > 0 && x[i] == x[i-1] {
			run++
		} else {
			run = 1
		}
		best = max(best, run)
	}
	return best
}

// rareRun reports whether a run of r equal differences (r-1 coincidences
// of probability 1/256 each) anywhere in n random bytes is rarer than
// randomFailBound.
func rareRun(n, r int) bool {
	return r > 1 && float64(n)*math.Pow(256, -float64(r-1)) < randomFailBound
}

// checkSecretText refuses a value whose characters were not drawn at
// random: a block repeated at some offset, then checkWords (only the
// estimate for hex). The error reads after "SK_MASTER_SECRET ".
func checkSecretText(secret string, isHex bool, context []string) error {
	runes := []rune(secret)
	if len(runes) > maxAnalysed {
		runes = runes[:maxAnalysed]
	}
	distinct := map[rune]bool{}
	for _, r := range runes {
		distinct[r] = true
	}
	// 1/distinct over-estimates the chance match of a random value, whose
	// alphabet is at least as large as what it shows.
	if periodicShift(runes, 1/float64(len(distinct))) > 0 {
		return errors.New("repeats a block of characters")
	}
	if isHex {
		// Six letters pair up like "deadbeef" by chance; the decoded
		// bytes were read as text already.
		if bits, _ := strength.Estimate(string(runes), append(masterSecretContext, context...)...); bits < masterSecretMinBits {
			return errGuessable
		}
		return nil
	}
	return checkWords(string(runes), context)
}

var errGuessable = errors.New("is guessable (repeated, sequential or dictionary-based)")

// checkWords refuses text whose letters pair up like English or French
// words more often than random letters would, or whose estimated guessing
// entropy is under masterSecretMinBits.
func checkWords(text string, context []string) error {
	pairs, plausible := strength.LetterPairs(text)
	if binomialTail(pairs, plausible, strength.PlausiblePairShare) < randomFailBound {
		return errors.New("reads as words, not random characters")
	}
	if bits, _ := strength.Estimate(text, append(masterSecretContext, context...)...); bits < masterSecretMinBits {
		return errGuessable
	}
	return nil
}

// binomialTail is P(X >= k) for X ~ Binomial(n, p).
func binomialTail(n, k int, p float64) float64 {
	if k <= 0 {
		return 1
	}
	if p >= 1 {
		return 1
	}
	lnN, _ := math.Lgamma(float64(n + 1))
	sum := 0.0
	for i := k; i <= n; i++ {
		lnI, _ := math.Lgamma(float64(i + 1))
		lnR, _ := math.Lgamma(float64(n - i + 1))
		sum += math.Exp(lnN - lnI - lnR + float64(i)*math.Log(p) + float64(n-i)*math.Log1p(-p))
	}
	return sum
}
