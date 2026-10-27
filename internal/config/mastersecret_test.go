package config

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

// Regression: a decoded key passed with any one byte changed (the checks
// demanded all-printable bytes, a perfect progression, <= 16 distinct
// values), hex hid any phrase, and passphrases of English or French words,
// product words diluted with other words, or a block repeated with
// separators all cleared the entropy estimate.
func TestValidate_MasterSecretHandMade(t *testing.T) {
	t.Parallel()
	b64 := base64.StdEncoding.EncodeToString
	keyFrom := func(f func(i int) byte) string {
		raw := make([]byte, 32)
		for i := range raw {
			raw[i] = f(i)
		}
		return b64(raw)
	}
	block17 := []byte{0x9a, 0x01, 0xf3, 0x77, 0x10, 0xc4, 0x5e, 0xbb, 0x02, 0xe9, 0x6d, 0x38, 0xa1, 0x4f, 0x80, 0xd5, 0x3c}
	for _, c := range []struct{ name, secret string }{
		{"phrase with one control byte", b64([]byte("sealkeeper production master k\x01y"))},
		{"phrase then four high bytes", b64(append([]byte("sealkeeper production master"), 0xff, 0xfe, 0xfd, 0xfc))},
		{"progression, last byte changed", keyFrom(func(i int) byte {
			if i == 31 {
				return 0x00
			}
			return byte(0x80 + i)
		})},
		{"squares", keyFrom(func(i int) byte { return byte(i * i) })},
		{"17-byte block repeated", b64(append(append([]byte{}, block17...), block17[:15]...))},
		{"zeros then a counter", keyFrom(func(i int) byte {
			if i < 15 {
				return 0
			}
			return byte(i - 14)
		})},
		{"hex of a phrase", hex.EncodeToString([]byte("sealkeeper production master key"))},
		{"hex of a short phrase", hex.EncodeToString([]byte("sealkeeper prod!"))},
		{"product words diluted", "ThisIsMyVeryLongProductionSecretForSealKeeper!"},
		{"english passphrase", "correct horse battery staple and then some more"},
		{"english sentence", "my dog is called rex and he likes to eat bones"},
		{"french sentence", "le chat de ma grand mere mange des souris"},
		{"one long word and a year", "supercalifragilisticexpialidocious2026"},
		{"block repeated with separators", "Tr0ub4dor&3-Tr0ub4dor&3-Tr0ub4dor&3"},
		{"base64 block repeated", strings.Repeat("ZXhhbXBsZQ==", 3)},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if err := productionConfig(c.secret).validate(); err == nil {
				t.Fatalf("validate() accepted hand-made secret %q", c.secret)
			}
		})
	}
}

// Random values in every shape an operator may have used must be
// accepted: a false refusal stops a correctly configured instance. Each
// test is bounded analytically (randomFailBound); this pins the shapes,
// including a base64 key with no digit and a 32-character lower-case
// passphrase that is also valid base64.
func TestValidate_RandomMasterSecretShapes(t *testing.T) {
	t.Parallel()
	alphabets := []string{
		"0123456789",
		"0123456789abcdef",
		"abcdefghijklmnopqrstuvwxyz",
		"abcdefghijklmnopqrstuvwxyz0123456789",
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*+-=?@^_~",
	}
	for i := 0; i < 50; i++ {
		key := randomBytes(t, 32)
		secrets := []string{
			base64.StdEncoding.EncodeToString(key),
			base64.RawStdEncoding.EncodeToString(key),
			base64.URLEncoding.EncodeToString(key),
			base64.RawURLEncoding.EncodeToString(key),
			base64.StdEncoding.EncodeToString(randomBytes(t, 24)),
			base64.StdEncoding.EncodeToString(randomBytes(t, 48)),
			hex.EncodeToString(key),
			strings.ToUpper(hex.EncodeToString(key)),
			hex.EncodeToString(key[:16]),
		}
		for _, a := range alphabets {
			secrets = append(secrets, randomString(t, a, 32), randomString(t, a, 44))
		}
		for _, s := range secrets {
			if err := productionConfig(s).validate(); err != nil {
				t.Fatalf("random secret %q refused: %v", s, err)
			}
		}
	}
	noDigit := "TDtHoMKTZdiGfTrwpUKvAHPzLwJiImHxk+XQ/abcdefgh"[:43] + "="
	if err := productionConfig(noDigit).validate(); err != nil {
		t.Fatalf("base64 key without a digit refused: %v", err)
	}
}

// The thresholds follow from the bound: uniform bytes hold 18 or fewer
// distinct values of 32 with probability ~5e-12, 19 or fewer ~1.4e-10.
func TestFewDistinctThreshold(t *testing.T) {
	t.Parallel()
	withDistinct := func(d int) []byte {
		raw := make([]byte, 32)
		for i := range raw {
			raw[i] = byte((i % d) * 37) // distinct values, no progression
		}
		return raw
	}
	if !fewDistinct(withDistinct(18)) {
		t.Error("18 distinct bytes of 32 not flagged")
	}
	if fewDistinct(withDistinct(19)) {
		t.Error("19 distinct bytes of 32 flagged; a random key has that with probability 1.4e-10")
	}
}

func TestBinomialTail(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		n, k int
		p    float64
		want float64
	}{
		{10, 0, 0.5, 1},
		{10, 10, 0.5, 1.0 / 1024},
		{10, 9, 0.5, 11.0 / 1024},
		{4, 2, 0.25, 1 - (81.0+108.0)/256},
	} {
		if got := binomialTail(c.n, c.k, c.p); got < c.want*(1-1e-9) || got > c.want*(1+1e-9) {
			t.Errorf("binomialTail(%d, %d, %g) = %g, want %g", c.n, c.k, c.p, got, c.want)
		}
	}
}

// The key eval mode mints for itself is what production demands.
func TestEvalGeneratedMasterSecretIsStrong(t *testing.T) {
	t.Setenv("SK_MODE", "eval")
	t.Setenv("SK_MASTER_SECRET", "")
	t.Setenv("SK_DATABASE_URL", "sqlite://"+t.TempDir()+"/x.db")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := checkMasterSecret(cfg.MasterSecret); err != nil {
		t.Fatalf("eval-generated master secret fails the production check: %v", err)
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func randomString(t *testing.T, alphabet string, n int) string {
	t.Helper()
	var b bytes.Buffer
	for b.Len() < n {
		i, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			t.Fatal(err)
		}
		b.WriteByte(alphabet[i.Int64()])
	}
	return b.String()
}
