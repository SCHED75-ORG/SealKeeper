package strength

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Regression: the master-secret check imported internal/admin for the
// estimator, which dragged the storage layer and every SQL driver into
// internal/config. The estimator lives here now and must stay a leaf:
// standard library only, so both callers can import it. config may also
// import webbundle, which holds only the embedded JS bundle.
func TestStandardLibraryOnly(t *testing.T) {
	t.Parallel()
	configMay := map[string]bool{
		"github.com/sched75/sealkeeper/internal/strength":  true,
		"github.com/sched75/sealkeeper/internal/webbundle": true,
	}
	configDir := filepath.Join("..", "config")
	for _, dir := range []string{".", filepath.Join("..", "webbundle"), configDir} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			ast, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range ast.Imports {
				path, _ := strconv.Unquote(imp.Path.Value)
				internal := strings.HasPrefix(path, "github.com/sched75/sealkeeper/internal/")
				switch {
				case dir != configDir && strings.Contains(strings.SplitN(path, "/", 2)[0], "."):
					t.Errorf("%s imports %s: strength and webbundle must stay standard-library only", f, path)
				case dir == configDir && internal && !configMay[path]:
					t.Errorf("%s imports %s: config may only reach the estimator through strength", f, path)
				}
			}
		}
	}
}

// Estimate scores the whole input; cutting at bcrypt's 72 bytes is the
// admin wrapper's job, not the estimator's.
func TestEstimateCountsWholeInput(t *testing.T) {
	t.Parallel()
	weak := strings.Repeat("password", 9) // 72 bytes, all pattern
	tail := "Zq7#vK2!pW9@xR4$"
	short, _ := Estimate(weak)
	long, _ := Estimate(weak + tail)
	if long-short < 60 {
		t.Fatalf("Estimate ignored bytes past 72: %.0f -> %.0f bits", short, long)
	}
}

func TestEstimateUsesContext(t *testing.T) {
	t.Parallel()
	s := "acmecorp-production-2026-acmecorp"
	without, _ := Estimate(s)
	with, codes := Estimate(s, "sk.acmecorp.test", "production")
	if with >= without {
		t.Fatalf("context did not lower the estimate: %.0f -> %.0f", without, with)
	}
	if !strings.Contains(strings.Join(codes, ","), Context) {
		t.Fatalf("codes = %v, want %q", codes, Context)
	}
}

func TestLetterPairs(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		in               string
		pairs, plausible int
	}{
		{"", 0, 0},
		{"a1b2c3", 0, 0},      // digits break every run
		{"The", 2, 2},         // th, he
		{"Éte-ST", 3, 3},      // et, te | st: accents and case folded
		{"qxzj", 3, 0},        // qx, xz, zj
		{"le chat", 4, 4},     // le | ch, ha, at
		{"Kq9vXz7w", 3, 0},    // kq | vx, xz
		{"rendez-vous", 8, 6}, // re en nd de, not ez | ou us, not vo
	} {
		pairs, plausible := LetterPairs(c.in)
		if pairs != c.pairs || plausible != c.plausible {
			t.Errorf("LetterPairs(%q) = %d, %d; want %d, %d", c.in, pairs, plausible, c.pairs, c.plausible)
		}
	}
	if PlausiblePairShare < 0.2 || PlausiblePairShare > 0.3 {
		t.Errorf("PlausiblePairShare = %.3f, want ~0.24 (160 pairs of 676)", PlausiblePairShare)
	}
}
