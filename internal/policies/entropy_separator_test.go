package policies

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sched75/sealkeeper/internal/elevations"
)

// Library entries holding a separator character used to be credited in full:
// G2 joins words with the separator and G1 turns whitespace into it, so
// different draws could print the same password and the server floor
// accepted policies far below their level.
func TestSeparatorInsideLibraryIsNotCredited(t *testing.T) {
	t.Parallel()
	mustJSON := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	dashes := make([]string, 1024)
	for i := range dashes {
		dashes[i] = strings.Repeat("-", i+1)
	}
	// 2^17 citations "w?w?…w" with ? in {' ', '-'}: all render "w-w-…-w".
	citations := make([]string, 1<<17)
	for i := range citations {
		var b strings.Builder
		b.WriteString("w")
		for bit := range 17 {
			if i&(1<<bit) != 0 {
				b.WriteString("-")
			} else {
				b.WriteString(" ")
			}
			b.WriteString("w")
		}
		citations[i] = b.String()
	}

	cases := []struct {
		name   string
		level  elevations.Level
		gen    Generator
		params string
		want   float64
	}{
		{"G2 dash words", elevations.LevelB3, GeneratorG2, mustJSON(map[string]any{
			"library": dashes, "numberOfWords": 11, "separatorOptions": []string{"-"}, "numericGroups": []any{},
		}), 0},
		{"G2 hyphenated entry next to its parts", elevations.LevelB1, GeneratorG2, mustJSON(map[string]any{
			"library": []string{"porte", "monnaie", "porte-monnaie"}, "numberOfWords": 40,
			"separatorOptions": []string{"-", "+"}, "numericGroups": []any{map[string]any{"digitsCount": 4}},
		}), 13.2},
		{"G1 space versus separator", elevations.LevelB1, GeneratorG1, mustJSON(map[string]any{
			"library": citations, "separatorOptions": []string{"-"},
			"numericGroups": []any{map[string]any{"position": "suffix", "digitsCount": 10}},
		}), 33.2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			rep, err := CalculateEntropy(c.gen, c.params)
			if err != nil {
				t.Fatalf("CalculateEntropy: %v", err)
			}
			if rep.MinBits != c.want {
				t.Fatalf("MinBits = %v (%+v), want %v", rep.MinBits, rep.Breakdown, c.want)
			}
			if err := checkEntropyFloor(c.level, c.gen, c.params); !errors.Is(err, ErrBelowFloor) {
				t.Fatalf("checkEntropyFloor(%s) = %v, want ErrBelowFloor", c.level, err)
			}
		})
	}
}

// Entries free of separator characters keep their full credit.
func TestSeparatorFreeLibraryKeepsCredit(t *testing.T) {
	t.Parallel()
	cases := []struct {
		gen    Generator
		params string
		want   float64
	}{
		// 2·log2(3) + log2(2) + 4·log2(10)
		{GeneratorG2, `{"library":["porte","monnaie","portemonnaie"],"numberOfWords":2,"separatorOptions":["-","+"]}`, 17.4},
		// A separator character is fine in an entry that is never joined.
		{GeneratorG2, `{"library":["a-b","c-d"],"numberOfWords":1,"numericGroups":[{"separator":""}]}`, 14.2},
		// log2(2) + log2(10) + 3·log2(10): citations differ in more than punctuation.
		{GeneratorG1, `{"library":["veni, vidi","alea jacta"],"separatorOptions":["-",",","+","/","~","|","_",":","!",";"],"numericGroups":[{"digitsCount":3}]}`, 14.2},
	}
	for _, c := range cases {
		rep, err := CalculateEntropy(c.gen, c.params)
		if err != nil {
			t.Fatalf("%s: %v", c.params, err)
		}
		if rep.MinBits != c.want {
			t.Errorf("%s: MinBits = %v (%+v), want %v", c.params, rep.MinBits, rep.Breakdown, c.want)
		}
	}
}
