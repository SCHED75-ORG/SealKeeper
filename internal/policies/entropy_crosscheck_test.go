package policies

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The browser bundle (web/src/entropy.js) is the reference calculator. This
// test runs it through node on a corpus of parameter sets and requires the
// Go port to agree exactly: same accept/refuse decision, same figures, same
// breakdown. It is skipped when node is not installed.

const crosscheckScript = `
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const [entropyPath, corpusPath] = process.argv.slice(2);
const { calculateEntropy } = await import(pathToFileURL(entropyPath).href);
const corpus = JSON.parse(readFileSync(corpusPath, "utf8"));
const out = corpus.map((c) => {
  try {
    const r = calculateEntropy({ generator: c.generator, parameters: c.parameters });
    return { ok: true, report: { minBits: r.minBits, maxBits: r.maxBits, expectedBits: r.expectedBits, breakdown: r.breakdown } };
  } catch (e) {
    return { ok: false, error: String(e && e.message) };
  }
});
process.stdout.write(JSON.stringify(out));
`

type crossCase struct {
	gen    Generator
	params string
}

func TestEntropyMatchesJSCalculator(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed: JS cross-check skipped")
	}
	entropyJS, err := filepath.Abs(filepath.Join("..", "..", "web", "src", "entropy.js"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(entropyJS); err != nil {
		t.Skipf("JS calculator not found: %v", err)
	}

	corpus := append(fixedCorpus(), randomCorpus(rand.New(rand.NewPCG(20, 26)), 600)...)

	// The reveal page receives the parameters re-encoded by the server
	// (resolvedPolicy unmarshals then marshals them): feed node that form.
	type jsCase struct {
		Generator  string `json:"generator"`
		Parameters any    `json:"parameters"`
	}
	in := make([]jsCase, len(corpus))
	for i, c := range corpus {
		var p any
		if err := json.Unmarshal([]byte(c.params), &p); err != nil {
			t.Fatalf("case %d: corpus JSON: %v", i, err)
		}
		in[i] = jsCase{string(c.gen), p}
	}
	dir := t.TempDir()
	corpusPath := filepath.Join(dir, "corpus.json")
	scriptPath := filepath.Join(dir, "crosscheck.mjs")
	data, _ := json.Marshal(in)
	if err := os.WriteFile(corpusPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scriptPath, []byte(crosscheckScript), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(node, scriptPath, entropyJS, corpusPath) // #nosec G204 -- test-only, fixed arguments
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("node: %v\n%s", err, stderr.String())
	}
	var got []struct {
		OK     bool          `json:"ok"`
		Error  string        `json:"error"`
		Report EntropyReport `json:"report"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("node output: %v", err)
	}
	if len(got) != len(corpus) {
		t.Fatalf("node returned %d results for %d cases", len(got), len(corpus))
	}

	accepted := 0
	for i, c := range corpus {
		rep, err := CalculateEntropy(c.gen, c.params)
		js := got[i]
		switch {
		case js.OK != (err == nil):
			t.Errorf("case %d %s %s:\n  JS ok=%v (%s)\n  Go err=%v", i, c.gen, clip(c.params), js.OK, js.Error, err)
		case js.OK:
			accepted++
			if fmt.Sprint(rep) != fmt.Sprint(js.Report) {
				t.Errorf("case %d %s %s:\n  JS %+v\n  Go %+v", i, c.gen, clip(c.params), js.Report, rep)
			}
		}
	}
	t.Logf("%d cases, %d accepted by both calculators", len(corpus), accepted)
	// Guard against a corpus that only exercises the refusal paths.
	if accepted < len(corpus)/2 {
		t.Errorf("only %d of %d cases accepted: corpus too degenerate", accepted, len(corpus))
	}
}

func fixedCorpus() []crossCase {
	lib := func(n int) string {
		b := []byte("[")
		for i := 0; i < n; i++ {
			if i > 0 {
				b = append(b, ',')
			}
			b = fmt.Appendf(b, "%q", fmt.Sprintf("w%04d", i))
		}
		return string(append(b, ']'))
	}
	return []crossCase{
		// G3
		{GeneratorG3, `{}`},
		{GeneratorG3, `{"length":4}`},
		{GeneratorG3, `{"length":17}`},
		{GeneratorG3, `{"length":256,"excludeAmbiguous":true}`},
		{GeneratorG3, `{"length":20,"alphabetSize":62}`},
		{GeneratorG3, `{"length":20,"excludeAmbiguous":true,"alphabetSize":57}`},
		{GeneratorG3, `{"length":20,"alphabetSize":94}`},
		{GeneratorG3, `{"length":0}`},
		{GeneratorG3, `{"length":12.5}`},
		{GeneratorG3, `{"length":"20"}`},
		{GeneratorG3, `{"length":null}`},
		{GeneratorG3, `{"excludeAmbiguous":"yes"}`},
		{GeneratorG3, `{"blockSize":-1}`},
		{GeneratorG3, `{"blockSeparator":5}`},
		// G2
		{GeneratorG2, `{"library":["alpha","bravo","charlie","delta"]}`},
		{GeneratorG2, `{"library":` + lib(256) + `,"numberOfWords":8}`},
		{GeneratorG2, `{"library":` + lib(7776) + `,"numberOfWords":6}`},
		{GeneratorG2, `{"library":["a","a","b"],"dictionarySize":2}`},
		{GeneratorG2, `{"library":["a","a","b"],"dictionarySize":3}`},
		{GeneratorG2, `{"library":["solo"],"numberOfWords":1,"numericGroups":[]}`},
		{GeneratorG2, `{"library":["a","b"],"numberOfWords":1,"numericGroups":[{"separator":""}]}`},
		{GeneratorG2, `{"library":["a","b"],"numberOfWords":1,"numericGroups":[{"separator":"-","digitsCount":0}]}`},
		{GeneratorG2, `{"library":["a","b"],"numericGroups":[{"digitsCount":6},{"digitsCount":9}]}`},
		{GeneratorG2, `{"library":["a","b"],"separatorOptions":["-","-","_"]}`},
		{GeneratorG2, `{"library":["a","b"],"separatorOptions":[]}`},
		{GeneratorG2, `{"library":["a",""]}`},
		{GeneratorG2, `{"library":"dict-42"}`},
		{GeneratorG2, `{}`},
		{GeneratorG2, `{"library":["a","b"],"numberOfWords":65}`},
		{GeneratorG2, `{"library":["a","b"],"transforms":[{"code":"T99","active":true}]}`},
		{GeneratorG2, `{"library":["a","b"],"numericGroups":[[]]}`},
		{GeneratorG2, `{"library":["a","b"],"numericGroups":[null]}`},
		{GeneratorG2, `{"library":["a","b"],"numericGroups":[{"position":"middle","separator":null}]}`},
		{GeneratorG2, `{"library":["a","b"],"numericGroups":[{"position":null}]}`},
		{GeneratorG2, `{"library":["a","b"],"numericGroups":[{"position":"top"}]}`},
		// G1
		{GeneratorG1, `{"library":["veni vidi vici","alea jacta est"]}`},
		{GeneratorG1, `{"library":["veni vidi vici","alea jacta est"],"numericGroups":[]}`},
		{GeneratorG1, `{"library":["veni vidi vici","Veni Vidi Vici","VENI VIDI VICI"],"transforms":[{"code":"T01","active":true,"mode":"random"}]}`},
		{GeneratorG1, `{"library":["Été à Paris","Hiver à Lyon"],"transforms":[{"code":"T06","active":true,"mode":"random"},{"code":"T07","active":true,"mode":"random"}]}`},
		{GeneratorG1, `{"library":["ΟΔΟΣ ΚΑΛΗ","οδος καλη","Straße groß","STRASSE GROSS"],"transforms":[{"code":"T01","active":true,"mode":"random"}]}`},
		{GeneratorG1, `{"library":["İstanbul hızlı","istanbul hızlı","Iİ ıi"],"transforms":[{"code":"T03","active":true,"mode":"random","parameters":{"probability":0.3}},{"code":"T01","active":true,"mode":"random"}]}`},
		{GeneratorG1, `{"library":["😀 smile now","😁 smile now","a😀b c😀d"],"transforms":[{"code":"T05","active":true,"mode":"random","parameters":{"firstN":1}},{"code":"T04","active":true,"mode":"random"}]}`},
		{GeneratorG1, `{"library":["😀😁 x","😀😂 x"],"transforms":[{"code":"T05","active":true,"mode":"random","parameters":{"firstN":3}}]}`},
		{GeneratorG1, "{\"library\":[\"nbsp\u00a0here\",\"zero\ufeffwidth\",\"nel\u0085x y\",\"tab\\there\"],\"transforms\":[{\"code\":\"T08\",\"active\":true,\"mode\":\"random\",\"parameters\":{\"symbols\":[\"-\",\"ab\",\"_\",\" \"]}}]}"},
		{GeneratorG1, `{"library":["a-b c","ab c","a_b c","a b c"],"transforms":[{"code":"T08","active":true,"mode":"random","parameters":{"symbols":["-","+"]}}]}`},
		{GeneratorG1, `{"library":["one two three","four five six","seven eight nine"],"transforms":[{"code":"T09","active":true,"mode":"random","parameters":{"length":10}},{"code":"T02","active":true,"mode":"random"}]}`},
		{GeneratorG1, `{"library":["one two","three four"],"transforms":[{"code":"T09","active":true,"mode":"random","parameters":"abcdef"}]}`},
		{GeneratorG1, `{"library":["one two","three four"],"transforms":[{"code":"T09","active":true,"mode":"random","parameters":[1,2]}]}`},
		{GeneratorG1, `{"library":["one two","three four"],"transforms":[{"code":"T02","active":true,"mode":"random","parameters":{"probability":null}}]}`},
		{GeneratorG1, `{"library":["one two","three four"],"transforms":[{"code":"T02","active":true,"parameters":{"probability":1}}]}`},
		{GeneratorG1, `{"library":["one two","three four"],"transforms":[{"code":"T02","active":"yes","mode":"random"},{"code":"T03","active":1,"mode":"random"}]}`},
		{GeneratorG1, `{"library":["one two","three four"],"transforms":[{"code":"T02","active":0},{"code":"T02","active":true}]}`},
		{GeneratorG1, `{"library":["one two","three four"],"transforms":[{"code":"T02","active":true},{"code":"T02","active":true}]}`},
		{GeneratorG1, `{"library":["one two","three four"],"transforms":[{"code":"T01","active":true,"mode":null}]}`},
		{GeneratorG1, `{"library":["one two","three four"],"transforms":[{"code":"T01","active":true,"mode":"random","parameters":{"candidates":["lowercase","Upper"]}}]}`},
		{GeneratorG1, `{"library":["one two","three four"],"transforms":[[]]}`},
		{GeneratorG1, `{"library":["one two","three four"],"corpusSize":2}`},
		{GeneratorG1, `{"library":["one two","three four"],"corpusSize":3}`},
		// A corpus large enough to clear B1 (> 125k citations) must not
		// overflow the JS call stack: Go accepts it, so must the bundle.
		{GeneratorG1, `{"library":` + bigCorpus(130000) + `}`},
	}
}

// clip shortens a case's parameters for a failure message.
func clip(s string) string {
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}

// bigCorpus returns n distinct citations as a JSON array.
func bigCorpus(n int) string {
	b := []byte("[")
	for i := 0; i < n; i++ {
		if i > 0 {
			b = append(b, ',')
		}
		b = fmt.Appendf(b, "%q", fmt.Sprintf("Citation numero %d du corpus", i))
	}
	return string(append(b, ']'))
}

var crossCitations = []string{
	"veni vidi vici", "Veni vidi vici", "VENI VIDI VICI", "alea jacta est", "Alea Jacta Est",
	"Été à Paris", "ete a paris", "L'été indien", "ΟΔΟΣ ΚΑΛΗ", "Straße groß", "İstanbul hızlı",
	"😀 smile now", "a😀b c😀d", "x", "X", "Tout_va_bien", "tout va bien", "nbsp\u00a0here now",
	"zero\ufeffwidth", "nel\u0085x y", "  padded  words ", "Señor Nuñez", "ǅemal ǈuka",
	"123 456", "!!! ???", "élan vital", "ELAN VITAL", "e l a n", "Ab-Cd ef", "ab+cd ef",
	"to be or not to be", "be to not or be to", "eb ot ro ton ot eb", "gaze blot", "9a3e b10t",
	"Carpe diem", "carpediem", "Cogito ergo sum", "sum ergo cogito", "Ὀδυσσεύς", "ﬁne ﬂow",
}

func randomCorpus(r *rand.Rand, n int) []crossCase {
	pick := func(list []string, max int) []string {
		k := 1 + r.IntN(max)
		out := make([]string, k)
		for i := range out {
			out[i] = list[r.IntN(len(list))]
		}
		return out
	}
	var out []crossCase
	for len(out) < n {
		params := map[string]any{}
		gen := GeneratorG1
		switch r.IntN(6) {
		case 0:
			gen = GeneratorG2
			params["library"] = pick(crossCitations, 12)
			if r.IntN(2) == 0 {
				params["numberOfWords"] = 1 + r.IntN(10)
			}
		case 1:
			gen = GeneratorG3
			params["length"] = 1 + r.IntN(40)
			params["excludeAmbiguous"] = r.IntN(2) == 0
		default:
			params["library"] = pick(crossCitations, 8)
			params["transforms"] = randomTransforms(r)
		}
		if gen != GeneratorG3 {
			switch r.IntN(4) {
			case 0:
				params["numericGroups"] = []any{}
			case 1:
				groups := []any{}
				for range 1 + r.IntN(3) {
					g := map[string]any{"digitsCount": r.IntN(5)}
					if r.IntN(3) == 0 {
						g["separator"] = []string{"", "-", "."}[r.IntN(3)]
					}
					groups = append(groups, g)
				}
				params["numericGroups"] = groups
			}
			if r.IntN(3) == 0 {
				params["separatorOptions"] = pick([]string{"-", "_", ".", "+", "ab"}, 4)
			}
		}
		data, _ := json.Marshal(params)
		out = append(out, crossCase{gen, string(data)})
	}
	return out
}

func randomTransforms(r *rand.Rand) []any {
	codes := []string{"T01", "T02", "T03", "T04", "T05", "T06", "T07", "T08", "T09"}
	r.Shuffle(len(codes), func(i, j int) { codes[i], codes[j] = codes[j], codes[i] })
	var out []any
	for _, code := range codes[:r.IntN(5)] {
		t := map[string]any{"code": code, "active": r.IntN(6) != 0}
		switch r.IntN(4) {
		case 0:
			t["mode"] = "deterministic"
		case 1, 2:
			t["mode"] = "random"
		}
		p := map[string]any{}
		switch code {
		case "T01":
			if r.IntN(2) == 0 {
				modes := []string{"lowercase", "uppercase", "camelCase", "PascalCase", "SCREAMING_SNAKE"}
				r.Shuffle(len(modes), func(i, j int) { modes[i], modes[j] = modes[j], modes[i] })
				p["candidates"] = modes[:1+r.IntN(len(modes))]
			}
		case "T02", "T03":
			if r.IntN(2) == 0 {
				p["probability"] = []float64{0.1, 0.25, 0.5, 0.7, 0.9}[r.IntN(5)]
			}
		case "T05":
			p["firstN"] = 1 + r.IntN(4)
		case "T08":
			if r.IntN(2) == 0 {
				syms := []string{"-", "+", "ab", "_", "!", " ", "😀"}
				r.Shuffle(len(syms), func(i, j int) { syms[i], syms[j] = syms[j], syms[i] })
				p["symbols"] = syms[:1+r.IntN(4)]
			}
		case "T09":
			p["length"] = 1 + r.IntN(10)
		}
		if len(p) > 0 {
			t["parameters"] = p
		}
		out = append(out, t)
	}
	return out
}
