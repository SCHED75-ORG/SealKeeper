package policies

// Server-side mirror of the browser entropy calculator.
//
// web/src/entropy.js and web/src/params.js are the reference: this file
// ports them line for line so the server can refuse, at save time, a policy
// whose entropy is below its ANSSI level floor (PRD A FR-A.G1.5 / G2.4 /
// G3.3) instead of trusting a badge computed in the admin's browser.
// entropy_crosscheck_test.go runs the JS calculator through node on a corpus
// of parameter sets and requires identical reports, so any change on one
// side must be mirrored on the other.
//
// JavaScript string semantics are reproduced where the calculator depends
// on them: whitespace is the ECMAScript \s set, slices and w[0] count UTF-16
// code units (a cut astral character leaves a lone high surrogate, kept here
// as its WTF-8 encoding so texts stay comparable), and case mapping uses the
// full Unicode mappings of String.prototype.toLowerCase / toUpperCase.

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/unicode/norm"

	"github.com/sched75/sealkeeper/internal/elevations"
)

// EntropyComponent is one line of an EntropyReport breakdown.
type EntropyComponent struct {
	Component string  `json:"component"`
	Bits      float64 `json:"bits"`
}

// EntropyReport mirrors the EntropyReport of web/src/entropy.js. Every
// credit is a lower bound, so the three figures coincide.
type EntropyReport struct {
	MinBits      float64            `json:"minBits"`
	MaxBits      float64            `json:"maxBits"`
	ExpectedBits float64            `json:"expectedBits"`
	Breakdown    []EntropyComponent `json:"breakdown"`
}

// LevelFloor is the minimum entropy, in bits, a policy of `level` must
// guarantee (PRD A §3: B1 ≥ 50, B2 ≥ 80, B3 ≥ 100).
func LevelFloor(level elevations.Level) (float64, bool) {
	switch level {
	case elevations.LevelB1:
		return 50, true
	case elevations.LevelB2:
		return 80, true
	case elevations.LevelB3:
		return 100, true
	}
	return 0, false
}

// CalculateEntropy computes the entropy report of a policy exactly as
// calculateEntropy({generator, parameters}) does in the browser bundle.
// Parameters the bundle refuses yield an ErrInvalidShape error.
func CalculateEntropy(gen Generator, paramsJSON string) (EntropyReport, error) {
	var raw any
	if err := json.Unmarshal([]byte(canonJSON(paramsJSON)), &raw); err != nil {
		return EntropyReport{}, shapeErr("params_json: %s", err.Error())
	}
	params := obj{}
	switch v := raw.(type) {
	case nil:
	case map[string]any:
		params = v
	default:
		return EntropyReport{}, shapeErr("parameters must be an object")
	}
	switch gen {
	case GeneratorG1:
		p, err := normalizeG1(params)
		if err != nil {
			return EntropyReport{}, err
		}
		return entropyG1(p), nil
	case GeneratorG2:
		p, err := normalizeG2(params)
		if err != nil {
			return EntropyReport{}, err
		}
		return entropyG2(p), nil
	case GeneratorG3:
		p, err := normalizeG3(params)
		if err != nil {
			return EntropyReport{}, err
		}
		return entropyG3(p), nil
	}
	return EntropyReport{}, shapeErr("unknown generator %q", gen)
}

// checkEntropyFloor refuses a policy whose guaranteed entropy is below the
// floor of the level it is routed to.
func checkEntropyFloor(level elevations.Level, gen Generator, paramsJSON string) error {
	rep, err := CalculateEntropy(gen, paramsJSON)
	if err != nil {
		return err
	}
	floor, ok := LevelFloor(level)
	if !ok {
		return shapeErr("anssi_level %q", level)
	}
	if rep.MinBits < floor {
		return fmt.Errorf("%w: %s parameters guarantee %.1f bits, %s requires at least %g bits",
			ErrBelowFloor, gen, rep.MinBits, level, floor)
	}
	return nil
}

func shapeErr(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidShape}, args...)...)
}

// ----- params.js ------------------------------------------------------------

type obj = map[string]any

var (
	defaultSeparators = []string{"-", "_", ".", "/", "+", ":", "|", ";", ",", "~"}
	defaultSymbols    = []string{"!", "@", "#", "$", "%", "&", "*", "+", "=", "?"}
	caseModes         = []string{"lowercase", "uppercase", "camelCase", "PascalCase", "SCREAMING_SNAKE"}
	transformCodes    = []string{"T01", "T02", "T03", "T04", "T05", "T06", "T07", "T08", "T09"}
	positions         = []string{"prefix", "middle", "suffix"}
)

const (
	alphabetFull       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	ambiguous          = "lI10O"
	maxWords           = 64
	maxDigits          = 32
	maxLength          = 256
	maxTransformLength = 64
)

type numericGroup struct {
	digitsCount int
	separator   *string
}

type transform struct {
	code        string
	mode        string // "" when absent
	candidates  []string
	probability float64
	firstN      int
	symbols     []string
	length      int
}

type g1Params struct {
	citations  []string
	separators []string
	groups     []numericGroup
	transforms []transform
}

type g2Params struct {
	words       []string
	wordCount   int
	separators  []string
	digits      *numericGroup
	digitsGlued bool
}

type g3Params struct {
	length   int
	alphabet int
}

func normalizeG1(params obj) (g1Params, error) {
	var p g1Params
	var err error
	if p.citations, err = uniqueLibrary(params, "G1"); err != nil {
		return p, err
	}
	if err := sizeClaim(params, "corpusSize", len(p.citations)); err != nil {
		return p, err
	}
	if p.separators, err = stringList(params, "separatorOptions", "separatorOptions", defaultSeparators); err != nil {
		return p, err
	}
	g1Default := []numericGroup{{digitsCount: 3}, {digitsCount: 3}, {digitsCount: 3}}
	if p.groups, err = numericGroups(params, g1Default, 3); err != nil {
		return p, err
	}
	p.transforms, err = transforms(params)
	return p, err
}

func normalizeG2(params obj) (g2Params, error) {
	var p g2Params
	var err error
	if p.words, err = uniqueLibrary(params, "G2"); err != nil {
		return p, err
	}
	if err := sizeClaim(params, "dictionarySize", len(p.words)); err != nil {
		return p, err
	}
	groups, err := numericGroups(params, []numericGroup{{digitsCount: 4}}, 4)
	if err != nil {
		return p, err
	}
	if _, err = transforms(params); err != nil {
		return p, err
	}
	if p.wordCount, err = intIn(params, "numberOfWords", "numberOfWords", 1, maxWords, 6); err != nil {
		return p, err
	}
	if p.separators, err = stringList(params, "separatorOptions", "separatorOptions", defaultSeparators); err != nil {
		return p, err
	}
	if len(groups) > 0 {
		first := groups[0]
		p.digits = &first
		// `separator: ""` glues the digits to the last word.
		p.digitsGlued = first.separator != nil && *first.separator == ""
	}
	return p, nil
}

func normalizeG3(params obj) (g3Params, error) {
	var p g3Params
	exclude := false
	if v, ok := params["excludeAmbiguous"]; ok {
		b, isBool := v.(bool)
		if !isBool {
			return p, shapeErr("excludeAmbiguous must be a boolean")
		}
		exclude = b
	}
	p.alphabet = len(alphabetFull)
	if exclude {
		p.alphabet -= len(ambiguous)
	}
	if err := sizeClaim(params, "alphabetSize", p.alphabet); err != nil {
		return p, err
	}
	var err error
	if p.length, err = intIn(params, "length", "length", 1, maxLength, 20); err != nil {
		return p, err
	}
	if _, err = intIn(params, "blockSize", "blockSize", 0, maxLength, 5); err != nil {
		return p, err
	}
	if v, ok := params["blockSeparator"]; ok {
		if _, isStr := v.(string); !isStr {
			return p, shapeErr("blockSeparator must be a string")
		}
	}
	return p, nil
}

// uniqueLibrary mirrors library.js: an inline, non-empty array of
// non-empty strings, deduplicated in first-seen order.
func uniqueLibrary(params obj, gen string) ([]string, error) {
	list, ok := params["library"].([]any)
	if !ok || len(list) == 0 {
		return nil, shapeErr("%s requires a non-empty inline library array", gen)
	}
	return dedupeStrings(list, gen+" library")
}

func dedupeStrings(list []any, name string) ([]string, error) {
	seen := make(map[string]bool, len(list))
	out := make([]string, 0, len(list))
	for _, v := range list {
		s, ok := v.(string)
		if !ok || s == "" {
			return nil, shapeErr("%s entries must be non-empty strings", name)
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out, nil
}

// jsGet reads property `key` of a JSON value the way JavaScript would:
// objects by key, plus the `length` of strings and arrays.
func jsGet(v any, key string) (any, bool) {
	switch x := v.(type) {
	case map[string]any:
		val, ok := x[key]
		return val, ok
	case string:
		if key == "length" {
			return float64(utf16Len(x)), true
		}
	case []any:
		if key == "length" {
			return float64(len(x)), true
		}
	}
	return nil, false
}

func intIn(v any, key, name string, lo, hi, fallback int) (int, error) {
	val, ok := jsGet(v, key)
	if !ok {
		return fallback, nil
	}
	f, isNum := val.(float64)
	if !isNum || f != math.Trunc(f) || f < float64(lo) || f > float64(hi) {
		return 0, shapeErr("%s must be an integer in [%d, %d]", name, lo, hi)
	}
	return int(f), nil
}

func stringList(v any, key, name string, fallback []string) ([]string, error) {
	val, ok := jsGet(v, key)
	if !ok {
		return fallback, nil
	}
	list, isList := val.([]any)
	if !isList || len(list) == 0 {
		return nil, shapeErr("%s must be a non-empty array", name)
	}
	return dedupeStrings(list, name)
}

func sizeClaim(params obj, key string, actual int) error {
	val, ok := params[key]
	if !ok {
		return nil
	}
	if f, isNum := val.(float64); isNum && f == float64(actual) {
		return nil
	}
	return shapeErr("%s does not match the %d entries really drawn from", key, actual)
}

func numericGroups(params obj, fallback []numericGroup, defaultDigits int) ([]numericGroup, error) {
	val, ok := params["numericGroups"]
	if !ok {
		return fallback, nil
	}
	list, isList := val.([]any)
	if !isList {
		return nil, shapeErr("numericGroups must be an array")
	}
	out := make([]numericGroup, 0, len(list))
	for i, g := range list {
		switch g.(type) {
		case map[string]any, []any: // JS: any object, arrays included
		default:
			return nil, shapeErr("numericGroups[%d] must be an object", i)
		}
		if pos, ok := jsGet(g, "position"); ok && pos != nil {
			s, isStr := pos.(string)
			if !isStr || !contains(positions, s) {
				return nil, shapeErr("numericGroups[%d].position", i)
			}
		}
		var ng numericGroup
		if sep, ok := jsGet(g, "separator"); ok {
			s, isStr := sep.(string)
			if !isStr {
				return nil, shapeErr("numericGroups[%d].separator must be a string", i)
			}
			ng.separator = &s
		}
		n, err := intIn(g, "digitsCount", fmt.Sprintf("numericGroups[%d].digitsCount", i), 0, maxDigits, defaultDigits)
		if err != nil {
			return nil, err
		}
		ng.digitsCount = n
		out = append(out, ng)
	}
	return out, nil
}

// transforms returns the active transforms, in order, parameters filled in.
func transforms(params obj) ([]transform, error) {
	val, ok := params["transforms"]
	if !ok {
		return nil, nil
	}
	list, isList := val.([]any)
	if !isList {
		return nil, shapeErr("transforms must be an array")
	}
	var out []transform
	for _, t := range list {
		switch t.(type) {
		case map[string]any, []any:
		default:
			return nil, shapeErr("transform must be an object")
		}
		codeV, _ := jsGet(t, "code")
		code, _ := codeV.(string)
		if !contains(transformCodes, code) {
			return nil, shapeErr("unknown transform %v", codeV)
		}
		if active, _ := jsGet(t, "active"); !truthy(active) {
			continue
		}
		for _, o := range out {
			if o.code == code {
				return nil, shapeErr("transform %s listed twice", code)
			}
		}
		tr := transform{code: code}
		if m, ok := jsGet(t, "mode"); ok {
			s, _ := m.(string)
			if s != "random" && s != "deterministic" {
				return nil, shapeErr("transform %s mode %v", code, m)
			}
			tr.mode = s
		}
		tp, ok := jsGet(t, "parameters")
		if !ok || tp == nil {
			tp = obj{}
		}
		if err := transformParameters(&tr, tp); err != nil {
			return nil, err
		}
		out = append(out, tr)
	}
	return out, nil
}

func transformParameters(t *transform, p any) error {
	name := func(key string) string { return t.code + "." + key }
	var err error
	switch t.code {
	case "T01":
		if t.candidates, err = stringList(p, "candidates", name("candidates"), caseModes); err != nil {
			return err
		}
		for _, c := range t.candidates {
			if !contains(caseModes, c) {
				return shapeErr("%s unknown mode %q", name("candidates"), c)
			}
		}
	case "T02", "T03":
		t.probability = 0.5
		if v, ok := jsGet(p, "probability"); ok && v != nil {
			f, isNum := v.(float64)
			if !isNum || f <= 0 || f >= 1 {
				return shapeErr("%s must be in (0, 1)", name("probability"))
			}
			t.probability = f
		}
	case "T05":
		t.firstN, err = intIn(p, "firstN", name("firstN"), 1, maxTransformLength, 3)
	case "T08":
		t.symbols, err = stringList(p, "symbols", name("symbols"), defaultSymbols)
	case "T09":
		t.length, err = intIn(p, "length", name("length"), 1, maxTransformLength, 4)
	}
	return err
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case float64:
		return x != 0 && !math.IsNaN(x)
	case string:
		return x != ""
	}
	return true // objects and arrays
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ----- entropy.js: G2 / G3 --------------------------------------------------

func entropyG2(p g2Params) EntropyReport {
	var b breakdown
	b.push("word-selection", float64(p.wordCount)*math.Log2(float64(len(p.words))))
	if p.wordCount > 1 || (p.digits != nil && !p.digitsGlued) {
		b.push("separator", math.Log2(float64(len(p.separators))))
	}
	if p.digits != nil {
		b.push("digit-suffix", float64(p.digits.digitsCount)*math.Log2(10))
	}
	return b.finalize()
}

func entropyG3(p g3Params) EntropyReport {
	var b breakdown
	b.push("alphabet-draw", float64(p.length)*math.Log2(float64(p.alphabet)))
	return b.finalize()
}

type breakdown []EntropyComponent

func (b *breakdown) push(component string, bits float64) {
	if !math.IsInf(bits, 0) && !math.IsNaN(bits) && bits > 0 {
		*b = append(*b, EntropyComponent{Component: component, Bits: bits})
	}
}

func (b breakdown) finalize() EntropyReport {
	sum := 0.0
	for _, c := range b {
		sum += c.Bits
	}
	expected := roundDown(sum)
	out := EntropyReport{MinBits: expected, MaxBits: expected, ExpectedBits: expected,
		Breakdown: make([]EntropyComponent, 0, len(b))}
	for _, c := range b {
		out.Breakdown = append(out.Breakdown, EntropyComponent{Component: c.Component, Bits: roundDown(c.Bits)})
	}
	return out
}

// roundDown rounds DOWN to 0.1 bit so a threshold is never crossed upward.
func roundDown(n float64) float64 { return math.Floor(n*10+1e-9) / 10 }

// ----- entropy.js: G1 -------------------------------------------------------

var (
	leetTable = map[rune]rune{'a': '@', 'e': '3', 'i': '!', 'o': '0', 's': '$', 't': '+', 'l': '1', 'g': '9', 'b': '8', 'z': '2'}
	leetKeys  = map[string][]rune{
		"T02": {'a', 'e', 'i', 'o'},
		"T03": {'a', 'e', 'i', 'o', 's', 't', 'l', 'g', 'b', 'z'},
	}
	joiningCases = []string{"camelCase", "PascalCase", "SCREAMING_SNAKE"}
)

const t09MaxBits = 32

type g1Calc struct {
	p       g1Params
	ts      []transform
	t05     *transform
	text    jsText
	views   map[string][]string
	folds   map[string]string
	leet    []rune
	lib     libFacts
	hasJoin bool
}

type libFacts struct {
	minWords          int
	allStartCased     bool
	allViewsCased     bool
	allHaveDiacritics bool
}

func entropyG1(p g1Params) EntropyReport {
	c := &g1Calc{p: p, ts: p.transforms, text: newJSText(),
		views: map[string][]string{}, folds: map[string]string{}}
	for i := range c.ts {
		if c.ts[i].code == "T05" && c.t05 == nil {
			c.t05 = &c.ts[i]
		}
		if isLeet(c.ts[i]) {
			c.leet = append(c.leet, leetKeys[c.ts[i].code]...)
		}
		if joins(c.ts[i]) {
			c.hasJoin = true
		}
	}
	c.lib = c.libraryFacts()

	var b breakdown
	b.push("citation-selection", c.citationBits())
	if len(p.groups) > 0 || !c.spacesMayBeGone(len(c.ts)) {
		b.push("separator", math.Log2(float64(len(p.separators))))
	}
	digits := 0
	for _, g := range p.groups {
		digits += g.digitsCount
	}
	b.push("digit-groups", float64(digits)*math.Log2(10))

	for i, t := range c.ts {
		if t.mode != "random" {
			continue // FR-A.E.2: deterministic → 0 bits.
		}
		bits := 0.0
		switch t.code {
		case "T01":
			if !c.after(i, isCode("T07")) {
				multiWord := !c.spacesMayBeGone(i) && !c.after(i, isCode("T05"))
				startCased := c.lib.allStartCased && !c.before(i, isCode("T04"))
				if startCased || !c.after(i, isCode("T05")) {
					bits = caseBits(t.candidates, multiWord, startCased, c.lib.allViewsCased)
				}
			}
		case "T02", "T03":
			bits = c.leetBits(t, i)
		case "T04":
			bits = c.choiceBits(i, func(s string) []string {
				return []string{s, c.text.reverseChars(s), c.text.reverseWords(s)}
			})
		case "T05":
			bits = c.choiceBits(i, func(s string) []string {
				v := c.text.variantsT05(s, t.firstN)
				return []string{s, v[1], v[2]}
			})
		case "T06":
			if c.lib.allHaveDiacritics && c.t05 == nil {
				bits = 1
			}
		case "T07":
			if c.lib.allViewsCased && !c.after(i, isCode("T01")) {
				bits = 1
			}
		case "T08":
			if !c.spacesMayBeGone(i) && !c.after(i, isCode("T05")) {
				bits = math.Log2(float64(len(t.symbols)))
			}
		case "T09":
			if !c.after(i, isCode("T05")) {
				perChar := 4
				if c.after(i, isLeet) {
					perChar = 3
				}
				bits = math.Min(float64(perChar*t.length), t09MaxBits)
			}
		}
		b.push("transform-"+t.code, bits)
	}
	return b.finalize()
}

func isCode(code string) func(transform) bool {
	return func(t transform) bool { return t.code == code }
}

func isLeet(t transform) bool { _, ok := leetKeys[t.code]; return ok }

// joins: transforms that can merge the words of a citation into one.
func joins(t transform) bool {
	if t.code == "T05" || t.code == "T08" {
		return true
	}
	if t.code == "T01" {
		for _, m := range t.candidates {
			if contains(joiningCases, m) {
				return true
			}
		}
	}
	return false
}

func (c *g1Calc) before(i int, test func(transform) bool) bool {
	for _, t := range c.ts[:i] {
		if test(t) {
			return true
		}
	}
	return false
}

func (c *g1Calc) after(i int, test func(transform) bool) bool {
	for _, t := range c.ts[i+1:] {
		if test(t) {
			return true
		}
	}
	return false
}

func (c *g1Calc) spacesMayBeGone(i int) bool {
	return c.lib.minWords < 2 || c.before(i, joins)
}

func (c *g1Calc) truncations(s string) []string {
	if c.t05 == nil {
		return []string{s}
	}
	a := c.text.variantsT05(s, c.t05.firstN)
	b := c.text.variantsT05(c.text.joined(s), c.t05.firstN)
	return []string{a[0], a[1], a[2], b[1], b[2]}
}

// inputsAt: worst-case texts the transform at index i may receive (or, with
// i = len(ts), that reach the output) for citation s.
func (c *g1Calc) inputsAt(i int, s string) []string {
	inputs := []string{s}
	expand := func(f func(string) []string) {
		var next []string
		for _, x := range inputs {
			next = append(next, f(x)...)
		}
		inputs = next
	}
	if c.before(i, isCode("T04")) {
		expand(func(x string) []string { return []string{x, c.text.reverseChars(x), c.text.reverseWords(x)} })
	}
	if c.before(i, joins) {
		expand(func(x string) []string { return []string{x, c.text.joined(x)} })
	}
	if c.before(i, isCode("T05")) {
		expand(c.truncations)
	}
	return uniqueOrdered(inputs)
}

func (c *g1Calc) citationViews(s string) []string {
	if v, ok := c.views[s]; ok {
		return v
	}
	v := c.inputsAt(len(c.ts), s)
	c.views[s] = v
	return v
}

// folded applies the per-character changes (case, diacritics, leet) any
// transform may make: texts equal after it may come out identical.
func (c *g1Calc) folded(s string) string {
	if v, ok := c.folds[s]; ok {
		return v
	}
	var lower, strip, leet bool
	for _, t := range c.ts {
		switch {
		case t.code == "T01" || t.code == "T07":
			lower = true
		case t.code == "T06":
			strip = true
		case isLeet(t):
			leet = true
		}
	}
	out := s
	if strip {
		out = stripDiacritics(out)
	}
	if lower {
		out = c.text.lower(out)
	}
	if leet {
		out = strings.Map(func(r rune) rune {
			l := r
			if 'A' <= r && r <= 'Z' {
				l = r + ('a' - 'A')
			}
			if sub, ok := leetTable[l]; ok {
				return sub
			}
			return r
		}, out)
	}
	c.folds[s] = out
	return out
}

func (c *g1Calc) cased(ch string) bool {
	if !c.text.isCased(ch) {
		return false
	}
	l := c.text.lower(ch)
	for _, k := range c.leet {
		if l == string(k) {
			return false
		}
	}
	return true
}

func (c *g1Calc) hasCased(s string) bool {
	for _, r := range wtf8Runes(s) {
		if c.cased(wtf8String([]rune{r})) {
			return true
		}
	}
	return false
}

func (c *g1Calc) libraryFacts() libFacts {
	f := libFacts{minWords: math.MaxInt, allStartCased: true, allViewsCased: true, allHaveDiacritics: true}
	for _, s := range c.p.citations {
		f.minWords = min(f.minWords, len(c.text.words(s)))
		f.allStartCased = f.allStartCased && c.cased(firstUnit(c.text.trim(s)))
		if f.allViewsCased {
			for _, v := range c.citationViews(s) {
				if !c.hasCased(v) {
					f.allViewsCased = false
					break
				}
			}
		}
		f.allHaveDiacritics = f.allHaveDiacritics && hasCombiningMark(s)
	}
	return f
}

// citationBits: log2(N / largest group of citations that may yield the
// same text), grouping transitively (union-find).
func (c *g1Calc) citationBits() float64 {
	var symbols []string
	for _, t := range c.ts {
		if t.code == "T08" {
			symbols = t.symbols
			break
		}
	}
	key := func(s string) string {
		s = c.text.collapseSpaces(s)
		if c.hasJoin {
			s = c.text.dropRuns(s, symbols)
		}
		return s
	}
	n := len(c.p.citations)
	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		if parent[i] != i {
			parent[i] = find(parent[i])
		}
		return parent[i]
	}
	owner := map[string]int{}
	for i, s := range c.p.citations {
		for _, v := range c.inputsAt(len(c.ts), c.folded(s)) {
			k := key(v)
			if o, ok := owner[k]; ok {
				parent[find(i)] = find(o)
			} else {
				owner[k] = i
			}
		}
	}
	sizes := map[int]int{}
	largest := 0
	for i := range parent {
		r := find(i)
		sizes[r]++
		largest = max(largest, sizes[r])
	}
	return math.Log2(float64(n) / float64(largest))
}

// choiceBits: min-entropy of a uniform choice among outputs(s) for the
// transform at index i, worst case over the library, every text it may
// receive and every truncation a later T05 may apply to its result.
func (c *g1Calc) choiceBits(i int, outputs func(string) []string) float64 {
	posts := func(o string) []string { return []string{o} }
	if c.after(i, isCode("T05")) {
		posts = c.truncations
	}
	return c.minOverCitations(func(s string) float64 {
		bits := math.Inf(1)
		for _, in := range c.inputsAt(i, c.folded(s)) {
			var outs [][]string
			for _, o := range outputs(in) {
				outs = append(outs, posts(o))
			}
			for k := range outs[0] {
				col := make([]string, len(outs))
				for j, o := range outs {
					col[j] = o[k]
				}
				bits = math.Min(bits, uniformMinEntropy(col))
			}
		}
		return bits
	})
}

// leetBits: a letter shared by several leet transforms is credited once,
// by the first one, with their combined substitution probability.
func (c *g1Calc) leetBits(t transform, i int) float64 {
	perKey := map[rune]float64{}
	for _, k := range leetKeys[t.code] {
		if c.before(i, func(o transform) bool { return isLeet(o) && containsRune(leetKeys[o.code], k) }) {
			continue
		}
		keep := 1.0
		for _, o := range c.ts {
			if isLeet(o) && containsRune(leetKeys[o.code], k) {
				keep *= 1 - o.probability
			}
		}
		perKey[k] = -math.Log2(math.Max(keep, 1-keep))
	}
	bitsOf := func(s string) float64 {
		bits := 0.0
		for _, r := range wtf8Runes(c.text.lower(s)) {
			bits += perKey[r]
		}
		return bits
	}
	return c.minOverCitations(func(s string) float64 {
		m := math.Inf(1)
		for _, v := range c.citationViews(s) {
			m = math.Min(m, bitsOf(v))
		}
		return m
	})
}

func (c *g1Calc) minOverCitations(fn func(string) float64) float64 {
	m := math.Inf(1)
	for _, s := range c.p.citations {
		m = math.Min(m, fn(s))
		if m <= 0 {
			break
		}
	}
	return m
}

// caseBits: min-entropy of the T01 case mode over the outputs that are
// guaranteed distinct (see entropy.js).
func caseBits(candidates []string, multiWord, startCased, hasCased bool) float64 {
	if !hasCased {
		return 0
	}
	base := func(m string) string {
		if m == "lowercase" || m == "camelCase" {
			return "lower"
		}
		return "upper"
	}
	var partitions []func(string) string
	if multiWord {
		partitions = append(partitions, func(m string) string {
			if !startCased && m == "PascalCase" {
				return "camelCase"
			}
			return m
		})
	} else {
		partitions = append(partitions, base)
		if !startCased {
			partitions = append(partitions, func(m string) string {
				if m == "PascalCase" {
					return "lower"
				}
				return base(m)
			})
		}
	}
	bits := math.Inf(1)
	for _, cls := range partitions {
		col := make([]string, len(candidates))
		for i, m := range candidates {
			col[i] = cls(m)
		}
		bits = math.Min(bits, uniformMinEntropy(col))
	}
	return bits
}

// uniformMinEntropy: -log2(max probability) of a uniform draw over outcomes.
func uniformMinEntropy(outcomes []string) float64 {
	counts := map[string]int{}
	top := 0
	for _, o := range outcomes {
		counts[o]++
		top = max(top, counts[o])
	}
	return math.Log2(float64(len(outcomes)) / float64(top))
}

func uniqueOrdered(list []string) []string {
	seen := make(map[string]bool, len(list))
	out := list[:0:0]
	for _, s := range list {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func containsRune(list []rune, r rune) bool {
	for _, v := range list {
		if v == r {
			return true
		}
	}
	return false
}

// ----- JavaScript string semantics -----------------------------------------

// jsText bundles the Unicode casers (not safe for concurrent use, hence one
// per calculation).
type jsText struct {
	lowerC cases.Caser
	upperC cases.Caser
}

func newJSText() jsText {
	return jsText{lowerC: cases.Lower(language.Und), upperC: cases.Upper(language.Und)}
}

// lower is String.prototype.toLowerCase. Lone surrogates pass through.
func (j jsText) lower(s string) string { return j.mapCase(j.lowerC, s) }

func (j jsText) mapCase(c cases.Caser, s string) string {
	if utf8.ValidString(s) {
		return c.String(s)
	}
	// Map the valid stretches; keep the WTF-8 lone surrogates as they are.
	var b strings.Builder
	var run []rune
	flush := func() {
		if len(run) > 0 {
			b.WriteString(c.String(string(run)))
			run = run[:0]
		}
	}
	for _, r := range wtf8Runes(s) {
		if isSurrogate(r) {
			flush()
			b.WriteString(wtf8String([]rune{r}))
			continue
		}
		run = append(run, r)
	}
	flush()
	return b.String()
}

// isCased: ch.toUpperCase() !== ch.toLowerCase() for one code point (or "").
func (j jsText) isCased(ch string) bool {
	if ch == "" {
		return false
	}
	if r := wtf8Runes(ch); len(r) == 1 && isSurrogate(r[0]) {
		return false
	}
	return j.mapCase(j.upperC, ch) != j.mapCase(j.lowerC, ch)
}

// isJSSpace is the ECMAScript \s set (WhiteSpace + LineTerminator).
func isJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
		return true
	}
	return r >= 0x2000 && r <= 0x200A
}

func (j jsText) trim(s string) string {
	rs := wtf8Runes(s)
	lo, hi := 0, len(rs)
	for lo < hi && isJSSpace(rs[lo]) {
		lo++
	}
	for hi > lo && isJSSpace(rs[hi-1]) {
		hi--
	}
	return wtf8String(rs[lo:hi])
}

// words: s.trim().split(/\s+/u).filter(Boolean).
func (j jsText) words(s string) []string {
	var out []string
	var cur []rune
	for _, r := range wtf8Runes(s) {
		if isJSSpace(r) {
			if len(cur) > 0 {
				out = append(out, wtf8String(cur))
				cur = nil
			}
			continue
		}
		cur = append(cur, r)
	}
	if len(cur) > 0 {
		out = append(out, wtf8String(cur))
	}
	return out
}

func (j jsText) reverseWords(s string) string {
	ws := j.words(s)
	for a, b := 0, len(ws)-1; a < b; a, b = a+1, b-1 {
		ws[a], ws[b] = ws[b], ws[a]
	}
	return strings.Join(ws, " ")
}

// reverseChars: Array.from(s).reverse().join("").
func (j jsText) reverseChars(s string) string {
	rs := wtf8Runes(s)
	for a, b := 0, len(rs)-1; a < b; a, b = a+1, b-1 {
		rs[a], rs[b] = rs[b], rs[a]
	}
	return wtf8String(rs)
}

// joined: s.replace(/\s+/gu, "").
func (j jsText) joined(s string) string {
	rs := wtf8Runes(s)
	out := rs[:0:0]
	for _, r := range rs {
		if !isJSSpace(r) {
			out = append(out, r)
		}
	}
	return wtf8String(out)
}

// collapseSpaces: s.replace(/\s+/gu, " ").
func (j jsText) collapseSpaces(s string) string {
	var out []rune
	inSpace := false
	for _, r := range wtf8Runes(s) {
		if isJSSpace(r) {
			if !inSpace {
				out = append(out, ' ')
			}
			inSpace = true
			continue
		}
		inSpace = false
		out = append(out, r)
	}
	return wtf8String(out)
}

// dropRuns: s.replace(/(?:\s|_|sym1|sym2…)+/gu, ""). The alternatives are
// tried in order at each position, as the regex engine does.
func (j jsText) dropRuns(s string, symbols []string) string {
	rs := wtf8Runes(s)
	syms := make([][]rune, len(symbols))
	for i, sym := range symbols {
		syms[i] = wtf8Runes(sym)
	}
	match := func(pos int) int {
		if isJSSpace(rs[pos]) || rs[pos] == '_' {
			return 1
		}
		for _, sym := range syms {
			if pos+len(sym) <= len(rs) && runesEqual(rs[pos:pos+len(sym)], sym) {
				return len(sym)
			}
		}
		return 0
	}
	var out []rune
	for pos := 0; pos < len(rs); {
		if n := match(pos); n > 0 {
			pos += n
			continue
		}
		out = append(out, rs[pos])
		pos++
	}
	return wtf8String(out)
}

// variantsT05: bypass, first-N UTF-16 units of each word, first unit of
// each word.
func (j jsText) variantsT05(s string, firstN int) [3]string {
	ws := j.words(s)
	var firsts, initials strings.Builder
	for _, w := range ws {
		firsts.WriteString(sliceUnits(w, firstN))
		initials.WriteString(firstUnit(w))
	}
	return [3]string{s, firsts.String(), initials.String()}
}

// sliceUnits is s.slice(0, n) over UTF-16 code units.
func sliceUnits(s string, n int) string {
	var out []rune
	units := 0
	for _, r := range wtf8Runes(s) {
		w := 1
		if r > 0xFFFF {
			w = 2
		}
		if units+w > n {
			if units < n { // only half of an astral character fits
				out = append(out, highSurrogate(r))
			}
			break
		}
		out = append(out, r)
		units += w
	}
	return wtf8String(out)
}

// firstUnit is s[0] (or "" for an empty string).
func firstUnit(s string) string {
	rs := wtf8Runes(s)
	if len(rs) == 0 {
		return ""
	}
	if rs[0] > 0xFFFF {
		return wtf8String([]rune{highSurrogate(rs[0])})
	}
	return wtf8String(rs[:1])
}

func utf16Len(s string) int {
	n := 0
	for _, r := range wtf8Runes(s) {
		if r > 0xFFFF {
			n += 2
		} else {
			n++
		}
	}
	return n
}

func highSurrogate(r rune) rune { return 0xD800 + ((r - 0x10000) >> 10) }

func isSurrogate(r rune) bool { return r >= 0xD800 && r <= 0xDFFF }

func runesEqual(a, b []rune) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// wtf8Runes decodes UTF-8 plus the WTF-8 encoding of lone surrogates.
func wtf8Runes(s string) []rune {
	out := make([]rune, 0, len(s))
	for i := 0; i < len(s); {
		if i+2 < len(s) && s[i] == 0xED && s[i+1]&0xE0 == 0xA0 && s[i+2]&0xC0 == 0x80 {
			out = append(out, 0xD000|rune(s[i+1]&0x3F)<<6|rune(s[i+2]&0x3F))
			i += 3
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		out = append(out, r)
		i += size
	}
	return out
}

// wtf8String encodes runes as UTF-8, lone surrogates as WTF-8.
func wtf8String(rs []rune) string {
	b := make([]byte, 0, len(rs))
	for _, r := range rs {
		if isSurrogate(r) {
			b = append(b, 0xED, byte(0x80|(r>>6)&0x3F), byte(0x80|r&0x3F))
			continue
		}
		b = utf8.AppendRune(b, r)
	}
	return string(b)
}

// stripDiacritics: s.normalize("NFD").replace(/[̀-ͯ]/gu, "").
func stripDiacritics(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 0x300 && r <= 0x36F {
			return -1
		}
		return r
	}, norm.NFD.String(s))
}

func hasCombiningMark(s string) bool {
	for _, r := range norm.NFD.String(s) {
		if r >= 0x300 && r <= 0x36F {
			return true
		}
	}
	return false
}
