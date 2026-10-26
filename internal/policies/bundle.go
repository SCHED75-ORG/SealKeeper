package policies

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"unicode/utf16"
)

// This file mirrors web/src/params.js (and the checks generate() runs
// before it) so that a policy the reveal bundle would refuse with
// InvalidPolicyDescriptor / LibraryNotFound is refused here too: at save
// time in the editor, and at reveal time before the single-use token is
// burned. Keep the bounds and rules in lockstep with params.js.

const (
	maxProposals       = 50
	maxRegenerate      = 100
	maxWords           = 64
	maxDigits          = 32
	maxLength          = 256
	maxTransformLength = 64
	// G3 draws from [a-zA-Z0-9]; excludeAmbiguous drops l, I, 1, 0, O.
	g3AlphabetFull      = 62
	g3AlphabetAmbiguous = 57
)

var (
	transformCodes = []string{"T01", "T02", "T03", "T04", "T05", "T06", "T07", "T08", "T09"}
	groupPositions = []string{"prefix", "middle", "suffix"}
	caseModes      = []string{"lowercase", "uppercase", "camelCase", "PascalCase", "SCREAMING_SNAKE"}
)

// ValidateForReveal reports whether the reveal bundle would accept p, as
// served by GET /api/v1/policy. A non-nil error wraps ErrInvalidShape: the
// browser would throw, so the caller must not consume the user's token.
func ValidateForReveal(p Policy) error {
	var params any
	if len(p.Params) > 0 {
		if err := json.Unmarshal(p.Params, &params); err != nil {
			return fmt.Errorf("%w: params_json: %s", ErrInvalidShape, err.Error())
		}
	}
	return bundleRefusal(p.Generator, params, p.ProposalCount, p.RegenerateLimit)
}

// bundleRefusal returns the reason the bundle would refuse the descriptor
// {generator, proposalCount, regenerateLimit, parameters: params}, or nil.
func bundleRefusal(gen Generator, params any, proposalCount, regenerateLimit int) error {
	if proposalCount < 1 || proposalCount > maxProposals {
		return invalid("proposal_count must be an integer in [1, %d], got %d", maxProposals, proposalCount)
	}
	if regenerateLimit < 0 || regenerateLimit > maxRegenerate {
		return invalid("regenerate_limit must be an integer in [0, %d], got %d", maxRegenerate, regenerateLimit)
	}
	if params == nil { // descriptorFromPolicy: `parameters ?? {}`
		params = map[string]any{}
	}
	if _, ok := params.(map[string]any); !ok {
		return invalid("parameters must be an object")
	}
	switch gen {
	case GeneratorG1:
		return checkLibraryGenerator(gen, params, "corpusSize")
	case GeneratorG2:
		if err := checkLibraryGenerator(gen, params, "dictionarySize"); err != nil {
			return err
		}
		return intIn(params, "numberOfWords", "numberOfWords", 1, maxWords)
	case GeneratorG3:
		exclude, err := boolOf(params, "excludeAmbiguous")
		if err != nil {
			return err
		}
		size := g3AlphabetFull
		if exclude {
			size = g3AlphabetAmbiguous
		}
		if err := sizeClaim(params, "alphabetSize", size, "characters drawn by G3"); err != nil {
			return err
		}
		if err := intIn(params, "length", "length", 1, maxLength); err != nil {
			return err
		}
		if err := intIn(params, "blockSize", "blockSize", 0, maxLength); err != nil {
			return err
		}
		if v, ok := prop(params, "blockSeparator"); ok {
			if _, isStr := v.(string); !isStr {
				return invalid("blockSeparator must be a string")
			}
		}
		return nil
	}
	return invalid("unknown generator %q", gen)
}

// checkLibraryGenerator covers what G1 and G2 share: the inline library,
// its size claim, the separators, the numeric groups and the transforms.
func checkLibraryGenerator(gen Generator, params any, sizeKey string) error {
	lib, _ := prop(params, "library")
	entries, ok := lib.([]any)
	if !ok || len(entries) == 0 {
		return invalid("%s needs parameters.library, a non-empty array of strings", gen)
	}
	distinct := map[string]struct{}{}
	for _, e := range entries {
		s, isStr := e.(string)
		if !isStr || s == "" {
			return invalid("%s library entries must be non-empty strings", gen)
		}
		distinct[s] = struct{}{}
	}
	if err := sizeClaim(params, sizeKey, len(distinct), "distinct library entries"); err != nil {
		return err
	}
	if err := stringList(params, "separatorOptions", "separatorOptions"); err != nil {
		return err
	}
	if err := numericGroups(params); err != nil {
		return err
	}
	return transforms(params)
}

func numericGroups(params any) error {
	v, ok := prop(params, "numericGroups")
	if !ok {
		return nil
	}
	groups, isArr := v.([]any)
	if !isArr {
		return invalid("numericGroups must be an array")
	}
	for i, g := range groups {
		if !isObject(g) {
			return invalid("numericGroups[%d] must be an object", i)
		}
		if pos, ok := prop(g, "position"); ok && pos != nil {
			if s, isStr := pos.(string); !isStr || !slices.Contains(groupPositions, s) {
				return invalid("numericGroups[%d].position %v", i, pos)
			}
		}
		if sep, ok := prop(g, "separator"); ok {
			if _, isStr := sep.(string); !isStr {
				return invalid("numericGroups[%d].separator must be a string", i)
			}
		}
		if err := intIn(g, "digitsCount", fmt.Sprintf("numericGroups[%d].digitsCount", i), 0, maxDigits); err != nil {
			return err
		}
	}
	return nil
}

func transforms(params any) error {
	v, ok := prop(params, "transforms")
	if !ok {
		return nil
	}
	list, isArr := v.([]any)
	if !isArr {
		return invalid("transforms must be an array")
	}
	var active []string
	for _, t := range list {
		if !isObject(t) {
			return invalid("transform must be an object")
		}
		c, _ := prop(t, "code")
		code, isStr := c.(string)
		if !isStr || !slices.Contains(transformCodes, code) {
			return invalid("unknown transform %v", c)
		}
		if a, _ := prop(t, "active"); !truthy(a) {
			continue
		}
		if slices.Contains(active, code) {
			return invalid("transform %s listed twice", code)
		}
		active = append(active, code)
		if m, ok := prop(t, "mode"); ok && m != "random" && m != "deterministic" {
			return invalid("transform %s mode %v", code, m)
		}
		p, _ := prop(t, "parameters")
		if p == nil { // `t.parameters ?? {}`
			p = map[string]any{}
		}
		if err := transformParameters(code, p); err != nil {
			return err
		}
	}
	return nil
}

func transformParameters(code string, p any) error {
	name := func(key string) string { return code + "." + key }
	switch code {
	case "T01":
		if err := stringList(p, "candidates", name("candidates")); err != nil {
			return err
		}
		if v, ok := prop(p, "candidates"); ok {
			for _, c := range v.([]any) {
				if !slices.Contains(caseModes, c.(string)) {
					return invalid("%s unknown mode %q", name("candidates"), c)
				}
			}
		}
	case "T02", "T03":
		if v, ok := prop(p, "probability"); ok && v != nil {
			f, isNum := v.(float64)
			if !isNum || f <= 0 || f >= 1 {
				return invalid("%s must be in (0, 1)", name("probability"))
			}
		}
	case "T05":
		return intIn(p, "firstN", name("firstN"), 1, maxTransformLength)
	case "T08":
		return stringList(p, "symbols", name("symbols"))
	case "T09":
		return intIn(p, "length", name("length"), 1, maxTransformLength)
	}
	return nil
}

// ----- JS value semantics ----------------------------------------------------

// prop reads obj[key] the way JavaScript does on a JSON value: object
// members, plus `.length` on strings (UTF-16 units) and arrays. The bool is
// false when the property is undefined.
func prop(obj any, key string) (any, bool) {
	switch o := obj.(type) {
	case map[string]any:
		v, ok := o[key]
		return v, ok
	case string:
		if key == "length" {
			return float64(len(utf16.Encode([]rune(o)))), true
		}
	case []any:
		if key == "length" {
			return float64(len(o)), true
		}
	}
	return nil, false
}

// isObject is `v && typeof v === "object"` (arrays included).
func isObject(v any) bool {
	switch v.(type) {
	case map[string]any, []any:
		return true
	}
	return false
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		return x != ""
	}
	return true
}

func intIn(obj any, key, name string, lo, hi float64) error {
	v, ok := prop(obj, key)
	if !ok {
		return nil
	}
	f, isNum := v.(float64)
	if !isNum || f != math.Trunc(f) || f < lo || f > hi {
		return invalid("%s must be an integer in [%g, %g], got %v", name, lo, hi, jsonOf(v))
	}
	return nil
}

func boolOf(obj any, key string) (bool, error) {
	v, ok := prop(obj, key)
	if !ok {
		return false, nil
	}
	b, isBool := v.(bool)
	if !isBool {
		return false, invalid("%s must be a boolean, got %v", key, jsonOf(v))
	}
	return b, nil
}

// stringList: absent, or a non-empty array of non-empty strings.
func stringList(obj any, key, name string) error {
	v, ok := prop(obj, key)
	if !ok {
		return nil
	}
	list, isArr := v.([]any)
	if !isArr || len(list) == 0 {
		return invalid("%s must be a non-empty array", name)
	}
	for _, e := range list {
		if s, isStr := e.(string); !isStr || s == "" {
			return invalid("%s entries must be non-empty strings", name)
		}
	}
	return nil
}

func sizeClaim(obj any, key string, actual int, what string) error {
	v, ok := prop(obj, key)
	if !ok {
		return nil
	}
	if f, isNum := v.(float64); isNum && f == float64(actual) {
		return nil
	}
	return invalid("%s %v does not match the %d %s", key, jsonOf(v), actual, what)
}

func jsonOf(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidShape}, args...)...)
}
