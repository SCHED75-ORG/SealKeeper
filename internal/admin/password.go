package admin

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
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

// productWords are always treated as known to the attacker.
var productWords = []string{"sealkeeper", "seal", "keeper"}

// Weakness codes. They name a category, never a fragment of the password,
// so they are safe to put in a redirect URL or a log line.
const (
	WeakTooShort   = "too_short"
	WeakFewClasses = "few_classes"
	WeakCommon     = "common"
	WeakDictionary = "dictionary"
	WeakContext    = "context"
	WeakYear       = "year"
	WeakSequence   = "sequence"
	WeakKeyboard   = "keyboard"
	WeakRepeat     = "repeat"
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
	if commonSet[foldWord(strings.ToLower(s))] {
		return &WeakPasswordError{Codes: []string{WeakCommon}}
	}
	bits, codes := estimate(s, contextWords(userInputs))
	if bits < AdminPasswordMinEntropyBits {
		if len(codes) == 0 {
			codes = []string{WeakEntropy}
		}
		return &WeakPasswordError{Codes: codes, Bits: bits}
	}
	return nil
}

// EstimatePasswordEntropy returns a conservative estimate, in bits, of
// the number of guesses an attacker needs to find s. It is a small
// zxcvbn-style matcher: the password is split into the cheapest sequence
// of segments, where a segment is either one brute-forced character
// (log2 of the character pool) or a predictable pattern — common
// password, dictionary word (case and leetspeak variants included),
// product/instance/email word, year, alphabetic or numeric sequence,
// keyboard walk, or repetition — charged at what it costs an attacker
// who knows the pattern. Only the first 72 bytes count, as bcrypt
// ignores the rest.
func EstimatePasswordEntropy(s string, userInputs ...string) float64 {
	bits, _ := estimate(s, contextWords(userInputs))
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

// ----- estimator ------------------------------------------------------------

// Pattern costs, in bits. Dictionary words are charged as if they ranked
// ~4096 in an attacker's list, common passwords ~1024, known context
// words almost nothing.
const (
	costDictionaryWord = 12
	costCommonPassword = 10
	costContextWord    = 2
	costYear           = 7.65 // log2(200): 1900..2099
	minWordLen         = 4
	minContextLen      = 3
	minPatternLen      = 3
)

type segment struct {
	bits float64
	code string // "" for brute force
}

func estimate(s string, ctxWords map[string]bool) (float64, []string) {
	runes := truncateRunes(s, bcryptMaxBytes)
	n := len(runes)
	if n == 0 {
		return 0, nil
	}
	perChar := math.Log2(poolSize(runes))

	// best[j] is the cheapest cover of runes[:j]; via[j] the segment that
	// ends at j and from[j] where it starts.
	best := make([]float64, n+1)
	from := make([]int, n+1)
	via := make([]string, n+1)
	for j := 1; j <= n; j++ {
		best[j] = math.Inf(1)
	}
	for i := 0; i < n; i++ {
		if math.IsInf(best[i], 1) {
			continue
		}
		relax := func(j int, seg segment) {
			if c := best[i] + seg.bits; c < best[j] {
				best[j], from[j], via[j] = c, i, seg.code
			}
		}
		relax(i+1, segment{bits: perChar})
		for j := i + minPatternLen; j <= n; j++ {
			if seg, ok := matchPattern(runes[i:j], ctxWords); ok {
				relax(j, seg)
			}
		}
	}

	seen := map[string]bool{}
	for j := n; j > 0; j = from[j] {
		if via[j] != "" {
			seen[via[j]] = true
		}
	}
	codes := make([]string, 0, len(seen))
	for c := range seen {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	return best[n], codes
}

// matchPattern returns the cheapest predictable-pattern reading of w, if
// any.
func matchPattern(w []rune, ctxWords map[string]bool) (segment, bool) {
	var out segment
	found := false
	take := func(seg segment) {
		if !found || seg.bits < out.bits {
			out, found = seg, true
		}
	}
	if seg, ok := matchWord(w, ctxWords); ok {
		take(seg)
	}
	if isYear(w) {
		take(segment{bits: costYear, code: WeakYear})
	}
	if bits, ok := sequenceBits(w); ok {
		take(segment{bits: bits, code: WeakSequence})
	}
	if bits, ok := keyboardBits(w); ok {
		take(segment{bits: bits, code: WeakKeyboard})
	}
	if bits, ok := repeatBits(w, ctxWords); ok {
		take(segment{bits: bits, code: WeakRepeat})
	}
	return out, found
}

// matchWord looks w up, case-insensitively and with leetspeak undone, in
// the context words, the common-password list and the dictionary.
func matchWord(w []rune, ctxWords map[string]bool) (segment, bool) {
	extra := caseBits(w)
	var out segment
	found := false
	for _, v := range leetVariants(w) {
		bits := extra + float64(v.subs)
		if v.reversed {
			bits++
		}
		var seg segment
		switch {
		case len(v.word) >= minContextLen && ctxWords[v.word]:
			seg = segment{bits: costContextWord + bits, code: WeakContext}
		case commonSet[v.word]:
			seg = segment{bits: costCommonPassword + bits, code: WeakCommon}
		case utf8.RuneCountInString(v.word) >= minWordLen && dictSet[v.word]:
			seg = segment{bits: costDictionaryWord + bits, code: WeakDictionary}
		default:
			continue
		}
		if !found || seg.bits < out.bits {
			out, found = seg, true
		}
	}
	return out, found
}

type variant struct {
	word     string
	subs     int
	reversed bool
}

// leetVariants returns the lower-cased, accent-folded readings of w (and
// of w reversed) with leetspeak undone. '1' and '|' are ambiguous between
// "i" and "l", so both readings are produced.
func leetVariants(w []rune) []variant {
	var out []variant
	for _, rev := range []bool{false, true} {
		for _, oneAsL := range []bool{false, true} {
			var b strings.Builder
			subs := 0
			for k := range w {
				r := w[k]
				if rev {
					r = w[len(w)-1-k]
				}
				lr := unicode.ToLower(r)
				if m, ok := leetMap[lr]; ok {
					if oneAsL && (lr == '1' || lr == '|') {
						m = 'l'
					}
					lr = m
					subs++
				}
				b.WriteRune(foldRune(lr))
			}
			out = append(out, variant{word: b.String(), subs: subs, reversed: rev})
		}
	}
	return out
}

var leetMap = map[rune]rune{
	'0': 'o', '1': 'i', '!': 'i', '|': 'i', '3': 'e', '4': 'a', '@': 'a',
	'5': 's', '$': 's', '7': 't', '+': 't', '8': 'b', '9': 'g', '€': 'e',
}

// caseBits charges the capitalisation of a word: free when all lower,
// one bit when capitalised or all upper, the number of ways to place the
// upper-case letters otherwise.
func caseBits(w []rune) float64 {
	upper, lower := 0, 0
	for _, r := range w {
		switch {
		case unicode.IsUpper(r):
			upper++
		case unicode.IsLower(r):
			lower++
		}
	}
	switch {
	case upper == 0:
		return 0
	case lower == 0, upper == 1 && unicode.IsUpper(w[0]):
		return 1
	}
	k := upper
	if lower < k {
		k = lower
	}
	var ways float64
	for i := 1; i <= k; i++ {
		ways += binomial(upper+lower, i)
	}
	return math.Log2(ways)
}

func binomial(n, k int) float64 {
	r := 1.0
	for i := 1; i <= k; i++ {
		r = r * float64(n-k+i) / float64(i)
	}
	return r
}

func isYear(w []rune) bool {
	if len(w) != 4 {
		return false
	}
	for _, r := range w {
		if r < '0' || r > '9' {
			return false
		}
	}
	return (w[0] == '1' && w[1] == '9') || (w[0] == '2' && w[1] == '0')
}

// sequenceBits matches runs like "abcd", "9876" or "KLMN".
func sequenceBits(w []rune) (float64, bool) {
	delta := w[1] - w[0]
	if delta != 1 && delta != -1 {
		return 0, false
	}
	for k := 1; k < len(w); k++ {
		if w[k]-w[k-1] != delta || classOf(w[k]) != classOf(w[0]) {
			return 0, false
		}
	}
	var base float64
	switch {
	case strings.ContainsRune("aAzZ019", w[0]):
		base = 4
	case classOf(w[0]) == 'd':
		base = 10
	case classOf(w[0]) == 'l' || classOf(w[0]) == 'u':
		base = 26
	default:
		return 0, false
	}
	bits := math.Log2(base * float64(len(w)))
	if delta < 0 {
		bits++
	}
	return bits, true
}

func classOf(r rune) byte {
	switch {
	case r >= 'a' && r <= 'z':
		return 'l'
	case r >= 'A' && r <= 'Z':
		return 'u'
	case r >= '0' && r <= '9':
		return 'd'
	}
	return 's'
}

// keyboardRows are straight walks on QWERTY and AZERTY layouts, plus the
// common diagonal "column" walks. Matching is on the lower-cased walk,
// forwards or backwards.
var keyboardRows = []string{
	"`1234567890-=", "~!@#$%^&*()_+", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./",
	"azertyuiop^$", "qsdfghjklmù*", "<wxcvbn,;:!", "&é\"'(-è_çà)=",
	"1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/", "1aqw2zsx3edc4rfv5tgb6yhn7ujn8ik,9ol;0pm:",
	"zaq1xsw2cde3vfr4bgt5nhy6mju7", "qwertzuiop", "yxcvbnm",
}

func keyboardBits(w []rune) (float64, bool) {
	lw := strings.ToLower(string(w))
	rw := reverseString(lw)
	for _, row := range keyboardRows {
		if strings.Contains(row, lw) || strings.Contains(row, rw) {
			// Start key (~48 keys), walk length, direction, shift state.
			bits := math.Log2(48*float64(len(w))) + 1 + caseBits(w)
			return bits, true
		}
	}
	return 0, false
}

func reverseString(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// repeatBits matches w as a block repeated at least twice ("aaaa",
// "abab", "2020"): the block's own cost plus log2 of the repeat count.
func repeatBits(w []rune, ctxWords map[string]bool) (float64, bool) {
	n := len(w)
	for size := 1; size <= n/2; size++ {
		if n%size != 0 {
			continue
		}
		ok := true
		for k := size; k < n && ok; k++ {
			ok = unicode.ToLower(w[k]) == unicode.ToLower(w[k-size])
		}
		if !ok {
			continue
		}
		blockBits, _ := estimate(string(w[:size]), ctxWords)
		return blockBits + math.Log2(float64(n/size)) + caseBits(w)/2, true
	}
	return 0, false
}

func poolSize(runes []rune) float64 {
	var lower, upper, digit, symbol, other bool
	for _, r := range runes {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		case r < 128:
			symbol = true
		default:
			other = true
		}
	}
	pool := 0.0
	for _, p := range []struct {
		on   bool
		size float64
	}{{lower, 26}, {upper, 26}, {digit, 10}, {symbol, 33}, {other, 100}} {
		if p.on {
			pool += p.size
		}
	}
	if pool < 2 {
		pool = 2
	}
	return pool
}

// truncateRunes keeps the longest rune prefix of s that fits in max bytes.
func truncateRunes(s string, max int) []rune {
	if len(s) > max {
		cut := max
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	return []rune(s)
}

// foldRune strips the accents French operators are most likely to type.
func foldRune(r rune) rune {
	switch r {
	case 'à', 'â', 'ä', 'á', 'ã':
		return 'a'
	case 'é', 'è', 'ê', 'ë':
		return 'e'
	case 'î', 'ï', 'í':
		return 'i'
	case 'ô', 'ö', 'ó':
		return 'o'
	case 'ù', 'û', 'ü', 'ú':
		return 'u'
	case 'ç':
		return 'c'
	case 'ÿ':
		return 'y'
	}
	return r
}

func foldWord(s string) string {
	return strings.Map(foldRune, s)
}

// contextWords splits attacker-known strings (product name, emails,
// domains) into lower-case tokens: "rssi.paris@acme-corp.fr" yields
// "rssi.paris", "rssi", "paris", "acme-corp", "acme", "corp", ...
func contextWords(inputs []string) map[string]bool {
	out := map[string]bool{}
	add := func(t string) {
		t = foldWord(strings.ToLower(strings.TrimSpace(t)))
		if utf8.RuneCountInString(t) >= minContextLen {
			out[t] = true
		}
	}
	for _, w := range productWords {
		add(w)
	}
	for _, in := range inputs {
		add(in)
		for _, part := range strings.FieldsFunc(in, func(r rune) bool { return r == '@' || r == '.' }) {
			add(part)
			for _, tok := range strings.FieldsFunc(part, func(r rune) bool {
				return !unicode.IsLetter(r) && !unicode.IsDigit(r)
			}) {
				add(tok)
			}
		}
	}
	return out
}
