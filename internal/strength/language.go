package strength

import "unicode"

// plausiblePairs are the 160 most frequent letter pairs inside English and
// French words, measured on this repository's prose (docs/prd, README,
// CLAUDE.md, SECURITY.md, ...; code spans and camelCase identifiers left
// out, accents folded). They cover 91% of the pairs of that text but only
// 160 of the 676 possible pairs, so a run of letters drawn at random lands
// on one about a quarter of the time, natural words nine times in ten.
const plausiblePairs = `
ab ac ad ag ai al an ap ar as at au av ba bi bl ca ce ch ci ck cl co cr
ct cu da de di dm do du ea ec ed ee ef eg el em en ep er es et eu ev ex
fa ff fi fo ge gr gu ha he hi ia ib ic id ie if ig il im in io iq ir is
it iv ke la le li ll lo lu ma me mi mm mo mp na nc nd ne nf ng ni nn no
ns nt oc od og oi ol om on op or os ot ou pa pe pl po pp pr pt pu qu ra
rd re ri rm rn ro rs rt sa se si so sp ss st su ta te th ti to tr ts tt
tu ub uc ud ue ui ul um un up ur us ut va ve vi
`

var pairSet = wordSet(plausiblePairs)

// PlausiblePairShare is the probability that two letters drawn uniformly
// at random (case folded) form one of the plausible pairs.
var PlausiblePairShare = float64(len(pairSet)) / (26 * 26)

// LetterPairs counts the adjacent pairs of ASCII letters in s (case and
// accents folded; any other character breaks the run) and how many of
// them are plausible inside an English or French word. Natural language,
// word salad and pronounceable inventions score close to pairs; random
// characters close to pairs × PlausiblePairShare.
func LetterPairs(s string) (pairs, plausible int) {
	prev := rune(0)
	for _, r := range s {
		r = foldRune(unicode.ToLower(r))
		if r < 'a' || r > 'z' {
			prev = 0
			continue
		}
		if prev != 0 {
			pairs++
			if pairSet[string([]rune{prev, r})] {
				plausible++
			}
		}
		prev = r
	}
	return pairs, plausible
}
