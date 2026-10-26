// =============================================================================
// SealKeeper — Entropy calculator
// =============================================================================
// PRD A §3.5 FR-A.E.1..5
//   - Kerckhoffs: attacker knows everything except the draw.
//   - Deterministic transforms contribute 0 bits.
//   - Same function used by user UI and admin console (FR-A.E.4).
//
// The calculator reads the policy through the same normalisers as the
// generators (params.js) and only credits what the generator really draws
// (audit js-generation#2/#3/#4):
//   - G2 / G3 are exact: distinct library entries, emitted separator, the
//     single numeric group G2 uses, the alphabet G3 draws from.
//   - G1 is a conservative lower bound on min-entropy:
//       log2(N / largest group of citations that may end up identical)
//     + min over citations of the min-entropy each transform adds,
//     where a transform earns nothing when an earlier one may have removed
//     what it acts on or a later one may erase what it added.
//     tests/entropy-property.test.js checks the bound against real draws.
// =============================================================================

import { InvalidPolicyDescriptor } from "./errors.js";
import { resolveLibrary } from "./library.js";
import { normalizeG1, normalizeG2, normalizeG3, normalizeTopLevel } from "./params.js";
import { stripDiacritics } from "./transforms.js";

const LOG2 = Math.log2;

// Leet table of T03 (T02 uses its first four keys); see transforms.js.
const LEET = { a: "@", e: "3", i: "!", o: "0", s: "$", t: "+", l: "1", g: "9", b: "8", z: "2" };
const LEET_KEYS = {
  T02: ["a", "e", "i", "o"],
  T03: Object.keys(LEET),
};
// T01 modes that remove whitespace (and thereby word boundaries).
const JOINING_CASES = ["camelCase", "PascalCase", "SCREAMING_SNAKE"];
// T09 hashes a 32-bit nonce (plus a guessable timestamp): at most 32 bits.
const T09_MAX_BITS = 32;

/** ANSSI level for a given expected entropy. */
export function anssiLevel(bits) {
  if (bits >= 100) return "B3";
  if (bits >= 80) return "B2";
  if (bits >= 50) return "B1";
  return null;
}

/**
 * @typedef {object} EntropyReport
 * @property {number} minBits
 * @property {number} maxBits
 * @property {number} expectedBits
 * @property {{B1:boolean, B2:boolean, B3:boolean}} anssiLevels
 * @property {Array<{component:string, bits:number}>} breakdown
 */

/**
 * Compute entropy for a policy descriptor.
 * @param {object} policy
 * @returns {EntropyReport}
 * @throws {InvalidPolicyDescriptor|import("./errors.js").LibraryNotFound}
 */
export function calculateEntropy(policy) {
  if (!policy || typeof policy !== "object") {
    throw new InvalidPolicyDescriptor("policy must be an object");
  }
  switch (policy.generator) {
    case "G1":
      normalizeTopLevel(policy);
      return entropyG1(normalizeG1(policy, resolveLibrary(policy)));
    case "G2":
      normalizeTopLevel(policy);
      return entropyG2(normalizeG2(policy, resolveLibrary(policy)));
    case "G3":
      normalizeTopLevel(policy);
      return entropyG3(normalizeG3(policy));
    default:
      throw new InvalidPolicyDescriptor(`unknown generator ${policy.generator}`);
  }
}

function entropyG2(p) {
  const breakdown = [];
  push(breakdown, "word-selection", p.wordCount * LOG2(p.words.length));
  // The separator only shows up between words or before detached digits.
  if (p.wordCount > 1 || (p.digits && !p.digits.attached)) {
    push(breakdown, "separator", LOG2(p.separators.length));
  }
  // generateG2 emits numericGroups[0] only; transforms are never applied.
  if (p.digits) push(breakdown, "digit-suffix", p.digits.digitsCount * LOG2(10));
  return finalize(breakdown);
}

function entropyG3(p) {
  const breakdown = [];
  push(breakdown, "alphabet-draw", p.length * LOG2(p.alphabet.length));
  return finalize(breakdown);
}

// -----------------------------------------------------------------------------
// G1
// -----------------------------------------------------------------------------

function entropyG1(p) {
  const breakdown = [];
  const ts = p.transforms;
  const isCode = (code) => (t) => t.code === code;
  const isLeet = (t) => t.code in LEET_KEYS;
  const before = (i, test) => ts.slice(0, i).some(test);
  const after = (i, test) => ts.slice(i + 1).some(test);
  // Transforms that can merge the words of a citation into one.
  const joins = (t) =>
    t.code === "T05" ||
    t.code === "T08" ||
    (t.code === "T01" && t.parameters.candidates.some((c) => JOINING_CASES.includes(c)));

  const t05 = ts.find(isCode("T05"));
  const joined = (s) => s.replace(/\s+/gu, "");
  // Every form a text may take once T05 has run on it: bypass, first-N,
  // initials — of the words, or of one joined word if the spaces may be
  // gone (initials then keep a single character).
  const truncations = (s) => {
    if (!t05) return [s];
    return [...variantsT05(s, t05), ...variantsT05(joined(s), t05).slice(1)];
  };
  // Worst-case texts the transform at index `i` may receive (or, with
  // i = ts.length, that reach the output) for citation `c`.
  const inputsAt = (i, c) => {
    let inputs = [c];
    if (before(i, isCode("T04"))) {
      inputs = inputs.flatMap((s) => [s, Array.from(s).reverse().join(""), reverseWords(s)]);
    }
    if (before(i, joins)) inputs = inputs.flatMap((s) => [s, joined(s)]);
    if (before(i, isCode("T05"))) inputs = inputs.flatMap(truncations);
    return [...new Set(inputs)];
  };
  const citationViews = memoize((c) => inputsAt(ts.length, c));
  // Case, diacritics and leet changes any transform may make, anywhere in
  // the chain: texts equal after this fold may come out identical. The fold
  // works character by character, so it commutes with reversal and
  // truncation and is applied once per citation, before them.
  const folded = memoize(charFold(ts));

  // Letters any active leet transform may turn into symbols do not count as
  // cased (with a high probability they all become symbols).
  const leetKeys = ts.filter(isLeet).flatMap((t) => LEET_KEYS[t.code]);
  const lib = libraryFacts(p.citations, leetKeys, citationViews);
  const spacesMayBeGone = (i) => lib.minWords < 2 || before(i, joins);

  push(breakdown, "citation-selection", citationBits());
  // Without digit groups the separator only replaces surviving whitespace.
  if (p.groups.length > 0 || !spacesMayBeGone(ts.length)) {
    push(breakdown, "separator", LOG2(p.separators.length));
  }
  push(breakdown, "digit-groups", p.groups.reduce((acc, g) => acc + g.digitsCount, 0) * LOG2(10));

  ts.forEach((t, i) => {
    if (t.mode !== "random") return; // FR-A.E.2: deterministic → 0 bits.
    let bits = 0;
    switch (t.code) {
      case "T01":
        // A later T07 rewrites every letter's case.
        if (!after(i, isCode("T07"))) {
          const multiWord = !spacesMayBeGone(i) && !after(i, isCode("T05"));
          // An earlier T04 may bring an uncased character to the front.
          const startCased = lib.allStartCased && !before(i, isCode("T04"));
          // Initials keep only first letters: without a cased start the
          // remaining case information is not guaranteed.
          if (startCased || !after(i, isCode("T05"))) {
            bits = caseBits(t.parameters.candidates, multiWord, startCased, lib.allViewsCased);
          }
        }
        break;
      case "T02":
      case "T03":
        bits = leetBits(t, i);
        break;
      case "T04":
        bits = choiceBits(i, (s) => [s, Array.from(s).reverse().join(""), reverseWords(s)]);
        break;
      case "T05":
        bits = choiceBits(i, (s) => [s, ...variantsT05(s, t).slice(1)]);
        break;
      case "T06":
        // Truncation may drop every accented letter.
        if (lib.allHaveDiacritics && !t05) bits = 1;
        break;
      case "T07":
        // A later T01 rewrites every letter's case; a later truncation may
        // keep no cased letter at all.
        if (lib.allViewsCased && !after(i, isCode("T01"))) bits = 1;
        break;
      case "T08":
        // Needs at least two words; a later truncation drops the symbol.
        if (!spacesMayBeGone(i) && !after(i, isCode("T05"))) {
          bits = LOG2(t.parameters.symbols.length);
        }
        break;
      case "T09":
        // A later truncation drops the suffix. A later leet may fold the
        // hex digits b/8 and e/3 together: count 3 bits per character then.
        if (!after(i, isCode("T05"))) {
          const perChar = after(i, isLeet) ? 3 : 4;
          bits = Math.min(perChar * t.parameters.length, T09_MAX_BITS);
        }
        break;
    }
    push(breakdown, `transform-${t.code}`, bits);
  });

  return finalize(breakdown);

  /**
   * log2(N / largest group of citations that may yield the same text). Two
   * citations share a group as soon as any of their possible output texts
   * coincide after folding (union-find, so the grouping is transitive).
   */
  function citationBits() {
    const folds = [(s) => s.replace(/\s+/gu, " ")];
    if (ts.some(joins)) {
      const symbols = ts.find(isCode("T08"))?.parameters.symbols ?? [];
      const escaped = [
        "\\s",
        "_",
        ...symbols.map((c) => c.replace(/[.*+?^${}()|[\]\\/-]/gu, "\\$&")),
      ];
      const dropped = new RegExp(`(?:${escaped.join("|")})+`, "gu");
      folds.push((s) => s.replace(dropped, ""));
    }
    const key = (s) => folds.reduce((acc, f) => f(acc), s);
    const parent = p.citations.map((_, i) => i);
    const find = (i) => (parent[i] === i ? i : (parent[i] = find(parent[i])));
    const owner = new Map();
    p.citations.forEach((c, i) => {
      for (const v of inputsAt(ts.length, folded(c))) {
        const k = key(v);
        if (owner.has(k)) parent[find(i)] = find(owner.get(k));
        else owner.set(k, i);
      }
    });
    const sizes = new Map();
    for (let i = 0; i < parent.length; i++) sizes.set(find(i), (sizes.get(find(i)) ?? 0) + 1);
    return LOG2(p.citations.length / Math.max(...sizes.values()));
  }

  /**
   * Min-entropy of a uniform choice among `outputs(s)` for the transform at
   * index `i`, worst case over the library, over every text it may receive
   * and over every truncation a later T05 may apply to its result.
   */
  function choiceBits(i, outputs) {
    const posts = after(i, isCode("T05")) ? truncations : (o) => [o];
    return minOver(p.citations, (c) => {
      let bits = Infinity;
      for (const s of inputsAt(i, folded(c))) {
        const outs = outputs(s).map(posts);
        for (let k = 0; k < outs[0].length; k++) {
          bits = Math.min(bits, uniformMinEntropy(outs.map((o) => o[k])));
        }
      }
      return bits;
    });
  }

  /**
   * T02/T03: each eligible character is substituted independently. A letter
   * shared by several leet transforms is credited once, by the first one,
   * with the combined substitution probability of all of them.
   */
  function leetBits(t, i) {
    const keys = LEET_KEYS[t.code].filter(
      (k) => !before(i, (o) => isLeet(o) && LEET_KEYS[o.code].includes(k)),
    );
    const perKey = new Map(
      keys.map((k) => {
        const keep = ts
          .filter((o) => isLeet(o) && LEET_KEYS[o.code].includes(k))
          .reduce((acc, o) => acc * (1 - o.parameters.probability), 1);
        return [k, -LOG2(Math.max(keep, 1 - keep))];
      }),
    );
    const bitsOf = (s) => {
      let bits = 0;
      for (const ch of s.toLowerCase()) bits += perKey.get(ch) ?? 0;
      return bits;
    };
    return minOver(p.citations, (c) => Math.min(...citationViews(c).map(bitsOf)));
  }
}

/**
 * Per-character changes `list` may make (case, diacritics, leet), as one
 * normalising function: texts equal after it may be indistinguishable.
 */
function charFold(list) {
  const codes = list.map((t) => t.code);
  const lower = codes.some((c) => c === "T01" || c === "T07");
  const strip = codes.includes("T06");
  const leet = codes.some((c) => c in LEET_KEYS);
  return (s) => {
    let out = strip ? stripDiacritics(s) : s;
    if (lower) out = out.toLowerCase();
    if (leet) out = out.replace(/[aeiostlgbz]/giu, (ch) => LEET[ch.toLowerCase()] ?? ch);
    return out;
  };
}

/** Worst-case properties of the corpus (`views`: texts reaching the output). */
function libraryFacts(citations, leetKeys, views) {
  const cased = (ch) => isCased(ch) && !leetKeys.includes(ch.toLowerCase());
  const hasCased = (s) => Array.from(s).some(cased);
  return {
    minWords: minOver(citations, (c) => words(c).length),
    allStartCased: citations.every((c) => cased(c.trim()[0] ?? "")),
    allViewsCased: citations.every((c) => views(c).every(hasCased)),
    allHaveDiacritics: citations.every((c) => /[\u0300-\u036f]/u.test(c.normalize("NFD"))),
  };
}

/** Outputs of T05 for `s`: bypass, first-N of each word, initials. */
function variantsT05(s, t05) {
  const ws = words(s);
  return [
    s,
    ws.map((w) => w.slice(0, t05.parameters.firstN)).join(""),
    ws.map((w) => w[0]).join(""),
  ];
}

/**
 * T01: min-entropy of the case mode over the outputs that are guaranteed
 * distinct. Multi-word text keeps all five modes apart, except PascalCase
 * and camelCase when the first character is uncased. A single word merges
 * lowercase/camelCase and uppercase/SCREAMING_SNAKE; PascalCase matches
 * uppercase when the rest of the word has no cased letter left, or
 * lowercase when its first character is uncased: the worse case counts.
 */
function caseBits(candidates, multiWord, startCased, hasCased) {
  if (!hasCased) return 0;
  const partitions = [];
  if (multiWord) {
    partitions.push((m) => (!startCased && m === "PascalCase" ? "camelCase" : m));
  } else {
    const base = (m) => (m === "lowercase" || m === "camelCase" ? "lower" : "upper");
    partitions.push(base);
    if (!startCased) partitions.push((m) => (m === "PascalCase" ? "lower" : base(m)));
  }
  return Math.min(...partitions.map((cls) => uniformMinEntropy(candidates.map(cls))));
}

/** -log2(max probability) of a uniform draw over `outcomes` (may repeat). */
function uniformMinEntropy(outcomes) {
  const counts = new Map();
  for (const o of outcomes) counts.set(o, (counts.get(o) ?? 0) + 1);
  return LOG2(outcomes.length / Math.max(...counts.values()));
}

function reverseWords(s) {
  return s.trim().split(/\s+/u).reverse().join(" ");
}

function words(s) {
  return s.trim().split(/\s+/u).filter(Boolean);
}

function isCased(ch) {
  return ch.toUpperCase() !== ch.toLowerCase();
}

/** Minimum of fn over list; stops early at 0, the floor of every credit. */
function minOver(list, fn) {
  let min = Infinity;
  for (const x of list) {
    min = Math.min(min, fn(x));
    if (min <= 0) break;
  }
  return min;
}

function memoize(fn) {
  const cache = new Map();
  return (s) => {
    if (!cache.has(s)) cache.set(s, fn(s));
    return cache.get(s);
  };
}

// -----------------------------------------------------------------------------

function finalize(breakdown) {
  // Every credit above is already a lower bound, so min, max and expected
  // coincide: the badge never relies on a lucky draw.
  const expected = round(breakdown.reduce((acc, c) => acc + c.bits, 0));
  return {
    minBits: expected,
    maxBits: expected,
    expectedBits: expected,
    anssiLevels: {
      B1: expected >= 50,
      B2: expected >= 80,
      B3: expected >= 100,
    },
    breakdown: breakdown.map((b) => ({ component: b.component, bits: round(b.bits) })),
  };
}

function push(breakdown, component, bits) {
  if (Number.isFinite(bits) && bits > 0) breakdown.push({ component, bits });
}

/** Rounds DOWN to 0.1 bit so the badge never crosses a threshold upward. */
function round(n) {
  return Math.floor(n * 10 + 1e-9) / 10;
}
