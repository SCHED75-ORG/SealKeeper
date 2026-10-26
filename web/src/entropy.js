// =============================================================================
// SealKeeper — Entropy calculator
// =============================================================================
// PRD A §3.5 FR-A.E.1..5
//   - Kerckhoffs: attacker knows everything except the draw.
//   - Deterministic transforms contribute 0 bits.
//   - Same function used by user UI and admin console (FR-A.E.4).
// =============================================================================

import { InvalidPolicyDescriptor } from "./errors.js";
import { resolveLibrary } from "./library.js";

const LOG2 = Math.log2;

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
 */
export function calculateEntropy(policy) {
  if (!policy || typeof policy !== "object") {
    throw new InvalidPolicyDescriptor("policy must be an object");
  }
  switch (policy.generator) {
    case "G1":
      return entropyG1(policy);
    case "G2":
      return entropyG2(policy);
    case "G3":
      return entropyG3(policy);
    default:
      throw new InvalidPolicyDescriptor(`unknown generator ${policy.generator}`);
  }
}

function entropyG1(policy) {
  const breakdown = [];
  const params = policy.parameters ?? {};
  // Size of the corpus the generator really draws from (distinct entries).
  // A bare `corpusSize` number is no longer trusted: without the entries
  // resolveLibrary throws LibraryNotFound (audit js-generation#1).
  const corpusSize = resolveLibrary(policy).length;
  const sepCount = (params.separatorOptions ?? []).length || 10;
  const digitGroups = params.numericGroups ?? [
    { digitsCount: 3 },
    { digitsCount: 3 },
    { digitsCount: 3 },
  ];
  const totalDigits = digitGroups.reduce((acc, g) => acc + numberOr(g.digitsCount, 0), 0);
  const activeTransforms = (params.transforms ?? []).filter(
    (t) => t && t.active && t.mode === "random",
  );

  push(breakdown, "citation-selection", LOG2(corpusSize));
  push(breakdown, "separator", LOG2(sepCount));
  push(breakdown, "digit-groups", totalDigits * LOG2(10));

  for (const t of activeTransforms) {
    push(breakdown, `transform-${t.code}`, transformBits(t));
  }

  return finalize(breakdown);
}

function entropyG2(policy) {
  const breakdown = [];
  const params = policy.parameters ?? {};
  // Same lookup as G1: distinct entries of the dictionary actually used.
  const dictSize = resolveLibrary(policy).length;
  const words = numberOr(params.numberOfWords, 6);
  const sepCount = (params.separatorOptions ?? []).length || 10;
  const digitGroups = params.numericGroups ?? [{ digitsCount: 4, position: "suffix" }];
  const totalDigits = digitGroups.reduce((acc, g) => acc + numberOr(g.digitsCount, 0), 0);

  push(breakdown, "word-selection", words * LOG2(dictSize));
  push(breakdown, "separator", LOG2(sepCount));
  push(breakdown, "digit-suffix", totalDigits * LOG2(10));

  // T01..T09 may also apply on G2 if the policy enables them.
  for (const t of params.transforms ?? []) {
    if (t && t.active && t.mode === "random") {
      push(breakdown, `transform-${t.code}`, transformBits(t));
    }
  }

  return finalize(breakdown);
}

function entropyG3(policy) {
  const breakdown = [];
  const params = policy.parameters ?? {};
  const length = numberOr(params.length, 20);
  const alphabetSize = numberOr(params.alphabetSize, 62);
  push(breakdown, "alphabet-draw", length * LOG2(alphabetSize));
  return finalize(breakdown);
}

function transformBits(t) {
  switch (t.code) {
    case "T01":
      return LOG2(numberOr((t.parameters ?? {}).candidates?.length, 5));
    case "T02":
    case "T03": {
      // n independent Bernoulli substitutions over the password — without a
      // sample at hand we estimate via the policy's expectedSubstitutionsHint.
      const n = numberOr((t.parameters ?? {}).expectedSubstitutionsHint, t.code === "T03" ? 8 : 5);
      return n;
    }
    case "T04":
      return LOG2(3);
    case "T05":
      return LOG2(3);
    case "T06":
      return 1;
    case "T07":
      return 1;
    case "T08":
      return LOG2(10);
    case "T09":
      return 16;
    default:
      return 0;
  }
}

function finalize(breakdown) {
  const min = breakdown.reduce((acc, c) => acc + c.bits, 0);
  // For the skeleton we treat min and max as equal — concrete generators
  // can widen the range with their own min/max calculations.
  const expected = min;
  const max = min;
  return {
    minBits: round(min),
    maxBits: round(max),
    expectedBits: round(expected),
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

function numberOr(value, fallback) {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : fallback;
}

function round(n) {
  return Math.round(n * 10) / 10;
}
