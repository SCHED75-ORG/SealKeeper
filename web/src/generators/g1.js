// =============================================================================
// G1 — Citation-based generator
// =============================================================================
// PRD A §3.1 (FR-A.G1.1..6):
//   - Pick one citation from a corpus of ≥ 5000 entries
//   - Apply T01..T09 (T10 reported to 0.2.0) per policy
//   - 3 groups of 3 random digits at policy-defined positions
//   - One separator from a 10-character list, also per policy
//   - Effective entropy ≥ 50 bits (B1 target)
// =============================================================================

import { cryptoRandomChoice, cryptoRandomInt } from "../crypto.js";
import { uniqueLibrary } from "../library.js";
import { applyTransforms } from "../transforms.js";

const DEFAULT_SEPARATORS = ["-", "_", ".", "/", "+", ":", "|", ";", ",", "~"];
const DEFAULT_POSITIONS = [
  { position: "prefix", digitsCount: 3 },
  { position: "middle", digitsCount: 3 },
  { position: "suffix", digitsCount: 3 },
];

/**
 * @param {object} policy   Policy descriptor for generator G1
 * @param {string[]} corpus
 * @returns {Promise<string>}
 */
export async function generateG1(policy, corpus) {
  // Distinct entries only, so the draw matches the log2(size) entropy credit.
  const citations = uniqueLibrary(corpus, "G1");
  const params = policy.parameters ?? {};
  const separator = cryptoRandomChoice(params.separatorOptions ?? DEFAULT_SEPARATORS);
  const groups = params.numericGroups ?? DEFAULT_POSITIONS;

  const citation = cryptoRandomChoice(citations);
  const transformed = await applyTransforms(citation, params.transforms ?? []);

  // Place digit groups at the requested positions. We split the transformed
  // citation in half on a whitespace boundary for the "middle" insertion.
  const collapsed = transformed.replace(/\s+/gu, separator);
  let prefix = "";
  let suffix = "";
  let middleLeft = collapsed;
  let middleRight = "";
  const midSep = collapsed.indexOf(separator, Math.floor(collapsed.length / 2));
  if (midSep > 0) {
    middleLeft = collapsed.slice(0, midSep);
    middleRight = collapsed.slice(midSep + separator.length);
  }

  for (const g of groups) {
    const digits = randomDigits(g.digitsCount ?? 3);
    switch (g.position ?? "suffix") {
      case "prefix":
        prefix = digits + separator + prefix;
        break;
      case "middle":
        middleLeft = middleLeft + separator + digits;
        break;
      case "suffix":
      default:
        suffix = suffix + separator + digits;
    }
  }

  const middle = middleRight ? middleLeft + separator + middleRight : middleLeft;
  return prefix + middle + suffix;
}

function randomDigits(n) {
  let out = "";
  for (let i = 0; i < n; i++) out += String(cryptoRandomInt(10));
  return out;
}
