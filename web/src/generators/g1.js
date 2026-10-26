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
import { normalizeG1 } from "../params.js";
import { applyTransforms } from "../transforms.js";

/**
 * @param {object} policy   Policy descriptor for generator G1
 * @param {string[]} corpus
 * @returns {Promise<string>}
 */
export async function generateG1(policy, corpus) {
  // Same validated, deduplicated reading as calculateEntropy (params.js).
  const { citations, separators, groups, transforms } = normalizeG1(policy, corpus);
  const separator = cryptoRandomChoice(separators);

  const citation = cryptoRandomChoice(citations);
  const transformed = await applyTransforms(citation, transforms);

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
    const digits = randomDigits(g.digitsCount);
    switch (g.position) {
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
