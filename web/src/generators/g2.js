// =============================================================================
// G2 — Diceware-style generator
// =============================================================================
// PRD A §3.2 (FR-A.G2.1..6):
//   - 6 independent draws from a dictionary of ≥ 5000 words
//   - One separator drawn from 10 candidates per policy
//   - 4 random digits appended (separated or collated per policy)
//   - Effective entropy ≥ 80 bits (B2 target)
// =============================================================================

import { cryptoRandomChoice, cryptoRandomInt } from "../crypto.js";
import { normalizeG2 } from "../params.js";

/**
 * @param {object} policy
 * @param {string[]} dictionary
 * @returns {string}
 */
export function generateG2(policy, dictionary) {
  // Same validated, deduplicated reading as calculateEntropy (params.js).
  // Only the first numeric group is used and no transform is applied;
  // entropy credits exactly that.
  const { words: entries, wordCount, separators, digits } = normalizeG2(policy, dictionary);
  const separator = cryptoRandomChoice(separators);

  const words = [];
  for (let i = 0; i < wordCount; i++) {
    words.push(cryptoRandomChoice(entries));
  }
  if (!digits) return words.join(separator);
  const suffix = randomDigits(digits.digitsCount);
  if (digits.attached) {
    words[words.length - 1] = words[words.length - 1] + suffix;
    return words.join(separator);
  }
  return words.join(separator) + separator + suffix;
}

function randomDigits(n) {
  let out = "";
  for (let i = 0; i < n; i++) out += String(cryptoRandomInt(10));
  return out;
}
