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
import { uniqueLibrary } from "../library.js";

const DEFAULT_SEPARATORS = ["-", "_", ".", "/", "+", ":", "|", ";", ",", "~"];

/**
 * @param {object} policy
 * @param {string[]} dictionary
 * @returns {string}
 */
export function generateG2(policy, dictionary) {
  // Distinct entries only, so the draw matches the log2(size) entropy credit.
  const entries = uniqueLibrary(dictionary, "G2");
  const params = policy.parameters ?? {};
  const wordCount = params.numberOfWords ?? 6;
  const separator = cryptoRandomChoice(params.separatorOptions ?? DEFAULT_SEPARATORS);
  const numericGroup = (params.numericGroups ?? [{ digitsCount: 4, position: "suffix" }])[0];
  const digitsCount = numericGroup.digitsCount ?? 4;
  const attached = numericGroup.separator === undefined ? false : numericGroup.separator === "";

  const words = [];
  for (let i = 0; i < wordCount; i++) {
    words.push(cryptoRandomChoice(entries));
  }
  const digits = randomDigits(digitsCount);
  if (attached) {
    words[words.length - 1] = words[words.length - 1] + digits;
    return words.join(separator);
  }
  return words.join(separator) + separator + digits;
}

function randomDigits(n) {
  let out = "";
  for (let i = 0; i < n; i++) out += String(cryptoRandomInt(10));
  return out;
}
