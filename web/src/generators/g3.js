// =============================================================================
// G3 — Random alphanumeric blocks
// =============================================================================
// PRD A §3.3 (FR-A.G3.1..5):
//   - 20 chars from a 62-character alphabet (a-z, A-Z, 0-9)
//   - Grouped in 4 blocks of 5 separated by hyphens
//   - Effective entropy ≥ 100 bits (B3 target)
//   - Policy MAY exclude ambiguous chars (l/I/1, 0/O)
//   - Stateless: no library required
// =============================================================================

import { cryptoRandomChoice } from "../crypto.js";
import { normalizeG3 } from "../params.js";

/**
 * @param {object} policy
 * @returns {string}
 */
export function generateG3(policy) {
  // Same validated reading as calculateEntropy (params.js): the alphabet
  // drawn here is the one whose size entropy uses.
  const { length, alphabet, blockSize, blockSeparator } = normalizeG3(policy);

  let chars = "";
  for (let i = 0; i < length; i++) {
    chars += cryptoRandomChoice(alphabet);
  }

  if (blockSize <= 0 || blockSize >= length) return chars;
  const blocks = [];
  for (let i = 0; i < chars.length; i += blockSize) {
    blocks.push(chars.slice(i, i + blockSize));
  }
  return blocks.join(blockSeparator);
}
