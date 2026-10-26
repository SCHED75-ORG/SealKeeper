// =============================================================================
// SealKeeper — Generation bundle entry point
// =============================================================================
// PRD A §6.1 (D-A.1): the bundle exposes a global namespace
// `window.SealKeeper.Generation`. The Go backend serves the UMD build at a
// static path and the reveal page loads it via <script src="...">.
// =============================================================================

import { generateG1 } from "./generators/g1.js";
import { generateG2 } from "./generators/g2.js";
import { generateG3 } from "./generators/g3.js";
import { calculateEntropy, anssiLevel } from "./entropy.js";
import { resolveLibrary } from "./library.js";
import { normalizeTopLevel } from "./params.js";
import { InvalidPolicyDescriptor, LibraryNotFound, RegenerationLimitExceeded } from "./errors.js";

const regenCount = new WeakMap();

/**
 * @param {object} policy
 * @returns {Promise<Array<{password:string, entropyBits:number, anssiLevel:string|null, generator:string}>>}
 */
export async function generate(policy) {
  const { proposalCount: n } = validatePolicy(policy);
  const proposals = [];
  // Same resolution as calculateEntropy: the badge describes the library
  // actually drawn from, never an assumed size.
  const library = resolveLibrary(policy);
  const entropy = calculateEntropy(policy);

  for (let i = 0; i < n; i++) {
    const password = await generateOne(policy, library);
    proposals.push({
      password,
      entropyBits: entropy.expectedBits,
      anssiLevel: anssiLevel(entropy.expectedBits),
      generator: policy.generator,
    });
  }
  return proposals;
}

/**
 * @param {object} policy
 * @returns {Promise<Array>}
 */
export async function regenerate(policy) {
  const { regenerateLimit: limit } = validatePolicy(policy);
  const used = regenCount.get(policy) ?? 0;
  if (used >= limit) throw new RegenerationLimitExceeded();
  regenCount.set(policy, used + 1);
  return generate(policy);
}

export { calculateEntropy } from "./entropy.js";

/**
 * Builds the generate() descriptor from the `policy` object returned by
 * GET /api/v1/policy?token=… . Two shapes reach the reveal page:
 *   - a resolved admin policy (`generator`, `proposalCount`, `parameters`):
 *     passed through untouched so proposals honour what the operator set;
 *   - the built-in default (`generators: [...]`, no admin policy yet):
 *     G2 over the sample dictionary, flagged `builtinDefault: true`. That
 *     flag is the only way to reach the bundled samples; it is never copied
 *     from an admin policy, so an admin G1/G2 policy without an inline
 *     library fails with LibraryNotFound instead of drawing from them.
 * An unknown generator is not replaced by a default — generate() rejects
 * it, so a broken policy fails visibly instead of yielding weaker output.
 * @param {object} policy
 * @returns {{generator:string, proposalCount:number, regenerateLimit?:number, parameters:object, builtinDefault?:true}}
 */
export function descriptorFromPolicy(policy) {
  if (!policy || typeof policy !== "object") throw new InvalidPolicyDescriptor("not an object");
  if (policy.generator !== undefined) {
    return {
      generator: policy.generator,
      proposalCount: policy.proposalCount ?? 5,
      regenerateLimit: policy.regenerateLimit,
      parameters: policy.parameters ?? {},
    };
  }
  return { generator: "G2", proposalCount: 5, parameters: {}, builtinDefault: true };
}

async function generateOne(policy, library) {
  switch (policy.generator) {
    case "G1":
      return generateG1(policy, library);
    case "G2":
      return generateG2(policy, library);
    case "G3":
      return generateG3(policy);
    default:
      throw new InvalidPolicyDescriptor(`unknown generator ${policy.generator}`);
  }
}

function validatePolicy(policy) {
  if (!policy || typeof policy !== "object") throw new InvalidPolicyDescriptor("not an object");
  if (!policy.generator) throw new InvalidPolicyDescriptor("missing generator");
  if (!["G1", "G2", "G3"].includes(policy.generator)) {
    throw new InvalidPolicyDescriptor(`unknown generator ${policy.generator}`);
  }
  // Generator parameters are validated by the same normalisers that
  // calculateEntropy and the generators use (params.js).
  return normalizeTopLevel(policy);
}

// -----------------------------------------------------------------------------
// Attach the namespace on the global object when running in a browser.
// `window` is undefined in Node, hence the typeof guard.
// -----------------------------------------------------------------------------

const Generation = { generate, regenerate, calculateEntropy, descriptorFromPolicy };

if (typeof window !== "undefined") {
  window.SealKeeper = window.SealKeeper || {};
  window.SealKeeper.Generation = Generation;
}

export default Generation;
export { InvalidPolicyDescriptor, LibraryNotFound, RegenerationLimitExceeded };
