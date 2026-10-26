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
import { SAMPLE_DICTIONARY_FR } from "./data/sample-dictionary.js";
import { SAMPLE_CORPUS_FR } from "./data/sample-corpus.js";

class RegenerationLimitExceeded extends Error {
  constructor() {
    super("RegenerationLimitExceeded");
    this.name = "RegenerationLimitExceeded";
  }
}

class InvalidPolicyDescriptor extends Error {
  constructor(msg) {
    super(`InvalidPolicyDescriptor: ${msg}`);
    this.name = "InvalidPolicyDescriptor";
  }
}

const regenCount = new WeakMap();

/**
 * @param {object} policy
 * @returns {Promise<Array<{password:string, entropyBits:number, anssiLevel:string|null, generator:string}>>}
 */
export async function generate(policy) {
  validatePolicy(policy);
  const proposals = [];
  const n = policy.proposalCount ?? 5;
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
  validatePolicy(policy);
  const limit = policy.regenerateLimit ?? 3;
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
 *     G2 over the sample dictionary.
 * An unknown generator is not replaced by a default — generate() rejects
 * it, so a broken policy fails visibly instead of yielding weaker output.
 * @param {object} policy
 * @returns {{generator:string, proposalCount:number, regenerateLimit?:number, parameters:object}}
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
  return { generator: "G2", proposalCount: 5, parameters: {} };
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
}

function resolveLibrary(policy) {
  if (policy.generator === "G3") return null;
  const params = policy.parameters ?? {};
  if (Array.isArray(params.library)) return params.library;
  // Fallback to sample library so the bundle is usable out of the box.
  return policy.generator === "G1" ? SAMPLE_CORPUS_FR : SAMPLE_DICTIONARY_FR;
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
export { InvalidPolicyDescriptor, RegenerationLimitExceeded };
