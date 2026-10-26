// =============================================================================
// SealKeeper — Library resolution (G1 corpus / G2 dictionary)
// =============================================================================
// PRD A §7: a G1/G2 policy without its library fails with LibraryNotFound.
// There is deliberately no silent fallback: the bundled samples are public
// and tiny (32 citations / 256 words), so an admin policy that lands on them
// would be far weaker than its badge (audit js-generation#1).
//
// The only caller allowed to use the samples is the zero-config default,
// which descriptorFromPolicy() marks with `builtinDefault: true`. Entropy is
// then computed from the sample's real size like any other library.
//
// Duplicates are removed before drawing, so the draw is uniform over the
// distinct entries and log2(length) is the exact selection entropy.
// =============================================================================

import { InvalidPolicyDescriptor, LibraryNotFound } from "./errors.js";
import { SAMPLE_DICTIONARY_FR } from "./data/sample-dictionary.js";
import { SAMPLE_CORPUS_FR } from "./data/sample-corpus.js";

/**
 * Library the generator will draw from, deduplicated. `null` for G3.
 * @param {object} policy
 * @returns {string[]|null}
 * @throws {LibraryNotFound|InvalidPolicyDescriptor}
 */
export function resolveLibrary(policy) {
  if (policy.generator === "G3") return null;
  const params = policy.parameters ?? {};
  if (params.library === undefined && policy.builtinDefault === true) {
    return uniqueLibrary(
      policy.generator === "G1" ? SAMPLE_CORPUS_FR : SAMPLE_DICTIONARY_FR,
      policy.generator,
    );
  }
  return uniqueLibrary(params.library, policy.generator);
}

/**
 * Validates an inline library and returns its distinct entries, in first-seen
 * order.
 * @param {unknown} library
 * @param {string} generator  For error messages only.
 * @returns {string[]}
 * @throws {LibraryNotFound|InvalidPolicyDescriptor}
 */
export function uniqueLibrary(library, generator) {
  if (!Array.isArray(library)) {
    // Library ids (FR-A.G1.6 / FR-A.G2.5) are not resolved by the bundle:
    // the server must ship the entries inline.
    const got = typeof library === "string" ? `id "${library}"` : typeof library;
    throw new LibraryNotFound(`${generator} requires an inline library array, got ${got}`);
  }
  if (library.length === 0) {
    throw new LibraryNotFound(`${generator} requires a non-empty library`);
  }
  for (const entry of library) {
    if (typeof entry !== "string" || entry.length === 0) {
      throw new InvalidPolicyDescriptor(`${generator} library entries must be non-empty strings`);
    }
  }
  return Array.from(new Set(library));
}
