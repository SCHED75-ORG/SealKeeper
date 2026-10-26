// =============================================================================
// SealKeeper — Policy parameter normalisation
// =============================================================================
// One typed reading of `policy.parameters`, shared by the generators and the
// entropy calculator, so the badge always describes the draw that really
// happens (audit js-generation#2/#3):
//   - every parameter is validated up front; a zero, negative, fractional or
//     string number, an empty list or an unknown enum value throws
//     InvalidPolicyDescriptor instead of being replaced by a default on one
//     side and honoured on the other;
//   - lists the generator draws from (separators, symbols, case modes) are
//     deduplicated so the draw is uniform and log2(length) is exact;
//   - size claims (corpusSize, dictionarySize, alphabetSize) must match what
//     the generator really uses, or the policy is rejected.
// The bounds below reject nonsense, not weak-but-legal policies: those are
// accepted and simply badged with their real (low) entropy.
// =============================================================================

import { InvalidPolicyDescriptor } from "./errors.js";
import { uniqueLibrary } from "./library.js";

export const DEFAULT_SEPARATORS = ["-", "_", ".", "/", "+", ":", "|", ";", ",", "~"];
export const DEFAULT_SYMBOLS = ["!", "@", "#", "$", "%", "&", "*", "+", "=", "?"];
export const CASE_MODES = ["lowercase", "uppercase", "camelCase", "PascalCase", "SCREAMING_SNAKE"];
export const ALPHABET_FULL = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
export const AMBIGUOUS = ["l", "I", "1", "0", "O"];

const TRANSFORM_CODES = ["T01", "T02", "T03", "T04", "T05", "T06", "T07", "T08", "T09"];
const POSITIONS = ["prefix", "middle", "suffix"];
const G1_DEFAULT_GROUPS = [
  { position: "prefix", digitsCount: 3 },
  { position: "middle", digitsCount: 3 },
  { position: "suffix", digitsCount: 3 },
];
const G2_DEFAULT_GROUP = { position: "suffix", digitsCount: 4 };

const MAX_PROPOSALS = 50;
const MAX_REGENERATE = 100;
const MAX_WORDS = 64;
const MAX_DIGITS = 32;
const MAX_LENGTH = 256;
const MAX_TRANSFORM_LENGTH = 64;

/**
 * Validates the top-level descriptor fields shared by every generator.
 * @param {object} policy
 * @returns {{proposalCount:number, regenerateLimit:number}}
 */
export function normalizeTopLevel(policy) {
  return {
    proposalCount: intIn(policy.proposalCount, "proposalCount", 1, MAX_PROPOSALS, 5),
    regenerateLimit: intIn(policy.regenerateLimit, "regenerateLimit", 0, MAX_REGENERATE, 3),
  };
}

/**
 * @param {object} policy  G1 descriptor
 * @param {string[]} library
 */
export function normalizeG1(policy, library) {
  const params = parametersOf(policy);
  const citations = uniqueLibrary(library, "G1");
  sizeClaim(params.corpusSize, "corpusSize", citations.length, "distinct library entries");
  return {
    citations,
    separators: stringList(params.separatorOptions, "separatorOptions", DEFAULT_SEPARATORS),
    groups: numericGroups(params.numericGroups, G1_DEFAULT_GROUPS, 3),
    transforms: transforms(params.transforms),
  };
}

/**
 * G2 consumes only the first numeric group and never applies transforms:
 * extra groups and transforms are validated but not credited by entropy.
 * @param {object} policy  G2 descriptor
 * @param {string[]} library
 */
export function normalizeG2(policy, library) {
  const params = parametersOf(policy);
  const words = uniqueLibrary(library, "G2");
  sizeClaim(params.dictionarySize, "dictionarySize", words.length, "distinct library entries");
  const groups = numericGroups(params.numericGroups, [G2_DEFAULT_GROUP], 4);
  transforms(params.transforms);
  const first = groups[0];
  return {
    words,
    wordCount: intIn(params.numberOfWords, "numberOfWords", 1, MAX_WORDS, 6),
    separators: stringList(params.separatorOptions, "separatorOptions", DEFAULT_SEPARATORS),
    // `separator: ""` glues the digits to the last word.
    digits: first ? { digitsCount: first.digitsCount, attached: first.separator === "" } : null,
  };
}

/** @param {object} policy  G3 descriptor */
export function normalizeG3(policy) {
  const params = parametersOf(policy);
  const excludeAmbiguous = bool(params.excludeAmbiguous, "excludeAmbiguous", false);
  const alphabet = Array.from(ALPHABET_FULL).filter(
    (c) => !excludeAmbiguous || !AMBIGUOUS.includes(c),
  );
  // The generator draws from a fixed alphabet; a different declared size
  // used to be credited while being ignored (audit js-generation#2).
  sizeClaim(params.alphabetSize, "alphabetSize", alphabet.length, "characters drawn by G3");
  const length = intIn(params.length, "length", 1, MAX_LENGTH, 20);
  return {
    length,
    alphabet,
    blockSize: intIn(params.blockSize, "blockSize", 0, MAX_LENGTH, 5),
    blockSeparator: string(params.blockSeparator, "blockSeparator", "-"),
  };
}

// -----------------------------------------------------------------------------
// Building blocks
// -----------------------------------------------------------------------------

function parametersOf(policy) {
  const params = policy?.parameters ?? {};
  if (typeof params !== "object" || Array.isArray(params)) {
    throw new InvalidPolicyDescriptor("parameters must be an object");
  }
  return params;
}

function numericGroups(value, fallback, defaultDigits) {
  if (value === undefined) return fallback;
  if (!Array.isArray(value)) throw new InvalidPolicyDescriptor("numericGroups must be an array");
  return value.map((g, i) => {
    if (!g || typeof g !== "object") {
      throw new InvalidPolicyDescriptor(`numericGroups[${i}] must be an object`);
    }
    const position = g.position ?? "suffix";
    if (!POSITIONS.includes(position)) {
      throw new InvalidPolicyDescriptor(`numericGroups[${i}].position ${JSON.stringify(position)}`);
    }
    if (g.separator !== undefined && typeof g.separator !== "string") {
      throw new InvalidPolicyDescriptor(`numericGroups[${i}].separator must be a string`);
    }
    return {
      position,
      digitsCount: intIn(
        g.digitsCount,
        `numericGroups[${i}].digitsCount`,
        0,
        MAX_DIGITS,
        defaultDigits,
      ),
      separator: g.separator,
    };
  });
}

/** Active transforms, in order, with their parameters filled in. */
function transforms(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new InvalidPolicyDescriptor("transforms must be an array");
  const out = [];
  for (const t of value) {
    if (!t || typeof t !== "object")
      throw new InvalidPolicyDescriptor("transform must be an object");
    if (!TRANSFORM_CODES.includes(t.code)) {
      throw new InvalidPolicyDescriptor(`unknown transform ${JSON.stringify(t.code)}`);
    }
    if (!t.active) continue;
    if (out.some((o) => o.code === t.code)) {
      throw new InvalidPolicyDescriptor(`transform ${t.code} listed twice`);
    }
    if (t.mode !== undefined && t.mode !== "random" && t.mode !== "deterministic") {
      throw new InvalidPolicyDescriptor(`transform ${t.code} mode ${JSON.stringify(t.mode)}`);
    }
    out.push({
      code: t.code,
      active: true,
      mode: t.mode,
      parameters: transformParameters(t.code, t.parameters ?? {}),
    });
  }
  return out;
}

function transformParameters(code, p) {
  const name = (key) => `${code}.${key}`;
  switch (code) {
    case "T01": {
      const candidates = stringList(p.candidates, name("candidates"), CASE_MODES);
      for (const c of candidates) {
        if (!CASE_MODES.includes(c)) {
          throw new InvalidPolicyDescriptor(
            `${name("candidates")} unknown mode ${JSON.stringify(c)}`,
          );
        }
      }
      return { candidates };
    }
    case "T02":
    case "T03": {
      // expectedSubstitutionsHint is no longer read: entropy is derived from
      // the library and the probability (audit js-generation#4).
      const probability = p.probability ?? 0.5;
      if (typeof probability !== "number" || !(probability > 0 && probability < 1)) {
        throw new InvalidPolicyDescriptor(`${name("probability")} must be in (0, 1)`);
      }
      return { probability };
    }
    case "T05":
      return { firstN: intIn(p.firstN, name("firstN"), 1, MAX_TRANSFORM_LENGTH, 3) };
    case "T08":
      return { symbols: stringList(p.symbols, name("symbols"), DEFAULT_SYMBOLS) };
    case "T09":
      return { length: intIn(p.length, name("length"), 1, MAX_TRANSFORM_LENGTH, 4) };
    default:
      return {};
  }
}

function intIn(value, name, min, max, fallback) {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new InvalidPolicyDescriptor(
      `${name} must be an integer in [${min}, ${max}], got ${JSON.stringify(value)}`,
    );
  }
  return value;
}

function bool(value, name, fallback) {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") {
    throw new InvalidPolicyDescriptor(`${name} must be a boolean, got ${JSON.stringify(value)}`);
  }
  return value;
}

function string(value, name, fallback) {
  if (value === undefined) return fallback;
  if (typeof value !== "string") throw new InvalidPolicyDescriptor(`${name} must be a string`);
  return value;
}

/** Non-empty list of non-empty strings, deduplicated in first-seen order. */
function stringList(value, name, fallback) {
  if (value === undefined) return fallback;
  if (!Array.isArray(value) || value.length === 0) {
    throw new InvalidPolicyDescriptor(`${name} must be a non-empty array`);
  }
  for (const v of value) {
    if (typeof v !== "string" || v.length === 0) {
      throw new InvalidPolicyDescriptor(`${name} entries must be non-empty strings`);
    }
  }
  return Array.from(new Set(value));
}

function sizeClaim(value, name, actual, what) {
  if (value === undefined || value === actual) return;
  throw new InvalidPolicyDescriptor(
    `${name} ${JSON.stringify(value)} does not match the ${actual} ${what}`,
  );
}
