// =============================================================================
// SealKeeper — WebCrypto random helpers
// =============================================================================
// PRD A NFR: `crypto.getRandomValues()` exclusively, NEVER `Math.random()`.
// This module is the only place in the bundle that touches the RNG.
// =============================================================================

/**
 * @returns {Crypto} The global WebCrypto object (or Node's `webcrypto`).
 * @throws {Error} When no WebCrypto implementation is available.
 */
function getCrypto() {
  // Browser / modern Node both expose globalThis.crypto.
  if (typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.getRandomValues) {
    return globalThis.crypto;
  }
  throw new Error("WebCryptoUnavailable");
}

/**
 * Returns `n` cryptographically random bytes as a Uint8Array.
 * @param {number} n
 * @returns {Uint8Array}
 */
export function cryptoRandomBytes(n) {
  if (!Number.isInteger(n) || n < 1) {
    throw new RangeError("cryptoRandomBytes: n must be a positive integer");
  }
  const out = new Uint8Array(n);
  getCrypto().getRandomValues(out);
  return out;
}

/**
 * Uniform random integer in [0, max), unbiased — uses rejection sampling.
 *
 * @param {number} max  Exclusive upper bound. Must be a positive integer < 2^32.
 * @returns {number}
 */
export function cryptoRandomInt(max) {
  if (!Number.isInteger(max) || max < 1) {
    throw new RangeError("cryptoRandomInt: max must be a positive integer");
  }
  if (max === 1) return 0;
  if (max > 0xffffffff) {
    throw new RangeError("cryptoRandomInt: max must fit in uint32");
  }
  // Number of bits we need. `|=` works on signed int32, so for max > 2^31
  // the mask would read as -1 and `buf[0] & mask` as a negative number;
  // `>>> 0` brings both back to uint32 (audit js-generation#5).
  let mask = max - 1;
  mask |= mask >>> 1;
  mask |= mask >>> 2;
  mask |= mask >>> 4;
  mask |= mask >>> 8;
  mask |= mask >>> 16;
  mask >>>= 0;

  const buf = new Uint32Array(1);
  // Rejection loop: keep drawing until we land below `max`.
  // With mask sized to (next power of 2) - 1 the worst-case acceptance
  // probability is 0.5, so the loop terminates very quickly.
  for (;;) {
    getCrypto().getRandomValues(buf);
    const candidate = (buf[0] & mask) >>> 0;
    if (candidate < max) return candidate;
  }
}

/**
 * Pick a uniformly random element from `arr`.
 * @template T
 * @param {ReadonlyArray<T>} arr
 * @returns {T}
 */
export function cryptoRandomChoice(arr) {
  if (!Array.isArray(arr) || arr.length === 0) {
    throw new RangeError("cryptoRandomChoice: array must be non-empty");
  }
  return arr[cryptoRandomInt(arr.length)];
}

/**
 * Coin-flip with optional bias (default 0.5). Useful for T02/T03 per-character
 * leet substitutions. Implemented by drawing 32 random bits and comparing
 * with a uint32 threshold — uniform and bias-correct.
 *
 * @param {number} [p=0.5] Probability of returning true. Must be in (0, 1).
 * @returns {boolean}
 */
export function cryptoCoin(p = 0.5) {
  if (!(p > 0 && p < 1)) {
    throw new RangeError("cryptoCoin: p must be strictly between 0 and 1");
  }
  const threshold = Math.floor(p * 0x100000000);
  const buf = new Uint32Array(1);
  getCrypto().getRandomValues(buf);
  return buf[0] < threshold;
}

/**
 * In-place Fisher–Yates shuffle using crypto-grade randomness.
 * @template T
 * @param {T[]} arr
 * @returns {T[]} the same array, mutated
 */
export function cryptoShuffleInPlace(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = cryptoRandomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}
