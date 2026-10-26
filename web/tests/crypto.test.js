import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cryptoCoin,
  cryptoRandomBytes,
  cryptoRandomChoice,
  cryptoRandomInt,
  cryptoShuffleInPlace,
} from "../src/crypto.js";

describe("crypto helpers", () => {
  it("cryptoRandomBytes returns a Uint8Array of the requested length", () => {
    const b = cryptoRandomBytes(16);
    expect(b).toBeInstanceOf(Uint8Array);
    expect(b.length).toBe(16);
  });

  it("cryptoRandomBytes rejects invalid input", () => {
    expect(() => cryptoRandomBytes(0)).toThrow(RangeError);
    expect(() => cryptoRandomBytes(-1)).toThrow(RangeError);
    expect(() => cryptoRandomBytes(1.5)).toThrow(RangeError);
  });

  it("cryptoRandomInt obeys [0, max) bounds across many draws", () => {
    const max = 17;
    const counts = new Array(max).fill(0);
    for (let i = 0; i < 5000; i++) {
      const v = cryptoRandomInt(max);
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThan(max);
      counts[v]++;
    }
    // Every bucket must be hit at least once with 5000 draws / 17 buckets
    for (const c of counts) expect(c).toBeGreaterThan(0);
  });

  it("cryptoRandomInt(1) returns 0 deterministically", () => {
    for (let i = 0; i < 32; i++) expect(cryptoRandomInt(1)).toBe(0);
  });

  it("cryptoRandomInt rejects invalid bounds", () => {
    expect(() => cryptoRandomInt(0)).toThrow(RangeError);
    expect(() => cryptoRandomInt(-3)).toThrow(RangeError);
    expect(() => cryptoRandomInt(2 ** 32 + 1)).toThrow(RangeError);
  });

  it("cryptoRandomChoice picks elements from the array", () => {
    const arr = ["a", "b", "c"];
    const seen = new Set();
    for (let i = 0; i < 100; i++) seen.add(cryptoRandomChoice(arr));
    expect(seen.size).toBe(3);
  });

  it("cryptoRandomChoice rejects empty input", () => {
    expect(() => cryptoRandomChoice([])).toThrow(RangeError);
  });

  it("cryptoCoin rejects out-of-range probabilities", () => {
    expect(() => cryptoCoin(0)).toThrow(RangeError);
    expect(() => cryptoCoin(1)).toThrow(RangeError);
    expect(() => cryptoCoin(-0.1)).toThrow(RangeError);
    expect(() => cryptoCoin(1.5)).toThrow(RangeError);
  });

  it("cryptoCoin produces both outcomes with a fair coin", () => {
    let heads = 0;
    let tails = 0;
    for (let i = 0; i < 2000; i++) cryptoCoin(0.5) ? heads++ : tails++;
    expect(heads).toBeGreaterThan(800);
    expect(tails).toBeGreaterThan(800);
  });

  it("cryptoShuffleInPlace returns a permutation of the input", () => {
    const arr = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    const before = [...arr];
    const result = cryptoShuffleInPlace(arr);
    expect(result).toBe(arr); // same reference
    expect(result.sort((a, b) => a - b)).toEqual(before);
  });
});

// Audit js-generation#5 (SK-38): the int32 mask overflowed for max > 2^31.
describe("cryptoRandomInt above 2^31", () => {
  afterEach(() => vi.restoreAllMocks());

  it("never returns a negative value", () => {
    vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation((buf) => {
      buf[0] = 0xfffffffe;
      return buf;
    });
    expect(cryptoRandomInt(0xffffffff)).toBe(0xfffffffe);
  });

  it("stays in [0, max) on real draws", () => {
    for (const max of [0xffffffff, 2 ** 31 + 1]) {
      for (let i = 0; i < 500; i++) {
        const v = cryptoRandomInt(max);
        expect(v).toBeGreaterThanOrEqual(0);
        expect(v).toBeLessThan(max);
      }
    }
  });
});
