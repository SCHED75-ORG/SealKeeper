import { describe, expect, it } from "vitest";
import { anssiLevel, calculateEntropy } from "../src/entropy.js";

// Entropy is computed from the library actually shipped in the policy, so
// the fixtures carry real (synthetic) entries rather than a size number.
const library = (n, prefix) => Array.from({ length: n }, (_, i) => `${prefix}${i}`);
const CORPUS_5000 = library(5000, "citation ");
const DICT_7776 = library(7776, "word");
// Multi-word, capitalised, accented: every transform has something to act on.
const ACCENTED = library(500, "Été numéro ");

describe("calculateEntropy", () => {
  it("anssiLevel maps thresholds correctly", () => {
    expect(anssiLevel(49)).toBeNull();
    expect(anssiLevel(50)).toBe("B1");
    expect(anssiLevel(79)).toBe("B1");
    expect(anssiLevel(80)).toBe("B2");
    expect(anssiLevel(99)).toBe("B2");
    expect(anssiLevel(100)).toBe("B3");
    expect(anssiLevel(200)).toBe("B3");
  });

  it("rejects non-objects", () => {
    expect(() => calculateEntropy(null)).toThrow(TypeError);
    expect(() => calculateEntropy(42)).toThrow(TypeError);
  });

  it("rejects unknown generators", () => {
    expect(() => calculateEntropy({ generator: "GZ" })).toThrow(/unknown generator/);
  });

  it("G1 baseline (5000 corpus, 10 separators, 3×3 digits) ≥ 30 bits", () => {
    const r = calculateEntropy({ generator: "G1", parameters: { library: CORPUS_5000 } });
    expect(r.expectedBits).toBeGreaterThanOrEqual(30);
    expect(r.anssiLevels.B1).toBe(false); // baseline alone is below B1
  });

  it("G1 with symbol insertion and hash suffix reaches B1", () => {
    const r = calculateEntropy({
      generator: "G1",
      parameters: {
        library: CORPUS_5000,
        transforms: ["T08", "T09"].map((code) => ({ code, active: true, mode: "random" })),
      },
    });
    expect(r.expectedBits).toBeGreaterThanOrEqual(50);
    expect(r.anssiLevels.B1).toBe(true);
  });

  it("G1 composition: all transforms together earn less than their solo credits", () => {
    const codes = ["T01", "T02", "T03", "T04", "T05", "T06", "T07", "T08", "T09"];
    const tr = (code) => ({ code, active: true, mode: "random" });
    const bits = (transforms) =>
      calculateEntropy({ generator: "G1", parameters: { library: ACCENTED, transforms } })
        .expectedBits;
    const base = bits([]);
    const solo = codes.reduce((acc, code) => acc + (bits([tr(code)]) - base), 0);
    expect(bits(codes.map(tr)) - base).toBeLessThan(solo);
  });

  it("G2 default policy (6 words × 7776) reaches B2", () => {
    const r = calculateEntropy({ generator: "G2", parameters: { library: DICT_7776 } });
    expect(r.expectedBits).toBeGreaterThanOrEqual(80);
    expect(r.anssiLevels.B2).toBe(true);
  });

  it("G3 default policy (20 chars × 62) reaches B3", () => {
    const r = calculateEntropy({ generator: "G3" });
    expect(r.expectedBits).toBeGreaterThanOrEqual(100);
    expect(r.anssiLevels.B3).toBe(true);
  });

  it("deterministic transforms add 0 bits", () => {
    const without = calculateEntropy({
      generator: "G1",
      parameters: { library: CORPUS_5000, transforms: [] },
    });
    const withDet = calculateEntropy({
      generator: "G1",
      parameters: {
        library: CORPUS_5000,
        transforms: [{ code: "T01", active: true, mode: "deterministic" }],
      },
    });
    expect(withDet.expectedBits).toBeCloseTo(without.expectedBits, 1);
  });

  it("transform bits cover the catalogue on G1", () => {
    const codes = ["T01", "T02", "T03", "T04", "T05", "T06", "T07", "T08", "T09"];
    for (const code of codes) {
      const r = calculateEntropy({
        generator: "G1",
        parameters: { library: ACCENTED, transforms: [{ code, active: true, mode: "random" }] },
      });
      expect(r.breakdown.map((b) => b.component)).toContain(`transform-${code}`);
    }
  });

  it("G2 never credits transforms (generateG2 does not apply them)", () => {
    const plain = calculateEntropy({ generator: "G2", parameters: { library: DICT_7776 } });
    for (const code of ["T01", "T03", "T08", "T09"]) {
      const r = calculateEntropy({
        generator: "G2",
        parameters: { library: DICT_7776, transforms: [{ code, active: true, mode: "random" }] },
      });
      expect(r.expectedBits).toBe(plain.expectedBits);
    }
  });

  it("G1 separator is not credited when it never shows up", () => {
    const r = calculateEntropy({
      generator: "G1",
      parameters: { library: ["unmot", "autre"], numericGroups: [] },
    });
    expect(r.breakdown.map((b) => b.component)).not.toContain("separator");
  });

  // "\-" is an invalid escape under the u flag: a T08 symbol list holding
  // "-" made calculateEntropy (and so generate) throw.
  it("G1 accepts regex-special T08 symbols, '-' included", () => {
    const symbols = ["-", "+", ".", "/", "\\", "|", "(", "[", "{", "^", "$", "*", "?"];
    const r = calculateEntropy({
      generator: "G1",
      parameters: {
        library: ACCENTED,
        transforms: [{ code: "T08", active: true, mode: "random", parameters: { symbols } }],
      },
    });
    expect(r.breakdown).toContainEqual({ component: "transform-T08", bits: 3.7 });
    // Citations differing only by a dropped symbol still collapse together.
    const merged = calculateEntropy({
      generator: "G1",
      parameters: {
        library: ["a-b c", "ab c"],
        numericGroups: [],
        transforms: [{ code: "T08", active: true, parameters: { symbols: ["-"] } }],
      },
    });
    expect(merged.breakdown.map((b) => b.component)).not.toContain("citation-selection");
  });
});
