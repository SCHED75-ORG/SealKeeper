// =============================================================================
// Regression tests for the generation-bundle security audit (js-generation#1..4,
// consolidated as SK-01 / SK-15; #5 / SK-38 lives in crypto.test.js). Each
// describe block names the finding it pins. The invariant behind all of them: the entropy figure and ANSSI badge
// shown next to a proposal never overstate what the generator really drew, and
// an admin policy never silently degrades to something weaker.
// =============================================================================

import { describe, expect, it } from "vitest";
import { calculateEntropy, descriptorFromPolicy, generate, LibraryNotFound } from "../src/index.js";
import { SAMPLE_DICTIONARY_FR } from "../src/data/sample-dictionary.js";

const L10 = Math.log2(10);
const round1 = (n) => Math.round(n * 10) / 10;

describe("js-generation#1 — no silent fallback to the bundled sample", () => {
  it("rejects an admin G2 policy with only numberOfWords", async () => {
    await expect(generate({ generator: "G2", parameters: { numberOfWords: 6 } })).rejects.toThrow(
      LibraryNotFound,
    );
  });

  it("rejects a library given as an id string", async () => {
    await expect(
      generate({ generator: "G2", parameters: { library: "fr-courant-v1", numberOfWords: 6 } }),
    ).rejects.toThrow(LibraryNotFound);
  });

  it("rejects an admin G1 policy without a library", async () => {
    await expect(generate({ generator: "G1" })).rejects.toThrow(LibraryNotFound);
  });

  it("calculateEntropy refuses to guess a library size (admin preview path)", () => {
    expect(() => calculateEntropy({ generator: "G2", parameters: { numberOfWords: 6 } })).toThrow(
      LibraryNotFound,
    );
    expect(() => calculateEntropy({ generator: "G1", parameters: { corpusSize: 5000 } })).toThrow(
      LibraryNotFound,
    );
  });

  it("the zero-config default is badged from the sample's real size", async () => {
    const descriptor = descriptorFromPolicy({ version: 1, generators: ["G1", "G2", "G3"] });
    expect(descriptor.builtinDefault).toBe(true);
    const proposals = await generate(descriptor);
    // 6 × log2(256) + log2(10 separators) + 4 × log2(10) = 64.6 bits → B1.
    const real = round1(6 * 8 + L10 + 4 * L10);
    for (const p of proposals) {
      expect(p.entropyBits).toBe(real);
      expect(p.anssiLevel).toBe("B1");
      for (const w of p.password.split(/[-_./+:|;,~]/u).slice(0, 6)) {
        expect(SAMPLE_DICTIONARY_FR).toContain(w);
      }
    }
  });

  it("an admin policy cannot opt into the sample through descriptorFromPolicy", async () => {
    const d = descriptorFromPolicy({ generator: "G2", builtinDefault: true, parameters: {} });
    expect(d.builtinDefault).toBeUndefined();
    await expect(generate(d)).rejects.toThrow(LibraryNotFound);
  });

  it("entropy follows the inline library actually used", () => {
    const r = calculateEntropy({
      generator: "G2",
      parameters: {
        library: ["alpha", "beta", "gamma", "delta"],
        numberOfWords: 3,
        separatorOptions: ["-"],
        numericGroups: [{ digitsCount: 2 }],
      },
    });
    expect(r.expectedBits).toBe(round1(3 * 2 + 2 * L10));
  });
});

describe("js-generation#4 — duplicate library entries do not inflate entropy", () => {
  it("a 7776-entry library of one repeated word is worth 0 word bits", () => {
    const r = calculateEntropy({
      generator: "G2",
      parameters: { library: Array(7776).fill("password"), numberOfWords: 6 },
    });
    expect(r.breakdown.find((b) => b.component === "word-selection")).toBeUndefined();
    expect(r.expectedBits).toBe(round1(L10 + 4 * L10));
  });

  it("draws uniformly over unique entries so log2(unique) is exact", async () => {
    let b = 0;
    const N = 4000;
    const proposals = await generate({
      generator: "G2",
      proposalCount: N,
      parameters: {
        library: ["a", "a", "a", "b"],
        numberOfWords: 1,
        separatorOptions: ["-"],
        numericGroups: [{ digitsCount: 1 }],
      },
    });
    for (const x of proposals) if (x.password.split("-")[0] === "b") b++;
    expect(b / N).toBeGreaterThan(0.44);
    expect(b / N).toBeLessThan(0.56);
  });
});
