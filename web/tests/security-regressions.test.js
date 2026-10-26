// =============================================================================
// Regression tests for the generation-bundle security audit (js-generation#1..4,
// consolidated as SK-01 / SK-15; #5 / SK-38 lives in crypto.test.js). Each
// describe block names the finding it pins. The invariant behind all of them: the entropy figure and ANSSI badge
// shown next to a proposal never overstate what the generator really drew, and
// an admin policy never silently degrades to something weaker.
// =============================================================================

import { describe, expect, it } from "vitest";
import {
  calculateEntropy,
  descriptorFromPolicy,
  generate,
  InvalidPolicyDescriptor,
  LibraryNotFound,
} from "../src/index.js";
import { generateG2 } from "../src/generators/g2.js";
import { SAMPLE_DICTIONARY_FR } from "../src/data/sample-dictionary.js";

const L10 = Math.log2(10);
// Reports round DOWN to 0.1 bit so a badge never crosses a threshold upward.
const round1 = (n) => Math.floor(n * 10 + 1e-9) / 10;
const words = (n) => Array.from({ length: n }, (_, i) => `w${i}`);

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

  it("draws uniformly over unique entries so log2(unique) is exact", () => {
    const policy = {
      generator: "G2",
      parameters: { numberOfWords: 1, separatorOptions: ["-"], numericGroups: [] },
    };
    let b = 0;
    const N = 4000;
    for (let i = 0; i < N; i++) if (generateG2(policy, ["a", "a", "a", "b"]) === "b") b++;
    expect(b / N).toBeGreaterThan(0.44);
    expect(b / N).toBeLessThan(0.56);
  });
});

describe("js-generation#2 — no credit for parameters the generator ignores", () => {
  const lib = words(7776);

  it("G2 credits exactly the digits it emits", async () => {
    const policy = {
      generator: "G2",
      proposalCount: 20,
      parameters: {
        library: lib,
        numberOfWords: 4,
        separatorOptions: [","],
        numericGroups: [{ digitsCount: 2 }, { digitsCount: 8 }, { digitsCount: 8 }],
      },
    };
    const r = calculateEntropy(policy);
    const emitted = (await generate(policy)).map((p) => p.password.split(",").pop());
    const digits = emitted[0].length;
    for (const d of emitted) expect(d).toMatch(/^\d+$/);
    expect(r.expectedBits).toBe(round1(4 * Math.log2(7776) + digits * L10));
    expect(r.anssiLevels.B3).toBe(false);
  });

  it("G2 does not credit transforms it never applies", () => {
    const base = { library: lib, numberOfWords: 4 };
    const plain = calculateEntropy({ generator: "G2", parameters: base });
    const withT = calculateEntropy({
      generator: "G2",
      parameters: {
        ...base,
        transforms: ["T09", "T03", "T01"].map((code) => ({ code, active: true, mode: "random" })),
      },
    });
    expect(withT.expectedBits).toBe(plain.expectedBits);
  });

  it("G3 rejects an alphabetSize the generator does not draw from", async () => {
    const policy = { generator: "G3", parameters: { length: 16, alphabetSize: 94 } };
    expect(() => calculateEntropy(policy)).toThrow(InvalidPolicyDescriptor);
    await expect(generate(policy)).rejects.toThrow(InvalidPolicyDescriptor);
    // Declaring the real size stays accepted.
    expect(
      calculateEntropy({ generator: "G3", parameters: { length: 16, alphabetSize: 62 } })
        .expectedBits,
    ).toBe(round1(16 * Math.log2(62)));
  });

  it("G3 excludeAmbiguous is computed over the 57-character alphabet", () => {
    const r = calculateEntropy({
      generator: "G3",
      parameters: { length: 17, excludeAmbiguous: true },
    });
    expect(r.expectedBits).toBe(round1(17 * Math.log2(57)));
    expect(r.anssiLevels.B3).toBe(false);
  });
});

describe("js-generation#3 — nonsensical parameters are rejected, not defaulted", () => {
  const lib = words(16);
  const bad = [
    ["G3 length 0", { generator: "G3", parameters: { length: 0 } }],
    ["G3 length '4'", { generator: "G3", parameters: { length: "4" } }],
    ["G3 length -3", { generator: "G3", parameters: { length: -3 } }],
    ["G3 excludeAmbiguous 'false'", { generator: "G3", parameters: { excludeAmbiguous: "false" } }],
    ["G2 numberOfWords 0", { generator: "G2", parameters: { library: lib, numberOfWords: 0 } }],
    ["G2 numberOfWords '1'", { generator: "G2", parameters: { library: lib, numberOfWords: "1" } }],
    ["G2 numberOfWords 2.5", { generator: "G2", parameters: { library: lib, numberOfWords: 2.5 } }],
    [
      "G2 digitsCount '4'",
      { generator: "G2", parameters: { library: lib, numericGroups: [{ digitsCount: "4" }] } },
    ],
    [
      "G2 empty separators",
      { generator: "G2", parameters: { library: lib, separatorOptions: [] } },
    ],
    ["G2 non-string entry", { generator: "G2", parameters: { library: ["a", 3] } }],
    ["proposalCount 0", { generator: "G3", proposalCount: 0 }],
  ];
  for (const [name, policy] of bad) {
    it(`rejects ${name}`, async () => {
      expect(() => calculateEntropy(policy)).toThrow(InvalidPolicyDescriptor);
      await expect(generate(policy)).rejects.toThrow(InvalidPolicyDescriptor);
    });
  }
});

describe("js-generation#4 — transform credits follow their parameters and composition", () => {
  const citations = ["Je pense donc je suis", "Le coeur a ses raisons", "Rien ne sert de courir"];
  const t = (code, parameters) => ({ code, active: true, mode: "random", parameters });

  it("one fixed citation with weak transforms is not badged B1 (audit F4)", async () => {
    const policy = {
      generator: "G1",
      proposalCount: 3,
      parameters: {
        library: ["Je pense donc je suis"],
        separatorOptions: ["-"],
        numericGroups: [],
        transforms: [
          t("T08", { symbols: ["!"] }),
          t("T09", { length: 1 }),
          t("T02", { probability: 1e-6, expectedSubstitutionsHint: 60 }),
        ],
      },
    };
    const r = calculateEntropy(policy);
    expect(r.expectedBits).toBeLessThan(5);
    for (const p of await generate(policy)) expect(p.anssiLevel).toBeNull();
  });

  it("T08 credits log2 of its symbol list", () => {
    const r = calculateEntropy({
      generator: "G1",
      parameters: { library: citations, transforms: [t("T08", { symbols: ["!", "?"] })] },
    });
    expect(r.breakdown.find((b) => b.component === "transform-T08").bits).toBe(1);
  });

  it("T09 credits 4 bits per hex char, capped by its 32-bit nonce", () => {
    const bits = (length) =>
      calculateEntropy({
        generator: "G1",
        parameters: { library: citations, transforms: [t("T09", { length })] },
      }).breakdown.find((b) => b.component === "transform-T09").bits;
    expect(bits(2)).toBe(8);
    expect(bits(20)).toBe(32);
  });

  it("T08 earns nothing once an earlier camelCase T01 may have removed the spaces", () => {
    const r = calculateEntropy({
      generator: "G1",
      parameters: {
        library: citations,
        transforms: [t("T01", { candidates: ["camelCase", "lowercase"] }), t("T08")],
      },
    });
    expect(r.breakdown.find((b) => b.component === "transform-T08")).toBeUndefined();
  });
});
