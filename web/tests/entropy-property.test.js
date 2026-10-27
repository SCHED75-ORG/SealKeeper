// =============================================================================
// Property test: credited entropy never exceeds the generator's real output
// distribution (audit js-generation#2/#4).
// =============================================================================
// Crediting b bits claims that no password is more likely than 2^-b. For small
// configurations we draw many passwords and check that the most frequent one
// stays within sampling noise of that bound. A configuration whose credit
// counts a parameter the generator ignores (or a transform another one
// erases) fails here because its most frequent output is far too common.
// =============================================================================

import { describe, expect, it } from "vitest";
import { calculateEntropy } from "../src/entropy.js";
import { generateG1 } from "../src/generators/g1.js";
import { generateG2 } from "../src/generators/g2.js";
import { generateG3 } from "../src/generators/g3.js";

const N = 12000;

async function maxFrequency(draw) {
  const counts = new Map();
  for (let i = 0; i < N; i++) {
    const p = await draw();
    counts.set(p, (counts.get(p) ?? 0) + 1);
  }
  return Math.max(...counts.values());
}

function expectWithinBound(observed, bits) {
  // Expected count of the likeliest output if the credit were tight, plus a
  // generous 6-sigma allowance for sampling noise.
  const bound = N * 2 ** -bits;
  expect(observed).toBeLessThanOrEqual(bound + 6 * Math.sqrt(bound) + 2);
}

const t = (code, parameters) => ({ code, active: true, mode: "random", parameters });

const cases = [
  [
    "G2 small dictionary, two separators",
    {
      generator: "G2",
      parameters: {
        library: ["a", "b", "c", "d", "d"],
        numberOfWords: 2,
        separatorOptions: ["-", "_"],
        numericGroups: [{ digitsCount: 1 }, { digitsCount: 6 }],
      },
    },
  ],
  [
    "G2 transforms are not credited",
    {
      generator: "G2",
      parameters: {
        library: ["a", "b"],
        numberOfWords: 3,
        separatorOptions: ["-"],
        numericGroups: [],
        transforms: [t("T09", { length: 8 }), t("T08")],
      },
    },
  ],
  [
    "G3 one char, ambiguous excluded",
    { generator: "G3", parameters: { length: 1, blockSize: 0, excludeAmbiguous: true } },
  ],
  [
    "G1 reversal + symbols + alternating case",
    {
      generator: "G1",
      parameters: {
        library: ["Le chat dort", "Un ours brun"],
        separatorOptions: ["-"],
        numericGroups: [],
        transforms: [t("T04"), t("T08", { symbols: ["!", "?"] }), t("T07")],
      },
    },
  ],
  [
    "G1 case + leet + accents",
    {
      generator: "G1",
      parameters: {
        library: ["Été brûlant", "Café crème"],
        separatorOptions: ["-"],
        numericGroups: [],
        transforms: [
          t("T01", { candidates: ["lowercase", "uppercase", "PascalCase"] }),
          t("T02", { probability: 0.5 }),
          t("T06"),
        ],
      },
    },
  ],
  [
    "G1 truncation erases a later-dropped symbol and hash",
    {
      generator: "G1",
      parameters: {
        library: ["Le chat dort", "La nuit tombe"],
        separatorOptions: ["-"],
        numericGroups: [{ position: "suffix", digitsCount: 1 }],
        transforms: [t("T08"), t("T09", { length: 2 }), t("T05", { firstN: 2 })],
      },
    },
  ],
  [
    "G2 words made of the separator",
    {
      generator: "G2",
      parameters: {
        library: ["-", "--", "---"],
        numberOfWords: 3,
        separatorOptions: ["-"],
        numericGroups: [],
      },
    },
  ],
  [
    "G1 citations differing by a space versus the separator",
    {
      generator: "G1",
      parameters: { library: ["w w", "w-w"], separatorOptions: ["-"], numericGroups: [] },
    },
  ],
  [
    "G1 case erased by a later alternating case",
    {
      generator: "G1",
      parameters: {
        library: ["Le chat dort", "Un ours brun"],
        separatorOptions: ["-"],
        numericGroups: [],
        transforms: [t("T01"), t("T07")],
      },
    },
  ],
];

describe("credited entropy is a lower bound on the real draw", () => {
  for (const [name, policy] of cases) {
    it(name, async () => {
      const { expectedBits } = calculateEntropy(policy);
      const lib = policy.parameters.library;
      const draw =
        policy.generator === "G1"
          ? () => generateG1(policy, lib)
          : policy.generator === "G2"
            ? () => generateG2(policy, lib)
            : () => generateG3(policy);
      expectWithinBound(await maxFrequency(draw), expectedBits);
    });
  }
});
