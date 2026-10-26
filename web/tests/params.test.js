import { describe, expect, it } from "vitest";
import { normalizeG1, normalizeG2, normalizeG3, normalizeTopLevel } from "../src/params.js";
import { resolveLibrary, uniqueLibrary } from "../src/library.js";
import { InvalidPolicyDescriptor, LibraryNotFound } from "../src/errors.js";

const lib = ["un", "deux", "trois"];
const g1 = (parameters) => normalizeG1({ generator: "G1", parameters }, lib);
const g2 = (parameters) => normalizeG2({ generator: "G2", parameters }, lib);
const g3 = (parameters) => normalizeG3({ generator: "G3", parameters });
const tr = (code, extra = {}) => ({ code, active: true, mode: "random", ...extra });

describe("normalizeTopLevel", () => {
  it("fills defaults and accepts bounds", () => {
    expect(normalizeTopLevel({})).toEqual({ proposalCount: 5, regenerateLimit: 3 });
    expect(normalizeTopLevel({ proposalCount: 50, regenerateLimit: 0 })).toEqual({
      proposalCount: 50,
      regenerateLimit: 0,
    });
  });

  it("rejects out-of-range or non-integer counts", () => {
    for (const bad of [{ proposalCount: 51 }, { proposalCount: "5" }, { regenerateLimit: -1 }]) {
      expect(() => normalizeTopLevel(bad)).toThrow(InvalidPolicyDescriptor);
    }
  });
});

describe("library resolution", () => {
  it("deduplicates in first-seen order", () => {
    expect(uniqueLibrary(["b", "a", "b"], "G2")).toEqual(["b", "a"]);
  });

  it("rejects missing, empty and malformed libraries", () => {
    expect(() => uniqueLibrary(undefined, "G2")).toThrow(LibraryNotFound);
    expect(() => uniqueLibrary("fr-courant-v1", "G2")).toThrow(/id "fr-courant-v1"/);
    expect(() => uniqueLibrary([], "G1")).toThrow(LibraryNotFound);
    expect(() => uniqueLibrary([""], "G1")).toThrow(InvalidPolicyDescriptor);
  });

  it("prefers an inline library over the built-in sample", () => {
    const policy = { generator: "G2", builtinDefault: true, parameters: { library: ["x"] } };
    expect(resolveLibrary(policy)).toEqual(["x"]);
    expect(resolveLibrary({ generator: "G3" })).toBeNull();
  });
});

describe("normalizeG1", () => {
  it("fills defaults", () => {
    const p = g1(undefined);
    expect(p.citations).toEqual(lib);
    expect(p.separators).toHaveLength(10);
    expect(p.groups.map((g) => g.digitsCount)).toEqual([3, 3, 3]);
    expect(p.transforms).toEqual([]);
  });

  it("normalises transform parameters and skips inactive ones", () => {
    const p = g1({
      transforms: [
        tr("T01", { parameters: { candidates: ["uppercase", "uppercase"] } }),
        { code: "T02", active: false },
        tr("T05"),
        tr("T08", { parameters: { symbols: ["!", "!", "?"] } }),
        tr("T09"),
        tr("T06", { mode: "deterministic" }),
      ],
    });
    expect(p.transforms.map((t) => t.code)).toEqual(["T01", "T05", "T08", "T09", "T06"]);
    expect(p.transforms[0].parameters.candidates).toEqual(["uppercase"]);
    expect(p.transforms[1].parameters.firstN).toBe(3);
    expect(p.transforms[2].parameters.symbols).toEqual(["!", "?"]);
    expect(p.transforms[3].parameters.length).toBe(4);
  });

  it("checks a declared corpusSize against the distinct entries", () => {
    expect(g1({ corpusSize: 3 }).citations).toHaveLength(3);
    expect(() => g1({ corpusSize: 5000 })).toThrow(/corpusSize 5000/);
  });

  const bad = [
    ["parameters as array", []],
    ["numericGroups not an array", { numericGroups: {} }],
    ["numericGroups entry not an object", { numericGroups: [3] }],
    ["unknown position", { numericGroups: [{ position: "start" }] }],
    ["non-string group separator", { numericGroups: [{ separator: 1 }] }],
    ["negative digitsCount", { numericGroups: [{ digitsCount: -1 }] }],
    ["transforms not an array", { transforms: "T01" }],
    ["transform not an object", { transforms: [null] }],
    ["unknown transform", { transforms: [tr("T10")] }],
    ["duplicate transform", { transforms: [tr("T04"), tr("T04")] }],
    ["unknown mode", { transforms: [tr("T04", { mode: "sometimes" })] }],
    ["unknown case mode", { transforms: [tr("T01", { parameters: { candidates: ["kebab"] } })] }],
    ["leet probability 1", { transforms: [tr("T02", { parameters: { probability: 1 } })] }],
    [
      "leet probability string",
      { transforms: [tr("T03", { parameters: { probability: "0.5" } })] },
    ],
    ["T05 firstN 0", { transforms: [tr("T05", { parameters: { firstN: 0 } })] }],
    ["T08 empty symbols", { transforms: [tr("T08", { parameters: { symbols: [] } })] }],
    ["T08 empty symbol", { transforms: [tr("T08", { parameters: { symbols: [""] } })] }],
    ["T09 length 0", { transforms: [tr("T09", { parameters: { length: 0 } })] }],
  ];
  for (const [name, parameters] of bad) {
    it(`rejects ${name}`, () => {
      expect(() => g1(parameters)).toThrow(InvalidPolicyDescriptor);
    });
  }
});

describe("normalizeG2", () => {
  it("uses the first numeric group only", () => {
    const p = g2({ numericGroups: [{ digitsCount: 2, separator: "" }, { digitsCount: 8 }] });
    expect(p.digits).toEqual({ digitsCount: 2, attached: true });
    expect(g2({ numericGroups: [] }).digits).toBeNull();
    expect(g2({ numericGroups: [{}] }).digits).toEqual({ digitsCount: 4, attached: false });
  });

  it("validates transforms it does not apply", () => {
    expect(() => g2({ transforms: [tr("T99")] })).toThrow(InvalidPolicyDescriptor);
  });

  it("checks a declared dictionarySize", () => {
    expect(() => g2({ dictionarySize: 7776 })).toThrow(/dictionarySize 7776/);
  });
});

describe("normalizeG3", () => {
  it("fills defaults", () => {
    expect(g3(undefined)).toMatchObject({ length: 20, blockSize: 5, blockSeparator: "-" });
    expect(g3({}).alphabet).toHaveLength(62);
    expect(g3({ excludeAmbiguous: true, alphabetSize: 57 }).alphabet).toHaveLength(57);
  });

  it("rejects malformed values", () => {
    expect(() => g3({ blockSeparator: 1 })).toThrow(InvalidPolicyDescriptor);
    expect(() => g3({ blockSize: -1 })).toThrow(InvalidPolicyDescriptor);
    expect(() => g3({ length: 257 })).toThrow(InvalidPolicyDescriptor);
    expect(() => g3({ alphabetSize: 57 })).toThrow(/alphabetSize 57/);
  });
});
