import { describe, expect, it } from "vitest";
import Generation, {
  calculateEntropy,
  generate,
  regenerate,
  InvalidPolicyDescriptor,
  LibraryNotFound,
  RegenerationLimitExceeded,
} from "../src/index.js";

describe("namespace", () => {
  it("default export exposes generate / regenerate / calculateEntropy", () => {
    expect(typeof Generation.generate).toBe("function");
    expect(typeof Generation.regenerate).toBe("function");
    expect(typeof Generation.calculateEntropy).toBe("function");
    expect(generate).toBe(Generation.generate);
    expect(regenerate).toBe(Generation.regenerate);
    expect(calculateEntropy).toBe(Generation.calculateEntropy);
  });

  it("generate returns the expected proposal shape", async () => {
    const proposals = await generate({
      generator: "G3",
      proposalCount: 3,
    });
    expect(proposals).toHaveLength(3);
    for (const p of proposals) {
      expect(typeof p.password).toBe("string");
      expect(p.generator).toBe("G3");
      expect(p.anssiLevel).toBe("B3");
      expect(p.entropyBits).toBeGreaterThanOrEqual(100);
    }
  });

  it("generate rejects invalid policies", async () => {
    await expect(generate(null)).rejects.toThrow(InvalidPolicyDescriptor);
    await expect(generate({})).rejects.toThrow(InvalidPolicyDescriptor);
    await expect(generate({ generator: "GZ" })).rejects.toThrow(InvalidPolicyDescriptor);
  });

  it("regenerate enforces the per-policy limit", async () => {
    const policy = { generator: "G3", proposalCount: 1, regenerateLimit: 2 };
    await regenerate(policy);
    await regenerate(policy);
    await expect(regenerate(policy)).rejects.toThrow(RegenerationLimitExceeded);
  });

  it("refuses G1/G2 without a library instead of using the sample", async () => {
    await expect(generate({ generator: "G2", proposalCount: 1 })).rejects.toThrow(LibraryNotFound);
    await expect(generate({ generator: "G1", proposalCount: 1 })).rejects.toThrow(LibraryNotFound);
  });

  it("uses the sample only for the flagged built-in default", async () => {
    const proposals = await generate({ generator: "G2", proposalCount: 1, builtinDefault: true });
    expect(proposals).toHaveLength(1);
    expect(proposals[0].generator).toBe("G2");
    expect(proposals[0].entropyBits).toBeGreaterThan(0);
    const [g1] = await generate({ generator: "G1", proposalCount: 1, builtinDefault: true });
    expect(g1.password.length).toBeGreaterThan(0);
  });

  it("uses the policy-provided library when available", async () => {
    const lib = ["alpha", "beta", "gamma", "delta", "epsilon"];
    const proposals = await generate({
      generator: "G2",
      proposalCount: 2,
      parameters: { library: lib, numberOfWords: 3, separatorOptions: ["-"] },
    });
    for (const p of proposals) {
      for (const part of p.password.split("-").slice(0, 3)) {
        expect(lib).toContain(part);
      }
    }
  });
});
