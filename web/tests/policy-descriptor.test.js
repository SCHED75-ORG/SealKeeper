import { describe, expect, it } from "vitest";
import Generation, {
  descriptorFromPolicy,
  generate,
  InvalidPolicyDescriptor,
} from "../src/index.js";

// Shape returned by POST /api/v1/policy {token} when an admin policy
// resolves (internal/httpserver/server.go resolvedPolicy).
const adminPolicy = {
  id: 7,
  domain: "example.test",
  anssiLevel: "B3",
  generator: "G3",
  proposalCount: 2,
  regenerateLimit: 1,
  parameters: { length: 32, blockSize: 8, blockSeparator: "." },
};

describe("descriptorFromPolicy", () => {
  it("is exposed on the namespace", () => {
    expect(Generation.descriptorFromPolicy).toBe(descriptorFromPolicy);
  });

  it("passes a resolved admin policy through", () => {
    expect(descriptorFromPolicy(adminPolicy)).toEqual({
      generator: "G3",
      proposalCount: 2,
      regenerateLimit: 1,
      parameters: { length: 32, blockSize: 8, blockSeparator: "." },
    });
  });

  // Regression: the reveal page used to discard generator / count /
  // parameters and always produce 5 default G2 proposals.
  it("yields proposals that follow the admin policy", async () => {
    const proposals = await generate(descriptorFromPolicy(adminPolicy));
    expect(proposals).toHaveLength(2);
    for (const p of proposals) {
      expect(p.generator).toBe("G3");
      expect(p.password).toMatch(/^[A-Za-z0-9]{8}(\.[A-Za-z0-9]{8}){3}$/);
    }
  });

  it("forwards an inline library to G2", async () => {
    const library = ["alpha", "beta", "gamma", "delta"];
    const [p] = await generate(
      descriptorFromPolicy({
        generator: "G2",
        proposalCount: 1,
        parameters: {
          library,
          numberOfWords: 3,
          separatorOptions: ["-"],
          numericGroups: [{ digitsCount: 2, position: "suffix" }],
        },
      }),
    );
    for (const word of p.password.split("-").filter((w) => /^[a-z]+$/i.test(w))) {
      expect(library.map((w) => w.toLowerCase())).toContain(word.toLowerCase());
    }
  });

  it("defaults count and parameters when the policy omits them", () => {
    expect(descriptorFromPolicy({ generator: "G1" })).toEqual({
      generator: "G1",
      proposalCount: 5,
      regenerateLimit: undefined,
      parameters: {},
    });
  });

  it("maps the built-in default descriptor to G2 over the sample, flagged", () => {
    expect(descriptorFromPolicy({ version: 1, generators: ["G1", "G2", "G3"] })).toEqual({
      generator: "G2",
      proposalCount: 5,
      parameters: {},
      builtinDefault: true,
    });
  });

  it("does not mask an unknown generator with a default", async () => {
    await expect(generate(descriptorFromPolicy({ generator: "GZ" }))).rejects.toThrow(
      InvalidPolicyDescriptor,
    );
  });

  it("rejects a non-object", () => {
    expect(() => descriptorFromPolicy(null)).toThrow(InvalidPolicyDescriptor);
  });
});
