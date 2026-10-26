// The Go side (internal/policies ValidateForReveal) refuses a policy at save
// time and before burning the reveal token exactly when generate() would
// throw. Both suites run the same fixture, so a rule added here without its
// Go mirror (or the reverse) fails CI.
import { readFileSync } from "node:fs";
import { URL } from "node:url";
import { describe, expect, it } from "vitest";
import { descriptorFromPolicy, generate } from "../src/index.js";

const cases = JSON.parse(
  readFileSync(
    new URL("../../internal/policies/testdata/reveal_parity.json", import.meta.url),
    "utf8",
  ),
);

describe("reveal parity with internal/policies", () => {
  it.each(cases.map((c) => [c.name, c]))("%s", async (_name, c) => {
    const run = generate(descriptorFromPolicy(c.policy));
    if (c.ok) {
      await expect(run).resolves.toHaveLength(c.policy.proposalCount);
    } else {
      await expect(run).rejects.toThrow();
    }
  });
});
