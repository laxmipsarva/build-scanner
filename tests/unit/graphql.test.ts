import { describe, expect, it } from "vitest";
import rule from "../../src/rules/graphql.js";
import { runRule } from "./test-utils.js";

describe("graphql rule", () => {
  it("flags enabled introspection, missing depth limiting, and resolver arg injection", () => {
    const findings = runRule(rule, "graphql.vuln.js");
    expect(findings.length).toBeGreaterThanOrEqual(3);
    expect(findings.some((f) => f.severity === "critical")).toBe(true);
  });

  it("does not flag a server with introspection gated and depth limiting configured", () => {
    const findings = runRule(rule, "graphql.safe.js");
    expect(findings).toHaveLength(0);
  });
});
