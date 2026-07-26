import { describe, expect, it } from "vitest";
import rule from "../../src/rules/nosql-injection.js";
import { runRule } from "./test-utils.js";

describe("nosql-injection rule", () => {
  it("flags raw request objects passed to query methods and $where injection", () => {
    const findings = runRule(rule, "nosql-injection.vuln.js");
    expect(findings.length).toBeGreaterThanOrEqual(2);
    expect(findings.some((f) => f.severity === "critical")).toBe(true);
  });

  it("does not flag explicitly picked fields", () => {
    const findings = runRule(rule, "nosql-injection.safe.js");
    expect(findings).toHaveLength(0);
  });
});
