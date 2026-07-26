import { describe, expect, it } from "vitest";
import rule from "../../src/rules/api-vulnerabilities.js";
import { runRule } from "./test-utils.js";

describe("api-vulnerabilities rule", () => {
  it("flags mass assignment and server-side parameter pollution", () => {
    const findings = runRule(rule, "api-vulnerabilities.vuln.js");
    expect(findings.length).toBeGreaterThanOrEqual(2);
    expect(findings.some((f) => f.severity === "high")).toBe(true);
  });

  it("does not flag explicitly picked fields and an encoded, allowlisted URL param", () => {
    const findings = runRule(rule, "api-vulnerabilities.safe.js");
    expect(findings).toHaveLength(0);
  });
});
