import { describe, expect, it } from "vitest";
import rule from "../../src/rules/sql-injection.js";
import { runRule } from "./test-utils.js";

describe("sql-injection rule", () => {
  it("flags template-literal and concatenated SQL queries", () => {
    const findings = runRule(rule, "sql-injection.vuln.js");
    expect(findings.length).toBeGreaterThanOrEqual(2);
    expect(findings.every((f) => f.ruleId === "sql-injection")).toBe(true);
  });

  it("does not flag parameterized queries", () => {
    const findings = runRule(rule, "sql-injection.safe.js");
    expect(findings).toHaveLength(0);
  });
});
