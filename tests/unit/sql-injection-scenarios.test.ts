import { describe, expect, it } from "vitest";
import rule from "../../src/rules/sql-injection.js";
import { runRule } from "./test-utils.js";

// Each fixture models the vulnerable source code behind one of the classic SQL injection
// attack scenarios (PortSwigger Web Security Academy naming). build-scanner is a static
// scanner, so it detects the root-cause sink in the app's own source rather than
// simulating the attack itself — several scenarios below share the exact same sink
// because the exploitation technique (blind/time-based/OOB/UNION/etc.) is determined by
// the attacker's payload against a live target, not by the shape of the vulnerable code.
const scenarios = [
  "01-where-clause-hidden-data.js",
  "02-login-bypass.js",
  "03-oracle-version-query.js",
  "04-mysql-mssql-version-query.js",
  "05-list-contents-non-oracle.js",
  "06-list-contents-oracle.js",
  "07-union-column-count.js",
  "08-union-find-text-column.js",
  "09-union-retrieve-other-tables.js",
  "10-union-multiple-values-single-column.js",
  "11-blind-conditional-responses.js",
  "12-blind-conditional-errors.js",
  "13-visible-error-based.js",
  "14-blind-time-delays.js",
  "15-blind-time-delays-info-retrieval.js",
  "16-blind-oob-interaction.js",
  "17-blind-oob-data-exfiltration.js",
  "18-filter-bypass-xml-encoding.js",
];

describe("sql-injection rule — attack scenario coverage", () => {
  it.each(scenarios)("flags the vulnerable sink in %s", (fixture) => {
    const findings = runRule(rule, `sql-scenarios/${fixture}`);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.ruleId === "sql-injection")).toBe(true);
  });

  it("flags a denylist quote-strip filter as a bypassable defense", () => {
    const findings = runRule(rule, "sql-scenarios/18-filter-bypass-xml-encoding.js");
    expect(findings.some((f) => /denylist filter/.test(f.message))).toBe(true);
  });

  it("flags a denylist keyword-test filter as a bypassable defense", () => {
    const findings = runRule(rule, "sql-scenarios/18-filter-bypass-xml-encoding.js");
    expect(findings.some((f) => /denylist of SQL keywords/.test(f.message))).toBe(true);
  });

  it("flags a raw DB error sent to the client (visible error-based SQLi)", () => {
    const findings = runRule(rule, "sql-scenarios/13-visible-error-based.js");
    expect(findings.some((f) => /leaks schema\/query details/.test(f.message))).toBe(true);
  });

  it("does not flag the truly blind conditional-errors scenario as leaking an error", () => {
    const findings = runRule(rule, "sql-scenarios/12-blind-conditional-errors.js");
    expect(findings.some((f) => /leaks schema\/query details/.test(f.message))).toBe(false);
  });
});
