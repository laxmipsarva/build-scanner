import { describe, expect, it } from "vitest";
import rule from "../../src/rules/nosql-injection.js";
import { runRule } from "./test-utils.js";

// Each fixture models the vulnerable source code behind one of the PortSwigger Web Security
// Academy "NoSQL injection" lab scenarios. build-scanner is a static scanner, so it detects the
// root-cause sink in the app's own source (raw request objects handed to query methods, or
// $where clauses built from dynamic strings) rather than simulating the attack itself.
const scenarios = [
  "01-detecting-nosql-injection.js",
  "02-login-bypass.js",
  "03-extract-data.js",
  "04-extract-unknown-fields.js",
];

describe("nosql-injection rule — attack scenario coverage", () => {
  it.each(scenarios)("flags the vulnerable sink in %s", (fixture) => {
    const findings = runRule(rule, `nosql-scenarios/${fixture}`);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.ruleId === "nosql-injection")).toBe(true);
  });

  it("flags raw query-string filters as operator injection (detecting NoSQL injection)", () => {
    const findings = runRule(rule, "nosql-scenarios/01-detecting-nosql-injection.js");
    expect(findings.some((f) => /operator injection/.test(f.message))).toBe(true);
  });

  it("flags credentials passed straight to findOne as an auth-bypass sink", () => {
    const findings = runRule(rule, "nosql-scenarios/02-login-bypass.js");
    expect(findings.some((f) => f.severity === "high")).toBe(true);
  });

  it("flags the concatenated $where clause used for blind data extraction", () => {
    const findings = runRule(rule, "nosql-scenarios/03-extract-data.js");
    expect(findings.some((f) => f.severity === "critical" && /\$where/.test(f.message))).toBe(true);
  });

  it("flags the spread query object used to extract unknown fields", () => {
    const findings = runRule(rule, "nosql-scenarios/04-extract-unknown-fields.js");
    expect(findings.some((f) => /operator injection/.test(f.message))).toBe(true);
  });
});
