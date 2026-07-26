import { describe, expect, it } from "vitest";
import rule from "../../src/rules/cors.js";
import { runRule } from "./test-utils.js";

// Each fixture models the vulnerable source code behind one of the PortSwigger Web Security
// Academy "CORS" lab scenarios.
const scenarios = [
  "01-basic-origin-reflection.js",
  "02-trusted-null-origin.js",
  "03-trusted-insecure-protocols.js",
];

describe("cors rule — attack scenario coverage", () => {
  it.each(scenarios)("flags the vulnerable config in %s", (fixture) => {
    const findings = runRule(rule, `cors-scenarios/${fixture}`);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.ruleId === "cors-misconfiguration")).toBe(true);
  });
});
