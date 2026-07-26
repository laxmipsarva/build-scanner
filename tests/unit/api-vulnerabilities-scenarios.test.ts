import { describe, expect, it } from "vitest";
import rule from "../../src/rules/api-vulnerabilities.js";
import { runRule } from "./test-utils.js";

// Each fixture models the vulnerable source code behind one of the PortSwigger Web Security
// Academy "API testing" lab scenarios.
const scenarios = [
  "01-exploiting-endpoint-via-documentation.js",
  "02-sspp-query-string.js",
  "03-unused-endpoint.js",
  "04-mass-assignment.js",
  "05-sspp-rest-url.js",
];

describe("api-vulnerabilities rule — attack scenario coverage", () => {
  it.each(scenarios)("flags the vulnerable sink in %s", (fixture) => {
    const findings = runRule(rule, `api-scenarios/${fixture}`);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.ruleId === "api-vulnerabilities")).toBe(true);
  });

  it("flags exposed Swagger UI docs", () => {
    const findings = runRule(rule, "api-scenarios/01-exploiting-endpoint-via-documentation.js");
    expect(findings.some((f) => /API documentation/.test(f.message))).toBe(true);
  });

  it("flags a raw query param spliced into an outbound backend URL", () => {
    const findings = runRule(rule, "api-scenarios/02-sspp-query-string.js");
    expect(findings.some((f) => /parameter pollution/.test(f.message))).toBe(true);
  });

  it("flags a deprecated route left mounted", () => {
    const findings = runRule(rule, "api-scenarios/03-unused-endpoint.js");
    expect(findings.some((f) => /deprecated\/legacy\/unused/.test(f.message))).toBe(true);
  });

  it("flags the raw request body passed into an update call", () => {
    const findings = runRule(rule, "api-scenarios/04-mass-assignment.js");
    expect(findings.some((f) => f.severity === "high" && /mass assignment/.test(f.message))).toBe(true);
  });

  it("flags a raw path param spliced into an outbound backend URL", () => {
    const findings = runRule(rule, "api-scenarios/05-sspp-rest-url.js");
    expect(findings.some((f) => /parameter pollution/.test(f.message))).toBe(true);
  });
});
