import { describe, expect, it } from "vitest";
import rule from "../../src/rules/cors.js";
import { runRule } from "./test-utils.js";

describe("cors rule", () => {
  it("flags reflected origin and wildcard-origin-with-credentials", () => {
    const findings = runRule(rule, "cors.vuln.js");
    expect(findings.length).toBeGreaterThanOrEqual(2);
  });

  it("does not flag an explicit origin allowlist", () => {
    const findings = runRule(rule, "cors.safe.js");
    expect(findings).toHaveLength(0);
  });

  it("flags wildcard and reflected origin set via middleware.ts headers.set(...)", () => {
    const findings = runRule(rule, "cors-nextjs-middleware.vuln.ts");
    expect(findings.length).toBeGreaterThanOrEqual(2);
  });

  it("does not flag an allowlist-checked origin set via headers.set(...)", () => {
    const findings = runRule(rule, "cors-nextjs-middleware.safe.ts");
    expect(findings).toHaveLength(0);
  });

  it("flags wildcard and reflected origin in App Router object-literal headers", () => {
    const findings = runRule(rule, "cors-nextjs-route.vuln.ts");
    expect(findings.length).toBeGreaterThanOrEqual(2);
  });

  it("does not flag an allowlist-checked origin in object-literal headers", () => {
    const findings = runRule(rule, "cors-nextjs-route.safe.ts");
    expect(findings).toHaveLength(0);
  });

  it("flags a wildcard Access-Control-Allow-Origin in next.config.js headers()", () => {
    const findings = runRule(rule, "cors-nextjs-config.vuln.js");
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("does not flag an explicit origin in next.config.js headers()", () => {
    const findings = runRule(rule, "cors-nextjs-config.safe.js");
    expect(findings).toHaveLength(0);
  });
});
