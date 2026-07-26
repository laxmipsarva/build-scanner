import { describe, expect, it } from "vitest";
import rule from "../../src/rules/csp.js";
import { runRule } from "./test-utils.js";

describe("csp rule", () => {
  it("flags unsafe-inline, wildcard sources, and disabled CSP", () => {
    const findings = runRule(rule, "csp.vuln.js");
    expect(findings.length).toBeGreaterThanOrEqual(3);
  });

  it("does not flag a nonce-based CSP", () => {
    const findings = runRule(rule, "csp.safe.js");
    expect(findings).toHaveLength(0);
  });

  it("flags unsafe-inline and a wildcard source in a Vite/CRA index.html <meta> CSP tag", () => {
    const findings = runRule(rule, "csp.vuln.html");
    expect(findings.length).toBeGreaterThanOrEqual(2);
  });

  it("does not flag a strict <meta> CSP tag, regardless of attribute order", () => {
    const findings = runRule(rule, "csp.safe.html");
    expect(findings).toHaveLength(0);
  });

  it("flags unsafe-inline in a next.config.js headers() key/value CSP entry", () => {
    const findings = runRule(rule, "csp-nextjs-config.vuln.js");
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("does not flag a strict next.config.js headers() CSP entry", () => {
    const findings = runRule(rule, "csp-nextjs-config.safe.js");
    expect(findings).toHaveLength(0);
  });

  it("flags unsafe-inline/unsafe-eval in a middleware.ts CSP built into a variable", () => {
    const findings = runRule(rule, "csp-nextjs-middleware.vuln.ts");
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("does not flag a strict nonce-based middleware.ts CSP variable", () => {
    const findings = runRule(rule, "csp-nextjs-middleware.safe.ts");
    expect(findings).toHaveLength(0);
  });
});
