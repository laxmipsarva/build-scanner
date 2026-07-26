import { describe, expect, it } from "vitest";
import rule from "../../src/rules/csrf.js";
import { runRule } from "./test-utils.js";

describe("csrf rule", () => {
  it("flags unprotected state-changing routes and SameSite=None cookies", () => {
    const findings = runRule(rule, "csrf.vuln.js");
    expect(findings.length).toBeGreaterThanOrEqual(2);
  });

  it("does not flag routes protected by CSRF middleware", () => {
    const findings = runRule(rule, "csrf.safe.js");
    expect(findings).toHaveLength(0);
  });

  it("flags an unprotected Next.js App Router route handler", () => {
    const findings = runRule(rule, "csrf-nextjs/app-vuln/route.ts");
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("does not flag an App Router route handler that references CSRF protection", () => {
    const findings = runRule(rule, "csrf-nextjs/app-safe/route.ts");
    expect(findings).toHaveLength(0);
  });

  it("does not flag a Next.js Server Action (use server) even without an explicit CSRF mention", () => {
    const findings = runRule(rule, "csrf-nextjs/app-server-action-safe/route.ts");
    expect(findings).toHaveLength(0);
  });

  it("flags an unprotected Next.js Pages API route method branch", () => {
    const findings = runRule(rule, "csrf-nextjs/pages-api-vuln/pages/api/transfer.ts");
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("does not flag a Pages API route that references CSRF protection", () => {
    const findings = runRule(rule, "csrf-nextjs/pages-api-safe/pages/api/transfer.ts");
    expect(findings).toHaveLength(0);
  });
});
