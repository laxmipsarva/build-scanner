import { describe, expect, it } from "vitest";
import rule from "../../src/rules/graphql.js";
import { runRule } from "./test-utils.js";

// Each fixture models one of the PortSwigger Web Security Academy "GraphQL API vulnerabilities"
// lab scenarios. Some of these are authorization-logic or recon-technique bugs that a
// single-file regex scanner fundamentally can't see (missing per-resolver auth checks,
// undocumented endpoint enumeration, batching-based rate-limit bypass) — expectFlagged: false
// documents that scope boundary as a permanent regression guard rather than a silent gap.
const scenarios: { fixture: string; expectFlagged: boolean; note?: string }[] = [
  {
    fixture: "01-accessing-private-posts.js",
    expectFlagged: false,
    note: "missing per-resolver authorization check — requires business-logic reasoning, not a regex pattern",
  },
  {
    fixture: "02-exposure-of-private-fields.js",
    expectFlagged: true,
    note: "sensitive field name (password) declared in a GraphQL `type` block",
  },
  {
    fixture: "03-hidden-endpoint.js",
    expectFlagged: false,
    note: "endpoint discovery is a recon technique, not a static code pattern",
  },
  {
    fixture: "04-brute-force-bypass.js",
    expectFlagged: false,
    note: "batching-based rate-limit bypass requires cross-cutting reasoning about request vs. operation counting",
  },
  {
    fixture: "05-csrf-over-graphql.js",
    expectFlagged: true,
    note: "Apollo Server's csrfPrevention: false is a direct, well-defined misconfiguration",
  },
];

describe("graphql-vulnerabilities rule — attack scenario coverage", () => {
  it.each(scenarios)(
    "$fixture — expectFlagged=$expectFlagged",
    ({ fixture, expectFlagged }) => {
      const findings = runRule(rule, `graphql-scenarios/${fixture}`);
      expect(findings.length > 0).toBe(expectFlagged);
      if (expectFlagged) {
        expect(findings.every((f) => f.ruleId === "graphql-vulnerabilities")).toBe(true);
      }
    },
  );
});
