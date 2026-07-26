import { makeFinding, matchAll } from "../core/helpers.js";
import type { Finding, Rule } from "../core/types.js";

const INTROSPECTION_ENABLED = /introspection\s*:\s*true/g;

const SERVER_INIT = /new\s+ApolloServer\s*\(\s*\{/g;
const HAS_DEPTH_OR_COMPLEXITY_GUARD = /depth[-_]?limit|queryComplexity|costAnalysis|graphql-depth-limit/i;

// args.<field> / args interpolated straight into exec/eval — command injection via resolver input.
const RESOLVER_ARGS_TO_EXEC =
  /\b(?:exec|execSync|spawn|eval)\s*\([^)]*\$\{[^}]*\bargs\b[^}]*\}/g;

// Apollo Server's built-in CSRF prevention explicitly turned off — lets a plain HTML form
// (simple, non-preflighted request) trigger state-changing mutations cross-site.
const CSRF_PREVENTION_DISABLED = /\bcsrfPrevention\s*:\s*false\b/g;

// A sensitive field (password, secret, api key, ...) declared inside a GraphQL SDL `type`
// block (not an `input` block, where receiving a password is normal) — exposed to any client
// that queries for it.
const SENSITIVE_FIELD_IN_TYPE =
  /\btype\s+\w+(?:\s+implements\s+\w+)?\s*\{[^}]*\b(password|passwordHash|apiKey|privateKey|creditCardNumber|ssn)\s*:\s*(?:String|Int|Float|Boolean|ID)!?[^}]*\}/gis;

const rule: Rule = {
  id: "graphql-vulnerabilities",
  category: "GraphQL",
  description:
    "Flags GraphQL introspection left enabled, Apollo servers with no query depth/complexity limiting, and resolver arguments passed into shell exec/eval.",
  extensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  check(file): Finding[] {
    const findings: Finding[] = [];

    for (const match of matchAll(file.content, INTROSPECTION_ENABLED)) {
      findings.push(
        makeFinding(
          rule,
          file,
          "medium",
          "GraphQL introspection is explicitly enabled — exposes the full schema to any client.",
          match.index,
          "Disable introspection in production (e.g. `introspection: process.env.NODE_ENV !== 'production'`).",
        ),
      );
    }

    for (const match of matchAll(file.content, SERVER_INIT)) {
      if (!HAS_DEPTH_OR_COMPLEXITY_GUARD.test(file.content)) {
        findings.push(
          makeFinding(
            rule,
            file,
            "medium",
            "ApolloServer is instantiated with no query depth or complexity limiting — vulnerable to denial-of-service via deeply nested or expensive queries.",
            match.index,
            "Add a depth-limiting or cost-analysis validation rule (e.g. `graphql-depth-limit` or `graphql-query-complexity`) to the server's `validationRules`.",
          ),
        );
      }
    }

    for (const match of matchAll(file.content, RESOLVER_ARGS_TO_EXEC)) {
      findings.push(
        makeFinding(
          rule,
          file,
          "critical",
          "GraphQL resolver argument is interpolated directly into a shell exec/eval call — command injection.",
          match.index,
          "Never pass resolver arguments into a shell command or eval; validate/allowlist inputs and use a non-shell API (e.g. execFile with an argument array).",
        ),
      );
    }

    for (const match of matchAll(file.content, CSRF_PREVENTION_DISABLED)) {
      findings.push(
        makeFinding(
          rule,
          file,
          "high",
          "ApolloServer's csrfPrevention is explicitly disabled — a plain HTML form on another site can trigger state-changing GraphQL mutations using the victim's session cookie.",
          match.index,
          "Remove csrfPrevention: false (it defaults to enabled) and require a non-simple content type (e.g. application/json) for GraphQL requests.",
        ),
      );
    }

    for (const match of matchAll(file.content, SENSITIVE_FIELD_IN_TYPE)) {
      findings.push(
        makeFinding(
          rule,
          file,
          "high",
          `A sensitive field ('${match[1]}') is exposed on a GraphQL object type — any client can request it via a normal query.`,
          match.index,
          "Remove sensitive fields from client-facing types entirely, or split them into a separate type that's never resolved for external queries.",
        ),
      );
    }

    return findings;
  },
};

export default rule;
