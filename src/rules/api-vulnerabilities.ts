import { makeFinding, matchAll } from "../core/helpers.js";
import type { Finding, Rule } from "../core/types.js";

// swagger-ui-express (or equivalent) mounted and reachable — exposes the full endpoint and
// parameter list, including operations never linked from the app's own UI, to anyone who
// finds the docs route.
const API_DOCS_EXPOSED = /\bswaggerUi\.setup\s*\(/g;

// A route immediately preceded by a comment marking it deprecated/legacy/unused, but still
// mounted and reachable — the forgotten endpoint an attacker finds via a leaked spec, old
// documentation, or a wordlist scan.
const DEPRECATED_ENDPOINT_STILL_MOUNTED =
  /\/\/[^\n]*\b(?:deprecated|legacy|unused)\b[^\n]*\n\s*(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*(['"`])([^'"`]*)\1/gi;

// The entire request body handed straight to a create/save/update/assign call — lets a
// client set fields it was never meant to control (e.g. { "isAdmin": true }).
const MASS_ASSIGNMENT =
  /\b(?:new\s+[A-Za-z_$][\w$]*|[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\.(?:create|save|updateOne|updateMany|update|set|assign))\s*\([^)]*\breq\.body\b[^)]*\)/g;

// A raw req.query/req.params value spliced into an outbound backend request's URL (query
// string or path segment) via interpolation/concatenation — server-side parameter pollution,
// since an attacker-controlled value can inject extra `&param=`/path segments that the
// backend interprets as its own parameters.
const RAW_PARAM_IN_OUTBOUND_URL =
  /\b(?:fetch|axios(?:\.\w+)?|http\.get|https\.get|request)\s*\(\s*(`[^`]*\$\{(?!\s*encodeURIComponent\()[^}]*req\.(?:query|params)[^}]*\}[^`]*`|(['"]).*?\+\s*(?!encodeURIComponent\()req\.(?:query|params)\b)/g;

const rule: Rule = {
  id: "api-vulnerabilities",
  category: "API",
  description:
    "Flags exposed API documentation UIs, deprecated/legacy endpoints left mounted, mass-assignment sinks (raw req.body into create/update/assign), and unsanitized request values spliced into outbound backend request URLs (server-side parameter pollution).",
  extensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  check(file): Finding[] {
    const findings: Finding[] = [];

    for (const match of matchAll(file.content, API_DOCS_EXPOSED)) {
      findings.push(
        makeFinding(
          rule,
          file,
          "medium",
          "Interactive API documentation (Swagger UI) is mounted and reachable — exposes the full endpoint/parameter list, including functionality never linked from the app's own UI, to anyone who finds the route.",
          match.index,
          "Gate the docs route behind authentication, or disable it outside development (e.g. only mount when NODE_ENV !== 'production').",
        ),
      );
    }

    for (const match of matchAll(file.content, DEPRECATED_ENDPOINT_STILL_MOUNTED)) {
      const routePath = match[2] ?? "";
      findings.push(
        makeFinding(
          rule,
          file,
          "medium",
          `Route '${routePath}' is marked deprecated/legacy/unused in a comment but is still mounted and reachable — a forgotten endpoint an attacker can find and exploit.`,
          match.index,
          "Remove the endpoint entirely once superseded, or explicitly gate it (auth + feature flag) instead of leaving it live and undocumented.",
        ),
      );
    }

    for (const match of matchAll(file.content, MASS_ASSIGNMENT)) {
      findings.push(
        makeFinding(
          rule,
          file,
          "high",
          "The entire request body is passed directly into a create/save/update/assign call — mass assignment lets a client set fields it was never meant to control (e.g. isAdmin).",
          match.index,
          "Explicitly pick and validate/cast individual fields (e.g. `user.name = String(req.body.name)`) instead of assigning the raw request body.",
        ),
      );
    }

    for (const match of matchAll(file.content, RAW_PARAM_IN_OUTBOUND_URL)) {
      findings.push(
        makeFinding(
          rule,
          file,
          "high",
          "A raw request value (req.query/req.params) is spliced directly into an outbound backend request URL — server-side parameter pollution lets an attacker inject extra query parameters or path segments that the backend interprets as its own.",
          match.index,
          "URL-encode the value (e.g. encodeURIComponent) and/or validate it against an allowlist before building the outbound URL, instead of splicing it in raw.",
        ),
      );
    }

    return findings;
  },
};

export default rule;
