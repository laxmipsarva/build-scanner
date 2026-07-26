import { makeFinding, matchAll } from "../core/helpers.js";
import type { Finding, Rule } from "../core/types.js";

// State-changing Express/Router routes.
const STATE_CHANGING_ROUTE = /\b(?:app|router)\.(post|put|patch|delete)\s*\(\s*(['"`])([^'"`]*)\2/g;

const MENTIONS_CSRF = /csrf/i;

// Next.js Server Actions ("use server") get automatic framework-level Origin-header CSRF
// protection (Next.js 13.4+), so state-changing exports in such a file shouldn't be flagged.
const USE_SERVER_DIRECTIVE = /['"]use server['"]/;

// Next.js App Router route handlers export the HTTP method directly, e.g.
// `export async function POST(request) {...}` or `export const POST = async (request) => {...}`.
// Only meaningful in a file literally named route.ts/js/tsx/jsx — that filename is mandated by
// the framework for Route Handlers, so scoping by it keeps false positives near zero.
const APP_ROUTER_HANDLER =
  /\bexport\s+(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE)\s*\(|\bexport\s+const\s+(POST|PUT|PATCH|DELETE)\s*=/g;

// Next.js Pages Router API routes use one default handler branching on req.method, e.g.
// `if (req.method === 'POST')` or `switch (req.method) { case 'POST': ... }`.
// Only meaningful under a pages/api/ path — scoping by path avoids matching unrelated
// method-branching code elsewhere.
const PAGES_API_METHOD_BRANCH =
  /\breq\.method\s*===?\s*(['"])(POST|PUT|PATCH|DELETE)\1|case\s*(['"])(POST|PUT|PATCH|DELETE)\3\s*:/g;

// Session/auth cookie set with SameSite=None (or missing) and no CSRF mitigation in the same file.
const COOKIE_SAMESITE_NONE = /\.cookie\s*\(\s*(['"`])[^'"`]*\1\s*,[^)]*sameSite\s*:\s*(['"`])none\2/gis;

const rule: Rule = {
  id: "csrf-vulnerabilities",
  category: "CSRF",
  description:
    "Flags state-changing routes (POST/PUT/PATCH/DELETE) with no CSRF protection referenced in the file, and cookies set with SameSite=None.",
  extensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  check(file): Finding[] {
    const findings: Finding[] = [];
    const hasCsrfMitigationSignal =
      MENTIONS_CSRF.test(file.content) || USE_SERVER_DIRECTIVE.test(file.content);
    const normalizedPath = file.relativePath.replace(/\\/g, "/");
    const isAppRouterHandler = /(^|\/)route\.(ts|tsx|js|jsx)$/.test(normalizedPath);
    const isPagesApiRoute = /(^|\/)pages\/api(\/|$)/.test(normalizedPath);

    if (!hasCsrfMitigationSignal) {
      for (const match of matchAll(file.content, STATE_CHANGING_ROUTE)) {
        const method = (match[1] ?? "").toUpperCase();
        const routePath = match[3] ?? "";
        findings.push(
          makeFinding(
            rule,
            file,
            "medium",
            `${method} route '${routePath}' has no CSRF protection referenced in this file.`,
            match.index,
            "Apply CSRF middleware (e.g. csurf, or a double-submit cookie / synchronizer token pattern) to state-changing routes, or confirm this route is authenticated via a non-cookie scheme (e.g. bearer token) that isn't CSRF-exposed.",
          ),
        );
      }

      if (isAppRouterHandler) {
        for (const match of matchAll(file.content, APP_ROUTER_HANDLER)) {
          const method = (match[1] ?? match[2] ?? "").toUpperCase();
          findings.push(
            makeFinding(
              rule,
              file,
              "medium",
              `${method} route handler in '${file.relativePath}' has no CSRF protection referenced in this file.`,
              match.index,
              "Route Handlers and Pages API routes do not get Next.js's automatic Server Action CSRF protection — validate the Origin/Sec-Fetch-Site header or use a synchronizer/double-submit CSRF token, or confirm this route is protected by a non-cookie auth scheme (e.g. bearer token) that isn't CSRF-exposed.",
            ),
          );
        }
      }

      if (isPagesApiRoute) {
        for (const match of matchAll(file.content, PAGES_API_METHOD_BRANCH)) {
          const method = (match[2] ?? match[4] ?? "").toUpperCase();
          findings.push(
            makeFinding(
              rule,
              file,
              "medium",
              `${method} handler in Pages API route '${file.relativePath}' has no CSRF protection referenced in this file.`,
              match.index,
              "Route Handlers and Pages API routes do not get Next.js's automatic Server Action CSRF protection — validate the Origin/Sec-Fetch-Site header or use a synchronizer/double-submit CSRF token, or confirm this route is protected by a non-cookie auth scheme (e.g. bearer token) that isn't CSRF-exposed.",
            ),
          );
        }
      }
    }

    for (const match of matchAll(file.content, COOKIE_SAMESITE_NONE)) {
      findings.push(
        makeFinding(
          rule,
          file,
          "medium",
          "Cookie is set with SameSite=None, which allows it to be sent on cross-site requests.",
          match.index,
          "Use SameSite=Lax or Strict for session/auth cookies unless cross-site delivery is required; if None is required, pair it with CSRF tokens and Secure.",
        ),
      );
    }

    return findings;
  },
};

export default rule;
