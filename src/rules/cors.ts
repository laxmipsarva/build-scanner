import { makeFinding, matchAll } from "../core/helpers.js";
import type { Finding, Rule } from "../core/types.js";

// res.setHeader('Access-Control-Allow-Origin', '*')  or  header('Access-Control-Allow-Origin', '*')
const WILDCARD_ORIGIN_HEADER =
  /(?:setHeader|header)\s*\(\s*(['"])Access-Control-Allow-Origin\1\s*,\s*(['"])\*\2\s*\)/g;

// Origin reflected straight from the request without an allowlist check.
const REFLECTED_ORIGIN_HEADER =
  /(?:setHeader|header)\s*\(\s*(['"])Access-Control-Allow-Origin\1\s*,\s*req\.headers(?:\.origin|\[['"]origin['"]\])\s*\)/g;

// cors({ origin: '*' , ... credentials: true ... }) or reversed order — wildcard + credentials is invalid/dangerous.
const CORS_MIDDLEWARE_WILDCARD_WITH_CREDENTIALS =
  /origin\s*:\s*(['"])\*\1[\s\S]{0,200}?credentials\s*:\s*true|credentials\s*:\s*true[\s\S]{0,200}?origin\s*:\s*(['"])\*\2/g;

// cors({ origin: true }) blindly reflects the request Origin header for every caller.
const CORS_MIDDLEWARE_ORIGIN_TRUE = /\bcors\s*\(\s*\{[^}]*\borigin\s*:\s*true\b/g;

// origin === "null" treated as trusted, followed by the origin being echoed back in
// Access-Control-Allow-Origin — "null" is trivially forgeable via a sandboxed iframe or a
// data:/file: page, so trusting it is equivalent to trusting any origin.
const NULL_ORIGIN_TRUSTED =
  /\borigin\s*===?\s*(['"])null\1[\s\S]{0,300}?Access-Control-Allow-Origin/g;

// An origin-matching regex that accepts both http and https (e.g. /^https?:\/\/.../), later
// used to decide the Access-Control-Allow-Origin value — trusting plain http means a
// network-level attacker can forge the Origin header for an otherwise-trusted domain.
const INSECURE_PROTOCOL_ORIGIN_CHECK =
  /https\?[\s\S]{0,150}?\.test\s*\(\s*(?:req\.headers\.origin|origin)\s*\)[\s\S]{0,300}?Access-Control-Allow-Origin/g;

// Next.js middleware.ts / route handlers set headers via response.headers.set(...) (dot-set),
// not Express's setHeader(...).
const WILDCARD_ORIGIN_HEADER_DOT_SET =
  /\bheaders\s*\.\s*set\s*\(\s*(['"])Access-Control-Allow-Origin\1\s*,\s*(['"])\*\2\s*\)/g;

// Same dot-set call, reflecting the origin via the Request/NextRequest API's .headers.get('origin').
const REFLECTED_ORIGIN_HEADER_DOT_SET =
  /\bheaders\s*\.\s*set\s*\(\s*(['"])Access-Control-Allow-Origin\1\s*,\s*(?:request|req)\.headers\.get\(\s*(['"])origin\2\s*\)\s*\)/gi;

// Next.js App Router route handlers commonly pass headers as an object literal instead of a
// function call, e.g. NextResponse.json(data, { headers: { 'Access-Control-Allow-Origin': '*' } }).
const WILDCARD_ORIGIN_HEADER_OBJECT = /(['"])Access-Control-Allow-Origin\1\s*:\s*(['"])\*\2/g;

const REFLECTED_ORIGIN_HEADER_OBJECT =
  /(['"])Access-Control-Allow-Origin\1\s*:\s*(?:request|req)\.headers\.get\(\s*(['"])origin\2\s*\)/gi;

// next.config.js headers(): { key: 'Access-Control-Allow-Origin', value: '*' }
const NEXT_CONFIG_CORS_WILDCARD =
  /key\s*:\s*(['"`])Access-Control-Allow-Origin\1\s*,\s*value\s*:\s*(['"`])\*\2/g;

const rule: Rule = {
  id: "cors-misconfiguration",
  category: "CORS",
  description:
    "Flags wildcard or blindly-reflected Access-Control-Allow-Origin, and wildcard origins combined with credentials.",
  extensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  check(file): Finding[] {
    const findings: Finding[] = [];

    for (const match of matchAll(file.content, WILDCARD_ORIGIN_HEADER)) {
      findings.push(
        makeFinding(
          rule,
          file,
          "medium",
          "Access-Control-Allow-Origin is set to '*', allowing any origin to read the response.",
          match.index,
          "Restrict Access-Control-Allow-Origin to an explicit allowlist of trusted origins instead of '*'.",
        ),
      );
    }

    for (const match of matchAll(file.content, REFLECTED_ORIGIN_HEADER)) {
      findings.push(
        makeFinding(
          rule,
          file,
          "high",
          "Access-Control-Allow-Origin reflects the request's Origin header with no allowlist check — any site can make credentialed cross-origin requests.",
          match.index,
          "Validate req.headers.origin against an explicit allowlist before echoing it back in Access-Control-Allow-Origin.",
        ),
      );
    }

    for (const match of matchAll(file.content, CORS_MIDDLEWARE_WILDCARD_WITH_CREDENTIALS)) {
      findings.push(
        makeFinding(
          rule,
          file,
          "high",
          "CORS configured with a wildcard origin and credentials: true — browsers reject this, but some clients/proxies don't, and it signals a broken trust boundary.",
          match.index,
          "Use an explicit origin allowlist when credentials: true is set; never combine '*' with credentials.",
        ),
      );
    }

    for (const match of matchAll(file.content, CORS_MIDDLEWARE_ORIGIN_TRUE)) {
      findings.push(
        makeFinding(
          rule,
          file,
          "medium",
          "cors() is configured with origin: true, which reflects every request's Origin header.",
          match.index,
          "Pass an explicit allowlist (array, regex, or validation function) as the origin option instead of true.",
        ),
      );
    }

    for (const match of matchAll(file.content, NULL_ORIGIN_TRUSTED)) {
      findings.push(
        makeFinding(
          rule,
          file,
          "high",
          "The origin allowlist trusts the literal 'null' origin — trivially forgeable via a sandboxed iframe or a data:/file: page, so it's equivalent to trusting any origin.",
          match.index,
          "Remove 'null' from the allowlist; if sandboxed-iframe callers must be supported, authenticate them some other way than the Origin header.",
        ),
      );
    }

    for (const match of matchAll(file.content, INSECURE_PROTOCOL_ORIGIN_CHECK)) {
      findings.push(
        makeFinding(
          rule,
          file,
          "high",
          "The origin allowlist accepts both http and https for a trusted domain — a network attacker who can intercept or host plain-http traffic on that domain can forge the Origin header.",
          match.index,
          "Require https explicitly in the allowlist check (e.g. /^https:\\/\\//) instead of an optional 's'.",
        ),
      );
    }

    for (const match of [
      ...matchAll(file.content, WILDCARD_ORIGIN_HEADER_DOT_SET),
      ...matchAll(file.content, WILDCARD_ORIGIN_HEADER_OBJECT),
      ...matchAll(file.content, NEXT_CONFIG_CORS_WILDCARD),
    ]) {
      findings.push(
        makeFinding(
          rule,
          file,
          "medium",
          "Access-Control-Allow-Origin is set to '*', allowing any origin to read the response.",
          match.index,
          "Restrict Access-Control-Allow-Origin to an explicit allowlist of trusted origins instead of '*'.",
        ),
      );
    }

    for (const match of [
      ...matchAll(file.content, REFLECTED_ORIGIN_HEADER_DOT_SET),
      ...matchAll(file.content, REFLECTED_ORIGIN_HEADER_OBJECT),
    ]) {
      findings.push(
        makeFinding(
          rule,
          file,
          "high",
          "Access-Control-Allow-Origin reflects the request's Origin header with no allowlist check — any site can make credentialed cross-origin requests.",
          match.index,
          "Validate the request's Origin header against an explicit allowlist before echoing it back in Access-Control-Allow-Origin.",
        ),
      );
    }

    return findings;
  },
};

export default rule;
