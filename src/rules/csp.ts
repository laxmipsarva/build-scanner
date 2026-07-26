import { makeFinding, matchAll } from "../core/helpers.js";
import type { Finding, Rule } from "../core/types.js";

// Content-Security-Policy header value containing unsafe-inline or unsafe-eval.
const UNSAFE_DIRECTIVE =
  /Content-Security-Policy['"]?\s*[,:]\s*(['"`])(?:(?!\1).)*?(unsafe-inline|unsafe-eval)(?:(?!\1).)*?\1/gs;

// A directive source list containing a bare wildcard, e.g. script-src *
// Allows single-quoted CSP keywords (e.g. 'unsafe-inline') inside the list; stops at the
// enclosing JS string delimiter (" or `) or a `;` that ends the directive.
const WILDCARD_SOURCE = /(script-src|style-src|default-src|connect-src|img-src|frame-src)\s+([^;"`]*\*[^;"`]*)/g;

// helmet's CSP middleware explicitly disabled.
const HELMET_CSP_DISABLED = /contentSecurityPolicy\s*:\s*false/g;

// A <meta http-equiv="Content-Security-Policy" content="..."> tag — the way Vite/CRA apps
// (which ship no server code) typically set their CSP. Attribute order is not fixed, so this
// only locates the tag; the content="" value is pulled out separately below.
const META_CSP_TAG = /<meta\b[^>]*\bhttp-equiv\s*=\s*(['"])Content-Security-Policy\1[^>]*>/gi;
const META_CONTENT_ATTR = /\bcontent\s*=\s*(['"])((?:(?!\1).)*)\1/i;

// next.config.js headers(): { key: 'Content-Security-Policy', value: "..." } — literal value.
const NEXT_CONFIG_CSP_LITERAL =
  /key\s*:\s*(['"`])Content-Security-Policy\1\s*,\s*value\s*:\s*(['"`])((?:(?!\2)[\s\S])*?)\2/g;

// Same shape, but the value is a variable: { key: 'Content-Security-Policy', value: cspHeader }
const NEXT_CONFIG_CSP_IDENTIFIER =
  /key\s*:\s*(['"`])Content-Security-Policy\1\s*,\s*value\s*:\s*(\w+)\s*[,}]/g;

// middleware.ts: response.headers.set('Content-Security-Policy', cspHeader) / setHeader(...) —
// the policy is built into a variable and only the variable name reaches this call, so the
// literal policy text is never adjacent to "Content-Security-Policy" in the source.
const CSP_HEADER_SET_IDENTIFIER =
  /(?:headers\s*\.\s*set|setHeader)\s*\(\s*(['"`])Content-Security-Policy\1\s*,\s*(\w+)\s*\)/g;

/** Finds `const/let/var <varName> = "..."` in `content` and returns its string value + absolute offset. */
function resolveStringVariable(
  content: string,
  varName: string,
): { value: string; valueStart: number } | undefined {
  const declRe = new RegExp(String.raw`\b(?:const|let|var)\s+${varName}\s*=\s*(['"\`])([\s\S]*?)\1`);
  const declMatch = declRe.exec(content);
  if (!declMatch) return undefined;
  const value = declMatch[2] ?? "";
  // declMatch[0] always ends in the 1-char closing quote immediately after the value text.
  const valueStart = declMatch.index + declMatch[0].length - 1 - value.length;
  return { value, valueStart };
}

const rule: Rule = {
  id: "csp-misconfiguration",
  category: "CSP",
  description:
    "Flags Content-Security-Policy configurations that allow unsafe-inline/unsafe-eval, use wildcard sources, or are disabled entirely.",
  extensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".html"],
  check(file): Finding[] {
    const findings: Finding[] = [];

    for (const match of matchAll(file.content, UNSAFE_DIRECTIVE)) {
      findings.push(
        makeFinding(
          rule,
          file,
          "medium",
          `Content-Security-Policy allows '${match[2]}', which significantly weakens XSS protection.`,
          match.index,
          "Remove 'unsafe-inline'/'unsafe-eval' from the CSP; use nonces or hashes for required inline scripts/styles instead.",
        ),
      );
    }

    for (const match of matchAll(file.content, WILDCARD_SOURCE)) {
      findings.push(
        makeFinding(
          rule,
          file,
          "medium",
          `CSP directive '${match[1]}' allows a wildcard source, permitting content from any origin.`,
          match.index,
          `Replace the wildcard in '${match[1]}' with an explicit list of trusted origins.`,
        ),
      );
    }

    for (const match of matchAll(file.content, HELMET_CSP_DISABLED)) {
      findings.push(
        makeFinding(
          rule,
          file,
          "high",
          "Content-Security-Policy is explicitly disabled (contentSecurityPolicy: false).",
          match.index,
          "Enable and configure a restrictive CSP instead of disabling it.",
        ),
      );
    }

    for (const match of matchAll(file.content, META_CSP_TAG)) {
      const contentValue = META_CONTENT_ATTR.exec(match[0])?.[2] ?? "";
      const unsafeMatch = /unsafe-inline|unsafe-eval/.exec(contentValue);
      if (unsafeMatch) {
        findings.push(
          makeFinding(
            rule,
            file,
            "medium",
            `Content-Security-Policy <meta> tag allows '${unsafeMatch[0]}', which significantly weakens XSS protection.`,
            match.index,
            "Remove 'unsafe-inline'/'unsafe-eval' from the CSP; use nonces or hashes for required inline scripts/styles instead.",
          ),
        );
      }
    }

    for (const match of matchAll(file.content, NEXT_CONFIG_CSP_LITERAL)) {
      const value = match[3] ?? "";
      const unsafeMatch = /unsafe-inline|unsafe-eval/.exec(value);
      if (unsafeMatch) {
        const valueStart = match.index + match[0].length - 1 - value.length;
        findings.push(
          makeFinding(
            rule,
            file,
            "medium",
            `Content-Security-Policy allows '${unsafeMatch[0]}', which significantly weakens XSS protection.`,
            valueStart + unsafeMatch.index,
            "Remove 'unsafe-inline'/'unsafe-eval' from the CSP; use nonces or hashes for required inline scripts/styles instead.",
          ),
        );
      }
    }

    for (const match of [
      ...matchAll(file.content, NEXT_CONFIG_CSP_IDENTIFIER),
      ...matchAll(file.content, CSP_HEADER_SET_IDENTIFIER),
    ]) {
      const resolved = resolveStringVariable(file.content, match[2] ?? "");
      if (!resolved) continue;
      const unsafeMatch = /unsafe-inline|unsafe-eval/.exec(resolved.value);
      if (unsafeMatch) {
        findings.push(
          makeFinding(
            rule,
            file,
            "medium",
            `Content-Security-Policy allows '${unsafeMatch[0]}', which significantly weakens XSS protection.`,
            resolved.valueStart + unsafeMatch.index,
            "Remove 'unsafe-inline'/'unsafe-eval' from the CSP; use nonces or hashes for required inline scripts/styles instead.",
          ),
        );
      }
    }

    return findings;
  },
};

export default rule;
