import { makeFinding, matchAll } from "../core/helpers.js";
import type { Finding, Rule } from "../core/types.js";

const SQL_KEYWORDS =
  /\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|WHERE|UNION\s+SELECT)\b/i;

// Template literal that contains a SQL keyword and at least one ${...} interpolation.
const TEMPLATE_LITERAL_SQL = /`([^`]*?)`/gs;

// String concatenation ("SELECT ..." + var) that contains a SQL keyword.
const CONCAT_SQL =
  /(['"])((?:(?!\1).)*?)\1\s*\+\s*[A-Za-z_$][\w.$[\]]*|[A-Za-z_$][\w.$[\]]*\s*\+\s*(['"])((?:(?!\3).)*?)\3/g;

// A query/execute call whose error handler sends the raw error (or .message) straight
// back to the client — leaks DB schema/query details and enables error-based/visible SQLi.
const QUERY_CALL = /\.(?:query|execute)\s*\(/g;
const ERR_TO_CLIENT = /res(?:\.\w+\([^)]*\))*\.(?:send|json|end|write)\([^)]*\berr(?:or)?\b[^)]*\)/i;
const ERR_WINDOW_SIZE = 400;

// Denylist-style sanitization: stripping quote characters via .replace(/['"]/g, "").
// Trivially bypassed (e.g. via encoded/alternate representations of the stripped character),
// so it isn't a substitute for parameterized queries.
const BLOCKLIST_QUOTE_STRIP =
  /\.replace\(\s*\/((?:\\.|[^/\n])*)\/([a-z]*)\s*,\s*(['"`])\s*\3\s*\)/g;

// Denylist-style sanitization: testing input against a regex of SQL keywords and
// rejecting/stripping on match. Bypassable via case variation, comments, or encoding.
const BLOCKLIST_KEYWORD_TEST =
  /\/[^/\n]*\b(select|union|insert|update|delete|drop)\b[^/\n]*\/[a-z]*\s*\.\s*(test|exec)\s*\(/gi;

const rule: Rule = {
  id: "sql-injection",
  category: "SQL Injection",
  description:
    "Flags SQL queries built via string concatenation or template-literal interpolation of unsanitized values, raw DB errors leaked to clients, and denylist-style SQL injection filters.",
  extensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  check(file): Finding[] {
    const findings: Finding[] = [];

    for (const match of matchAll(file.content, TEMPLATE_LITERAL_SQL)) {
      const body = match[1] ?? "";
      if (SQL_KEYWORDS.test(body) && /\$\{[^}]+\}/.test(body)) {
        findings.push(
          makeFinding(
            rule,
            file,
            "high",
            "SQL query built from a template literal with interpolated values — likely SQL injection.",
            match.index,
            "Use a parameterized query / prepared statement (e.g. `db.query('... WHERE id = ?', [id])`) instead of interpolating values into the SQL string.",
          ),
        );
      }
    }

    for (const match of matchAll(file.content, CONCAT_SQL)) {
      const snippetWindow = file.content.slice(Math.max(0, match.index - 40), match.index + match[0].length + 10);
      if (SQL_KEYWORDS.test(snippetWindow)) {
        findings.push(
          makeFinding(
            rule,
            file,
            "high",
            "SQL query appears to be built via string concatenation with a variable — likely SQL injection.",
            match.index,
            "Use a parameterized query / prepared statement instead of concatenating variables into the SQL string.",
          ),
        );
      }
    }

    for (const match of matchAll(file.content, QUERY_CALL)) {
      const window = file.content.slice(match.index, Math.min(file.content.length, match.index + ERR_WINDOW_SIZE));
      const errMatch = ERR_TO_CLIENT.exec(window);
      if (errMatch) {
        findings.push(
          makeFinding(
            rule,
            file,
            "medium",
            "Raw database error is sent back to the client near a query call — leaks schema/query details and enables error-based/visible SQL injection.",
            match.index + errMatch.index,
            "Log the full error server-side only; return a generic error message (with no DB error detail) to the client.",
          ),
        );
      }
    }

    const fileLooksSqlRelated = /\.(?:query|execute)\s*\(/.test(file.content) || SQL_KEYWORDS.test(file.content);
    if (fileLooksSqlRelated) {
      for (const match of matchAll(file.content, BLOCKLIST_QUOTE_STRIP)) {
        const regexBody = match[1] ?? "";
        if (/['"]/.test(regexBody)) {
          findings.push(
            makeFinding(
              rule,
              file,
              "medium",
              "SQL injection defense strips quote characters via a regex replace — a denylist filter that can be bypassed with encoded or alternate representations (e.g. XML/HTML entity encoding, Unicode variants) that get decoded after this check runs.",
              match.index,
              "Use parameterized queries / prepared statements instead of denylist character-stripping; never build SQL from filtered-but-still-concatenated input.",
            ),
          );
        }
      }

      for (const match of matchAll(file.content, BLOCKLIST_KEYWORD_TEST)) {
        findings.push(
          makeFinding(
            rule,
            file,
            "medium",
            `SQL injection defense tests input against a denylist of SQL keywords ('${match[1]}') — bypassable via case variation, inline comments, or encoding tricks.`,
            match.index,
            "Use parameterized queries / prepared statements instead of denylist keyword filtering.",
          ),
        );
      }
    }

    return findings;
  },
};

export default rule;
