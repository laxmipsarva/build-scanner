# build-scanner

Static scanner that walks a local build/source folder and flags common web
vulnerability patterns:

- **SQL Injection** — string-concatenated or template-literal SQL queries,
  raw DB errors leaked to the client, and denylist-style SQLi filters (see
  [SQL injection scenario coverage](#sql-injection-scenario-coverage) below)
- **NoSQL Injection** — raw request objects passed into MongoDB-style
  queries (operator injection), and `$where` clauses built from dynamic
  strings (JS injection)
- **GraphQL** — introspection left enabled, missing query depth/complexity
  limiting, resolver arguments piped into `exec`/`eval`
- **CORS** — wildcard or reflected `Access-Control-Allow-Origin`, wildcard
  origin combined with credentials
- **CSP** — `unsafe-inline`/`unsafe-eval`, wildcard directive sources, CSP
  disabled entirely
- **CSRF** — state-changing routes with no CSRF protection referenced,
  cookies set with `SameSite=None`

This is a heuristic, regex-based static scanner intended to catch common
mistakes quickly — it is not a substitute for a full SAST/DAST tool or a
manual security review, and it can produce false positives/negatives.

### Vite/CRA and Next.js coverage

Beyond Express-style server code, the CSP/CORS/CSRF rules also recognize:

- **Vite/CRA**: a `<meta http-equiv="Content-Security-Policy" content="...">`
  tag in `index.html` (attribute order doesn't matter).
- **Next.js CSP**: `next.config.js` `headers()` entries in the
  `{ key: 'Content-Security-Policy', value: "..." }` shape (literal or a
  variable), and a `middleware.ts` policy built into a variable and applied
  via `headers.set('Content-Security-Policy', cspVar)`.
- **Next.js CORS**: `headers.set('Access-Control-Allow-Origin', ...)` (dot-set,
  as used in `middleware.ts` and Route Handlers), object-literal headers
  passed to `NextResponse.json()`/`Response`, and the `next.config.js`
  `headers()` equivalent.
- **Next.js CSRF**: App Router Route Handlers (`export function POST(...)` /
  `export const POST = ...` in a file literally named `route.ts`) and Pages
  API routes (`req.method === 'POST'` / `switch` under `pages/api/`). Files
  containing the `"use server"` directive (Server Actions) are treated as
  already protected, since Next.js applies automatic Origin-header CSRF
  protection to them.

Known limitations: CSP/CORS values built through multi-step indirection
(`.join()`, `.replace()`, imports from another file) aren't resolved — only a
single `const`/`let`/`var` string or template-literal assignment in the same
file is. Generic `request.method === 'POST'` branching outside `pages/api/`
(e.g. in `middleware.ts`) isn't flagged, since that shape is too common in
unrelated auth/redirect logic to scope safely.

## Install

```bash
npm install
npm run build
```

## Usage

```bash
# Scan a directory
node dist/cli.js ./path/to/project

# Scan a single file
node dist/cli.js ./path/to/project/server.js

# JSON output (for CI / tooling)
node dist/cli.js ./path/to/project --format json

# Run only specific rules
node dist/cli.js ./path/to/project --rules sql-injection,csrf-vulnerabilities

# List available rules
node dist/cli.js rules

# Exit non-zero if a finding at or above a severity is present (for CI gating)
node dist/cli.js ./path/to/project --fail-on high
```

If you `npm link` (or install it globally), the same commands are available
via the `build-scanner` binary instead of `node dist/cli.js`.

## Use as a GitHub Action

Once this repo is pushed to GitHub and tagged (e.g. `v1`), any other repo can
run the scanner in CI without installing anything itself:

```yaml
- uses: actions/checkout@v4
- uses: your-org/build-scanner@v1
  with:
    path: .
    fail-on: high
```

Inputs mirror the CLI flags above: `path` (default `.`), `format` (`text` |
`json`, default `text`), `rules` (comma-separated rule IDs), `fail-on`
(`critical|high|medium|low|info`), and `list-files` (`true`/`false`). The
action installs its own dependencies and builds from source on each run, so
the job fails exactly the way a local `--fail-on` run would.

Replace `your-org/build-scanner` with wherever this repo actually lives.

## Programmatic use

```ts
import { scan, allRules, formatText } from "build-scanner";

const result = await scan({ root: "./path/to/project" }, allRules);
console.log(formatText(result));
```

## Development

```bash
npm run dev -- ./path/to/project   # run the CLI from source via tsx
npm test                           # run the unit tests (vitest)
npm run typecheck
```

Each rule lives in `src/rules/*.ts` and has matching vulnerable/safe
fixtures in `tests/fixtures/` plus a test in `tests/unit/`. To add a new
rule: implement the `Rule` interface (see `src/core/types.ts`), register it
in `src/rules/index.ts`, and add fixtures + a test.

## SQL injection scenario coverage

`src/rules/sql-injection.ts` is exercised against 18 fixtures in
`tests/fixtures/sql-scenarios/`, one per classic SQL injection attack
scenario (PortSwigger Web Security Academy naming), via
`tests/unit/sql-injection-scenarios.test.ts`.

build-scanner is a **static** scanner — it reads source files, it doesn't
send requests to a running app. So it detects the *root-cause sink* in the
application's own source (an unparameterized query built from
concatenation/interpolation) rather than simulating an attacker's exploit
traffic. Several scenarios below intentionally share the exact same sink,
because what differs between them is the attacker's payload/technique
against a live target, not the shape of the vulnerable source code:

| # | Scenario | What's actually detected |
|---|----------|---------------------------|
| 1 | WHERE clause — hidden data | Concatenated/interpolated `WHERE` clause |
| 2 | Login bypass | Concatenated `WHERE username=...AND password=...` |
| 3 | DB version query (Oracle) | Same sink — exploited via `UNION SELECT ... FROM v$version` |
| 4 | DB version query (MySQL/MSSQL) | Same sink — exploited via `UNION SELECT @@version` |
| 5 | List DB contents (non-Oracle) | Same sink — exploited via `information_schema.tables` |
| 6 | List DB contents (Oracle) | Same sink — exploited via `all_tables` |
| 7–10 | UNION attacks (column count, text column, other tables, multi-value column) | Same sink — all four are UNION payload variations against one injectable point |
| 11 | Blind, conditional responses | Same sink, response content differs on true/false |
| 12 | Blind, conditional errors | Same sink; **not** flagged as an error leak — status-only, no error detail returned |
| 13 | Visible error-based | Same sink **+ new check**: raw `err.message` sent to the client near a query call |
| 14–15 | Blind, time delays (+ info retrieval) | Same sink — timing side-channel is invisible to static analysis |
| 16–17 | Blind, out-of-band (interaction + exfiltration) | Same sink — OOB channel is invisible to static analysis |
| 18 | Filter bypass via XML encoding | **New checks**: denylist quote-stripping (`.replace(/'/g, "")`) and denylist keyword-testing (`/select|union|.../i.test(...)`) flagged as bypassable regardless of the specific encoding trick used |

If you need to actually confirm exploitability of these scenarios (not just
find the source-level root cause), that requires a dynamic/active scanner
that sends live payloads to a running target — a different, larger tool
than this static one.
