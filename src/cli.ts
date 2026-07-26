#!/usr/bin/env node
import { resolve } from "node:path";
import { Command } from "commander";
import { scan } from "./core/scanner.js";
import { formatJson, formatText } from "./core/report.js";
import { allRules } from "./rules/index.js";

const program = new Command();

program
  .name("build-scanner")
  .description(
    "Static scanner for SQL/NoSQL injection, GraphQL, CORS, CSP, and CSRF vulnerabilities in a local build/source folder",
  )
  .argument("[path]", "directory to scan", ".")
  .option("-f, --format <format>", "output format: text | json", "text")
  .option("-r, --rules <ids>", "comma-separated rule IDs to run (default: all)")
  .option(
    "--fail-on <severity>",
    "exit with a non-zero code if a finding at or above this severity is present (critical|high|medium|low|info)",
  )
  .option("-l, --list-files", "list every file that was scanned")
  .action(async (path: string, opts) => {
    const root = resolve(process.cwd(), path);
    const ruleIds = opts.rules ? String(opts.rules).split(",").map((s: string) => s.trim()) : undefined;

    if (ruleIds) {
      const knownIds = new Set(allRules.map((r) => r.id));
      const unknown = ruleIds.filter((id) => !knownIds.has(id));
      if (unknown.length > 0) {
        console.error(
          `Warning: unknown rule id(s) ${unknown.map((id) => `'${id}'`).join(", ")} — no rule matches, so they will contribute no findings. Run 'build-scanner rules' to list valid ids.`,
        );
      }
    }

    const result = await scan({ root, ruleIds }, allRules);

    if (opts.format === "json") {
      console.log(formatJson(result));
    } else {
      console.log(formatText(result, { listFiles: opts.listFiles }));
    }

    if (opts.failOn) {
      const order = ["critical", "high", "medium", "low", "info"];
      const threshold = order.indexOf(String(opts.failOn).toLowerCase());
      if (threshold === -1) {
        console.error(`Invalid --fail-on value: ${opts.failOn}`);
        process.exitCode = 2;
        return;
      }
      const hasBlocking = result.findings.some((f) => order.indexOf(f.severity) <= threshold);
      if (hasBlocking) process.exitCode = 1;
    }
  });

program.command("rules").description("List available rules").action(() => {
  for (const rule of allRules) {
    console.log(`${rule.id}\t${rule.category}\t${rule.description}`);
  }
});

program.parseAsync(process.argv);
