import { extname } from "node:path";
import { collectSourceFiles } from "./walker.js";
import type { Finding, Rule, ScanOptions, ScanResult, SourceFile } from "./types.js";

function ruleAppliesTo(rule: Rule, file: SourceFile): boolean {
  if (!rule.extensions || rule.extensions.length === 0) return true;
  return rule.extensions.includes(extname(file.relativePath));
}

export async function scan(options: ScanOptions, rules: Rule[]): Promise<ScanResult> {
  const start = Date.now();
  const activeRules = options.ruleIds
    ? rules.filter((r) => options.ruleIds!.includes(r.id))
    : rules;

  const files = await collectSourceFiles(options.root, options.include, options.exclude);

  const findings: Finding[] = [];
  for (const file of files) {
    for (const rule of activeRules) {
      if (!ruleAppliesTo(rule, file)) continue;
      try {
        findings.push(...rule.check(file));
      } catch {
        // A single rule failing on a single file should not abort the scan.
      }
    }
  }

  findings.sort((a, b) => {
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return sevOrder[a.severity] - sevOrder[b.severity] || a.file.localeCompare(b.file);
  });

  return {
    root: options.root,
    filesScanned: files.length,
    scannedFiles: files.map((f) => f.relativePath).sort(),
    findings,
    durationMs: Date.now() - start,
  };
}
