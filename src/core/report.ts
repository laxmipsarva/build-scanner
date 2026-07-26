import pc from "picocolors";
import type { Finding, ScanResult, Severity } from "./types.js";

const severityColor: Record<Severity, (s: string) => string> = {
  critical: pc.bgRed,
  high: pc.red,
  medium: pc.yellow,
  low: pc.cyan,
  info: pc.gray,
};

export function formatText(result: ScanResult, options: { listFiles?: boolean } = {}): string {
  const lines: string[] = [];
  lines.push(
    pc.bold(`build-scanner: ${result.filesScanned} files scanned in ${result.durationMs}ms`),
  );

  if (options.listFiles) {
    for (const file of result.scannedFiles) lines.push(`  ${pc.dim(file)}`);
  }

  if (result.findings.length === 0) {
    lines.push(pc.green("No findings."));
    return lines.join("\n");
  }

  for (const f of result.findings) {
    const badge = severityColor[f.severity](` ${f.severity.toUpperCase()} `);
    lines.push("");
    lines.push(`${badge} ${pc.bold(f.category)} — ${f.message}`);
    lines.push(`  ${pc.dim(`${f.file}:${f.line}${f.column ? ":" + f.column : ""}`)}`);
    if (f.snippet) lines.push(`  ${pc.dim("│")} ${f.snippet}`);
    lines.push(`  ${pc.dim("fix:")} ${f.recommendation}`);
  }

  lines.push("");
  lines.push(pc.bold(summarize(result.findings)));
  return lines.join("\n");
}

function summarize(findings: Finding[]): string {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return `Total: ${findings.length} (critical: ${counts.critical}, high: ${counts.high}, medium: ${counts.medium}, low: ${counts.low}, info: ${counts.info})`;
}

export function formatJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}
