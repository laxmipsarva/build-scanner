export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface SourceFile {
  path: string;
  relativePath: string;
  content: string;
  lines: string[];
}

export interface Finding {
  ruleId: string;
  category: string;
  severity: Severity;
  message: string;
  file: string;
  line: number;
  column?: number;
  snippet: string;
  recommendation: string;
}

export interface Rule {
  id: string;
  category: string;
  description: string;
  /** File extensions this rule applies to, e.g. [".js", ".ts"]. Omit to run on all text files. */
  extensions?: string[];
  check(file: SourceFile): Finding[];
}

export interface ScanOptions {
  /** Root directory to scan. */
  root: string;
  /** Glob patterns to include, relative to root. */
  include?: string[];
  /** Glob patterns to exclude, relative to root. */
  exclude?: string[];
  /** Rule IDs to run. Omit to run all registered rules. */
  ruleIds?: string[];
}

export interface ScanResult {
  root: string;
  filesScanned: number;
  scannedFiles: string[];
  findings: Finding[];
  durationMs: number;
}
