import type { Finding, Rule, Severity, SourceFile } from "./types.js";

/** Locates the 1-based line/column for a character offset within file content. */
export function locateOffset(content: string, offset: number): { line: number; column: number } {
  let line = 1;
  let lastNewline = -1;
  for (let i = 0; i < offset; i++) {
    if (content[i] === "\n") {
      line++;
      lastNewline = i;
    }
  }
  return { line, column: offset - lastNewline };
}

export function makeFinding(
  rule: Pick<Rule, "id" | "category">,
  file: SourceFile,
  severity: Severity,
  message: string,
  offset: number,
  recommendation: string,
): Finding {
  const { line, column } = locateOffset(file.content, offset);
  const snippet = (file.lines[line - 1] ?? "").trim().slice(0, 200);
  return {
    ruleId: rule.id,
    category: rule.category,
    severity,
    message,
    file: file.relativePath,
    line,
    column,
    snippet,
    recommendation,
  };
}

/** Runs a regex with the global flag over content and yields each match. */
export function* matchAll(content: string, pattern: RegExp): Generator<RegExpExecArray> {
  const re = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g");
  let match: RegExpExecArray | null;
  while ((match = re.exec(content)) !== null) {
    yield match;
    if (match[0].length === 0) re.lastIndex++;
  }
}
