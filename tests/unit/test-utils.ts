import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import type { Rule, SourceFile } from "../../src/core/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

export function loadFixture(name: string): SourceFile {
  const path = join(__dirname, "..", "fixtures", name);
  const content = readFileSync(path, "utf8");
  return {
    path,
    relativePath: name,
    content,
    lines: content.split(/\r?\n/),
  };
}

export function runRule(rule: Rule, fixtureName: string) {
  return rule.check(loadFixture(fixtureName));
}
