import * as fs from "node:fs";
import * as path from "node:path";
import { audit, exceeds } from "./engine.js";
import { auditWithNormalization } from "./normalize.js";
import { SEVERITY_ORDER } from "./types.js";
import type { AuditResult, Finding, PolicyConfig, Rule, Severity, Target } from "./types.js";

/** Default file extensions inspected during directory scans. */
export const DEFAULT_SCAN_EXTENSIONS = [".txt", ".md", ".json", ".prompt"] as const;
const DEFAULT_EXTENSIONS_SET = new Set<string>(DEFAULT_SCAN_EXTENSIONS);

const IGNORED_DIRS = new Set([
  "node_modules",
  ".git",
  ".svn",
  ".hg",
  "dist",
  "build",
  ".gemini",
  ".turbo",
  ".cache",
]);

export interface Position {
  line: number;
  column: number;
  lineContent: string;
}

export interface FileFinding extends Finding {
  line: number;
  column: number;
  filePath: string;
  lineContent?: string;
}

export type FileAuditResult = AuditResult & {
  findings: FileFinding[];
  content?: string;
};

export interface ScanOptions {
  cwd?: string;
  target?: Target;
  failOn?: Severity;
  disable?: string[];
  normalize?: boolean;
  schema?: object;
  rules?: Rule[];
  policy?: PolicyConfig;
}

export interface ScanSummary {
  filesScanned: number;
  totalFindings: number;
  fileResults: Map<string, FileAuditResult>;
  ok: boolean;
}

export interface CodeFrameOptions {
  colors?: boolean;
}

/**
 * Converts a 0-based character offset into a 1-based line and column,
 * extracting the full content of the line containing the offset.
 */
export function offsetToPosition(text: string, offset: number): Position {
  if (text.length === 0) {
    return { line: 1, column: 1, lineContent: "" };
  }

  const clamped = Math.max(0, Math.min(offset, text.length));
  let line = 1;
  let lastLineStart = 0;

  for (let i = 0; i < clamped; i++) {
    if (text[i] === "\n") {
      line++;
      lastLineStart = i + 1;
    }
  }

  const column = clamped - lastLineStart + 1;

  let nextNewline = text.indexOf("\n", lastLineStart);
  if (nextNewline === -1) {
    nextNewline = text.length;
  }

  let lineContent = text.slice(lastLineStart, nextNewline);
  if (lineContent.endsWith("\r")) {
    lineContent = lineContent.slice(0, -1);
  }

  return { line, column, lineContent };
}

/**
 * Formats a rustc/eslint style terminal codeframe showing line number,
 * code line, and an underline with carets `^^^^` directly under the offending span
 * accompanied by its severity and message.
 */
export function formatCodeFrame(
  text: string,
  start: number,
  end: number,
  message: string,
  severity: Severity,
  options?: CodeFrameOptions,
): string {
  const pos = offsetToPosition(text, start);
  const useColors = options?.colors ?? false;

  const lineNumStr = String(pos.line);
  const gutterWidth = Math.max(2, lineNumStr.length);
  const lineGutter = lineNumStr.padStart(gutterWidth, " ");
  const blankGutter = " ".repeat(gutterWidth);

  const colIndex = Math.max(0, pos.column - 1);
  const leading = pos.lineContent.slice(0, colIndex).replace(/[^\t]/g, " ");

  const spanLength = Math.max(1, end - start);
  const remainingOnLine = Math.max(1, pos.lineContent.length - colIndex);
  const caretCount = Math.max(1, Math.min(spanLength, remainingOnLine));
  const carets = "^".repeat(caretCount);

  if (useColors) {
    const pipe = "\x1b[90m|\x1b[0m";
    const lineGutterStyled = `\x1b[90m${lineGutter}\x1b[0m`;
    const severityColors: Record<Severity, string> = {
      critical: "\x1b[1;31m",
      high: "\x1b[31m",
      medium: "\x1b[33m",
      low: "\x1b[36m",
    };
    const sColor = severityColors[severity] ?? "\x1b[31m";
    const reset = "\x1b[0m";

    const line1 = ` ${lineGutterStyled} ${pipe} ${pos.lineContent}`;
    const line2 = ` ${blankGutter} ${pipe} ${leading}${sColor}${carets} [${severity}] ${message}${reset}`;
    return `${line1}\n${line2}`;
  }

  const line1 = ` ${lineGutter} | ${pos.lineContent}`;
  const line2 = ` ${blankGutter} | ${leading}${carets} [${severity}] ${message}`;
  return `${line1}\n${line2}`;
}

/**
 * Converts a glob pattern to a RegExp.
 */
export function globToRegex(pattern: string): RegExp {
  const normalized = pattern.replace(/\\/g, "/");
  let re = "";
  let i = 0;

  while (i < normalized.length) {
    const c = normalized[i];
    if (c === "*") {
      if (normalized[i + 1] === "*") {
        if (normalized[i + 2] === "/") {
          re += "(?:.*\\/)?";
          i += 3;
        } else {
          re += ".*";
          i += 2;
        }
      } else {
        re += "[^/]*";
        i++;
      }
    } else if (c === "?") {
      re += "[^/]";
      i++;
    } else if ("[].+^$(){}|\\".includes(c)) {
      re += "\\" + c;
      i++;
    } else {
      re += c;
      i++;
    }
  }

  return new RegExp(`^${re}$`);
}

async function collectFilesFromDir(dir: string): Promise<string[]> {
  const results: string[] = [];
  try {
    const entries = await fs.promises.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (IGNORED_DIRS.has(entry.name)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        const sub = await collectFilesFromDir(full);
        results.push(...sub);
      } else if (entry.isFile()) {
        results.push(full);
      }
    }
  } catch {
    // Ignore unreadable paths
  }
  return results;
}

/**
 * Resolves files matching given patterns or directories, audits each with AgentGuard,
 * and produces a comprehensive ScanSummary mapping findings to line and column positions.
 */
export async function scanFiles(
  patterns: string[] | string,
  options: ScanOptions = {},
): Promise<ScanSummary> {
  const rootDir = options.cwd ? path.resolve(options.cwd) : process.cwd();
  const patternList = Array.isArray(patterns) ? patterns : [patterns];
  const effectivePatterns = patternList.filter(Boolean);

  if (effectivePatterns.length === 0) {
    effectivePatterns.push(".");
  }

  const matchedFiles = new Set<string>();

  for (const rawPattern of effectivePatterns) {
    const cleanPattern = rawPattern.replace(/^(\.\/|\.\\)+/, "");
    const resolvedPath = path.resolve(rootDir, cleanPattern);

    let stat: fs.Stats | undefined;
    try {
      stat = await fs.promises.stat(resolvedPath);
    } catch {
      // Non-existent or glob pattern
    }

    if (stat?.isFile()) {
      matchedFiles.add(resolvedPath);
    } else if (stat?.isDirectory()) {
      const allInDir = await collectFilesFromDir(resolvedPath);
      for (const f of allInDir) {
        const ext = path.extname(f).toLowerCase();
        if (DEFAULT_EXTENSIONS_SET.has(ext)) {
          matchedFiles.add(f);
        }
      }
    } else {
      const isGlob = /[*?]/.test(cleanPattern);
      if (isGlob) {
        const regex = globToRegex(cleanPattern);
        const hasSpecificExt = /\.[a-zA-Z0-9_-]+$/.test(cleanPattern);

        const firstWildcard = cleanPattern.search(/[*?]/);
        const prefixPath = cleanPattern.slice(0, firstWildcard);
        const lastSlash = prefixPath.lastIndexOf("/");
        const baseSubdir = lastSlash !== -1 ? prefixPath.slice(0, lastSlash) : "";
        const searchRoot = path.resolve(rootDir, baseSubdir);

        const candidates = await collectFilesFromDir(
          fs.existsSync(searchRoot) ? searchRoot : rootDir,
        );

        for (const f of candidates) {
          const relFromRoot = path.relative(rootDir, f).replace(/\\/g, "/");
          const ext = path.extname(f).toLowerCase();

          if (!hasSpecificExt && !DEFAULT_EXTENSIONS_SET.has(ext)) {
            continue;
          }

          if (regex.test(relFromRoot) || regex.test(path.basename(f))) {
            matchedFiles.add(f);
          }
        }
      }
    }
  }

  const sortedFiles = Array.from(matchedFiles).sort((a, b) => a.localeCompare(b));
  const fileResults = new Map<string, FileAuditResult>();
  const allFindings: FileFinding[] = [];

  const auditFn = options.normalize ? auditWithNormalization : audit;

  for (const absPath of sortedFiles) {
    const relPath = path.relative(rootDir, absPath).replace(/\\/g, "/");
    const displayPath = relPath.startsWith("..") ? absPath.replace(/\\/g, "/") : relPath;

    let content = "";
    try {
      content = await fs.promises.readFile(absPath, "utf-8");
    } catch {
      continue;
    }

    const rawResult = auditFn(content, {
      target: options.target ?? "prompt",
      disable: options.disable,
      schema: options.schema,
      rules: options.rules,
      policy: options.policy,
    });

    const fileFindings: FileFinding[] = rawResult.findings.map((f) => {
      const pos = offsetToPosition(content, f.start);
      return {
        ...f,
        line: pos.line,
        column: pos.column,
        filePath: displayPath,
        lineContent: pos.lineContent,
      };
    });

    allFindings.push(...fileFindings);

    const fileOk = options.failOn
      ? !exceeds({ ok: false, findings: fileFindings }, options.failOn)
      : rawResult.ok;

    fileResults.set(displayPath, {
      ok: fileOk,
      findings: fileFindings,
      content,
    });
  }

  const summaryOk = options.failOn
    ? !exceeds({ ok: false, findings: allFindings }, options.failOn)
    : allFindings.length === 0;

  return {
    filesScanned: fileResults.size,
    totalFindings: allFindings.length,
    fileResults,
    ok: summaryOk,
  };
}

/**
 * Formats a terminal report from a ScanSummary with clean structured text
 * (or ANSI color coding), detailing each file, its codeframes, and a summary block.
 */
export function formatScanSummaryTerminal(
  summary: ScanSummary,
  options?: { colors?: boolean },
): string {
  const useColors = options?.colors ?? false;
  const lines: string[] = [];

  const passLabel = useColors ? "\x1b[32mPASS\x1b[0m" : "PASS";
  const failLabel = useColors ? "\x1b[31mFAIL\x1b[0m" : "FAIL";
  const okMark = useColors ? "\x1b[32m✓\x1b[0m" : "✓";
  const crossMark = useColors ? "\x1b[31m✖\x1b[0m" : "✖";

  if (summary.filesScanned === 0) {
    lines.push("No files scanned.");
    lines.push("");
    lines.push("──────────────────────────────────────────────────");
    lines.push("Scan Summary:");
    lines.push("  Files scanned:  0");
    lines.push("  Total findings: 0");
    lines.push(`  Status:         ${passLabel} (OK)`);
    lines.push("──────────────────────────────────────────────────");
    return lines.join("\n");
  }

  for (const [filePath, result] of summary.fileResults.entries()) {
    if (result.findings.length === 0) {
      lines.push(`${okMark} ${filePath}: OK (no findings)`);
    } else {
      const count = result.findings.length;
      lines.push(`${crossMark} ${filePath} (${count} finding${count === 1 ? "" : "s"}):`);

      for (const f of result.findings) {
        lines.push(
          `  [${f.severity.toUpperCase()}] ${f.ruleId} (line ${f.line}, col ${f.column}): ${f.message}`,
        );

        let text = result.content;
        let start = f.start;
        let end = f.end;

        if (!text && f.lineContent) {
          const prefix = "\n".repeat(Math.max(0, f.line - 1));
          text = prefix + f.lineContent;
          start = prefix.length + Math.max(0, f.column - 1);
          end = start + Math.max(1, f.end - f.start);
        } else if (!text && fs.existsSync(f.filePath)) {
          try {
            text = fs.readFileSync(f.filePath, "utf-8");
          } catch {
            // fallback
          }
        }

        const frameText = text ?? `${f.match}\n`;
        const frame = formatCodeFrame(
          frameText,
          text ? start : 0,
          text ? end : f.match.length,
          f.message,
          f.severity,
          options,
        );
        lines.push(frame);
        lines.push("");
      }
    }
  }

  lines.push("──────────────────────────────────────────────────");
  lines.push("Scan Summary:");
  lines.push(`  Files scanned:  ${summary.filesScanned}`);
  lines.push(`  Total findings: ${summary.totalFindings}`);
  lines.push(`  Status:         ${summary.ok ? passLabel : failLabel}`);
  lines.push("──────────────────────────────────────────────────");

  return lines.join("\n");
}
