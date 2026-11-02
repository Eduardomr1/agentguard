#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { buildCustomRules, extractPolicyFromConfig, loadConfig } from "./config.js";
import { audit, defaultRules } from "./engine.js";
import { formatFuzzReportTerminal, fuzzPromptResilience } from "./fuzzer.js";
import { AgentGuardMcpServer } from "./mcp.js";
import { auditWithNormalization } from "./normalize.js";
import { auditStructuredPrompt } from "./parsers.js";
import { evaluatePolicyGate, mergePolicies } from "./policy.js";
import { pseudonymizeText } from "./pseudonymize.js";
import { redactText } from "./redact.js";
import { generateHtmlReport, generateMarkdownReport } from "./reporter.js";
import { toSarif } from "./sarif.js";
import { formatScanSummaryTerminal, scanFiles } from "./scanner.js";
import type { Category, PolicyConfig, Severity, Target } from "./types.js";
import { AgentGuardWatcher } from "./watch.js";

const USAGE = `agentguard [file|-|scan|watch|fuzz] [options]

Commands:
  agentguard [file|-]       audit a single file or stdin
  agentguard scan [globs]   batch scan directories/files with codeframe excerpts
  agentguard watch [globs]  live interactive incremental watcher with terminal redraw
  agentguard fuzz [file]    adversarial red-teaming fuzzer & resilience score

Options:
  --target prompt|output    what is being audited (default: prompt)
  --schema <file.json>      validate text as JSON against this schema
  --config <file.json>      config with disable/failOn/policy/custom rules
  --fail-on <severity>      low|medium|high|critical (default: low)
  --min-severity <severity> retain only findings at or above severity
  --category <cat,...>      restrict audit to categories (injection,secret,pii,schema)
  --allow-pattern <regex>   allowlist regex pattern (repeatable)
  --allow-value <literal>   allowlist exact literal value (repeatable)
  --inline-suppressions     honor inline agentguard-ignore comments in trusted files
  --max-findings <n>        fail quality gate when total findings exceed n
  --min-score <0-100>       fail quality gate when security score is below threshold
  --disable <ruleId,...>    skip rules
  --normalize               enable homoglyph & leetspeak deobfuscation
  --structured <format>     parse structured prompt (markdown|chat-json)
  --html <out.html>         generate standalone interactive HTML audit report
  --markdown <out.md>       generate executive Markdown audit summary
  --json | --sarif          machine-readable output
  --redact                  stream input with secrets/PII masked as [REDACTED:<id>]
  --pseudonymize <mode>     anonymize input preserving structure (redact|hash|synthetic)
  --mcp                     launch Model Context Protocol (MCP) server over stdio

Exit codes: 0 clean, 1 findings/gate failure, 2 usage error`;

const SEVERITIES: readonly Severity[] = ["low", "medium", "high", "critical"];
const VALID_CATEGORIES = new Set<string>(["injection", "secret", "pii", "schema"]);

export interface CliIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  readInput?: (src: string) => string;
}

const defaultIo: CliIo = {
  stdout: (text: string) => process.stdout.write(text),
  stderr: (text: string) => process.stderr.write(text),
  readInput: (src: string) => readFileSync(src === "-" ? 0 : src, "utf8"),
};

export async function runCli(
  argv: string[] = process.argv.slice(2),
  io: CliIo = defaultIo,
): Promise<number> {
  const logOut = (line: string): void => io.stdout(line + "\n");
  const logErr = (line: string): void => io.stderr(line + "\n");
  const readSrc = io.readInput ?? defaultIo.readInput!;

  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        target: { type: "string", default: "prompt" },
        schema: { type: "string" },
        config: { type: "string" },
        "fail-on": { type: "string" },
        "min-severity": { type: "string" },
        category: { type: "string" },
        "allow-pattern": { type: "string", multiple: true },
        "allow-value": { type: "string", multiple: true },
        "inline-suppressions": { type: "boolean", default: false },
        "max-findings": { type: "string" },
        "min-score": { type: "string" },
        disable: { type: "string" },
        normalize: { type: "boolean", default: false },
        structured: { type: "string" },
        html: { type: "string" },
        markdown: { type: "string" },
        json: { type: "boolean", default: false },
        sarif: { type: "boolean", default: false },
        redact: { type: "boolean", default: false },
        pseudonymize: { type: "string" },
        mcp: { type: "boolean", default: false },
        help: { type: "boolean", short: "h", default: false },
      },
    });
  } catch (e) {
    logErr(`Invalid arguments: ${(e as Error).message}`);
    return 2;
  }

  const { values, positionals } = parsed;

  if (values.help) {
    logOut(USAGE);
    return 0;
  }

  if (values.mcp) {
    const server = new AgentGuardMcpServer();
    server.start();
    return 0;
  }

  let cfg;
  try {
    cfg = values.config ? loadConfig(values.config) : {};
  } catch (e) {
    logErr(`Bad config: ${(e as Error).message}`);
    return 2;
  }

  const failOn = (values["fail-on"] ?? cfg.failOn ?? "low") as Severity;
  if (
    !["prompt", "output"].includes(values.target!) ||
    !SEVERITIES.includes(failOn)
  ) {
    logErr(USAGE);
    return 2;
  }

  let minSeverity: Severity | undefined;
  if (values["min-severity"] !== undefined) {
    if (!SEVERITIES.includes(values["min-severity"] as Severity)) {
      logErr(`Invalid --min-severity '${values["min-severity"]}'.`);
      return 2;
    }
    minSeverity = values["min-severity"] as Severity;
  }

  let categories: Category[] | undefined;
  if (values.category !== undefined) {
    const rawCats = values.category
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (rawCats.length === 0 || rawCats.some((c) => !VALID_CATEGORIES.has(c))) {
      logErr(`Invalid --category '${values.category}'.`);
      return 2;
    }
    categories = rawCats as Category[];
  }

  let maxFindings: number | undefined;
  if (values["max-findings"] !== undefined) {
    const parsedMax = Number(values["max-findings"]);
    if (!Number.isInteger(parsedMax) || parsedMax < 0) {
      logErr("Invalid --max-findings: expected a non-negative integer.");
      return 2;
    }
    maxFindings = parsedMax;
  }

  let minSecurityScore: number | undefined;
  if (values["min-score"] !== undefined) {
    const parsedMin = Number(values["min-score"]);
    if (Number.isNaN(parsedMin) || parsedMin < 0 || parsedMin > 100) {
      logErr("Invalid --min-score: expected a number between 0 and 100.");
      return 2;
    }
    minSecurityScore = parsedMin;
  }

  const allowPatterns = values["allow-pattern"] ?? [];
  const allowValues = values["allow-value"] ?? [];
  for (const pat of allowPatterns) {
    try {
      new RegExp(pat);
    } catch (e) {
      logErr(`Invalid --allow-pattern '${pat}': ${(e as Error).message}`);
      return 2;
    }
  }

  const cliPolicyOverride: PolicyConfig | undefined =
    allowPatterns.length > 0 ||
    allowValues.length > 0 ||
    categories !== undefined ||
    minSeverity !== undefined ||
    values["inline-suppressions"]
      ? {
          ...(allowPatterns.length > 0 || allowValues.length > 0
            ? {
                allowlist: {
                  ...(allowPatterns.length > 0 ? { patterns: allowPatterns } : {}),
                  ...(allowValues.length > 0 ? { values: allowValues } : {}),
                },
              }
            : {}),
          ...(categories !== undefined ? { categories } : {}),
          ...(minSeverity !== undefined ? { minSeverity } : {}),
          ...(values["inline-suppressions"] ? { honorInlineSuppressions: true } : {}),
        }
      : undefined;

  const policy = mergePolicies(extractPolicyFromConfig(cfg), cliPolicyOverride);

  let custom;
  try {
    custom = buildCustomRules(cfg.rules);
  } catch (e) {
    logErr(`Invalid custom rule: ${(e as Error).message}`);
    return 2;
  }

  let schema: object | undefined;
  if (values.schema) {
    try {
      schema = JSON.parse(readFileSync(values.schema, "utf8")) as object;
    } catch (e) {
      logErr(`Invalid schema file: ${(e as Error).message}`);
      return 2;
    }
  }

  const disable = [
    ...(cfg.disable ?? []),
    ...(values.disable?.split(",").map((s) => s.trim()).filter(Boolean) ?? []),
  ];
  const rules = [...defaultRules, ...custom];

  // Batch directory scan command
  if (positionals[0] === "scan") {
    const patterns = positionals.slice(1);
    const summary = await scanFiles(patterns.length ? patterns : ["."], {
      target: values.target as Target,
      failOn,
      disable,
      normalize: values.normalize,
      schema,
      rules,
      policy,
    });
    logOut(formatScanSummaryTerminal(summary));
    if (maxFindings !== undefined && summary.totalFindings > maxFindings) {
      return 1;
    }
    return summary.ok ? 0 : 1;
  }

  // Interactive watch mode command
  if (positionals[0] === "watch") {
    const patterns = positionals.slice(1);
    const watcher = new AgentGuardWatcher(patterns.length ? patterns : ["."], {
      target: values.target as Target,
      failOn,
      disable,
      normalize: values.normalize,
      schema,
      rules,
      policy,
      clearTerminal: true,
    });
    await watcher.start();
    logOut("[agentguard] Watching files for changes... (Ctrl+C to exit)");
    return new Promise<number>(() => {}); // Keep alive until interrupted
  }

  // Adversarial fuzzing command
  if (positionals[0] === "fuzz") {
    const src = positionals[1] ?? "-";
    const content = readSrc(src);
    const attacks = content
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith("#"));
    const report = fuzzPromptResilience(attacks.length ? attacks : [content]);
    logOut(formatFuzzReportTerminal(report));
    return report.resilienceScore >= 80 ? 0 : 1;
  }

  const src = positionals[0] ?? "-";
  let text = "";
  try {
    text = readSrc(src);
  } catch (e) {
    logErr(`Error reading input: ${(e as Error).message}`);
    return 2;
  }

  let result;
  if (values.structured) {
    if (!["markdown", "chat-json"].includes(values.structured)) {
      logErr("Invalid --structured format. Must be 'markdown' or 'chat-json'.");
      return 2;
    }
    result = auditStructuredPrompt(text, values.structured as "markdown" | "chat-json", {
      schema,
      disable,
      rules,
      policy,
    });
  } else {
    const auditFn = values.normalize ? auditWithNormalization : audit;
    result = auditFn(text, {
      target: values.target as Target,
      schema,
      disable,
      rules,
      policy,
    });
  }

  if (values.pseudonymize) {
    const mode = values.pseudonymize as "redact" | "hash" | "synthetic";
    if (!["redact", "hash", "synthetic"].includes(mode)) {
      logErr("Invalid --pseudonymize mode. Must be 'redact', 'hash', or 'synthetic'.");
      return 2;
    }
    const pseudo = pseudonymizeText(text, result.findings, { mode });
    io.stdout(pseudo.text);
  } else if (values.html) {
    const html = generateHtmlReport(result, { inputSource: src === "-" ? "stdin" : src });
    if (values.html === "-" || values.html === "stdout") {
      io.stdout(html);
    } else {
      writeFileSync(values.html, html, "utf8");
      logOut(`[OK] HTML report written to ${values.html}`);
    }
  } else if (values.markdown) {
    const md = generateMarkdownReport(result, { inputSource: src === "-" ? "stdin" : src });
    if (values.markdown === "-" || values.markdown === "stdout") {
      io.stdout(md);
    } else {
      writeFileSync(values.markdown, md, "utf8");
      logOut(`[OK] Markdown report written to ${values.markdown}`);
    }
  } else if (values.redact) {
    io.stdout(redactText(text, result.findings));
  } else if (values.sarif) {
    logOut(JSON.stringify(toSarif(result, src === "-" ? "stdin" : src), null, 2));
  } else if (values.json) {
    logOut(JSON.stringify(result, null, 2));
  } else if (result.ok) {
    logOut("[OK] no findings");
  } else {
    for (const f of result.findings) {
      logOut(`[${f.severity.toUpperCase()}] ${f.ruleId} ${f.message} @${f.start}-${f.end} ${f.match}`);
    }
  }

  const verdict = evaluatePolicyGate(result, {
    failOn,
    maxFindings,
    minSecurityScore,
  });
  return verdict.passed ? 0 : 1;
}

const isExecutedDirectly = (() => {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return path.resolve(fileURLToPath(import.meta.url)) === path.resolve(entry);
  } catch {
    return false;
  }
})();

if (isExecutedDirectly) {
  runCli().then((code) => process.exit(code));
}
