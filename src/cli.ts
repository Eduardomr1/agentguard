#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { buildCustomRules, loadConfig } from "./config.js";
import { audit, defaultRules, exceeds } from "./engine.js";
import { formatFuzzReportTerminal, fuzzPromptResilience } from "./fuzzer.js";
import { AgentGuardMcpServer } from "./mcp.js";
import { auditWithNormalization } from "./normalize.js";
import { auditStructuredPrompt } from "./parsers.js";
import { pseudonymizeText } from "./pseudonymize.js";
import { redactText } from "./redact.js";
import { generateHtmlReport } from "./reporter.js";
import { toSarif } from "./sarif.js";
import { formatScanSummaryTerminal, scanFiles } from "./scanner.js";
import type { Severity, Target } from "./types.js";
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
  --config <file.json>      config with disable/failOn/custom rules
  --fail-on <severity>      low|medium|high|critical (default: low)
  --disable <ruleId,...>    skip rules
  --normalize               enable homoglyph & leetspeak deobfuscation
  --structured <format>     parse structured prompt (markdown|chat-json)
  --html <out.html>         generate standalone interactive HTML audit report
  --json | --sarif          machine-readable output
  --redact                  stream input with secrets/PII masked as [REDACTED:<id>]
  --pseudonymize <mode>     anonymize input preserving structure (redact|hash|synthetic)
  --mcp                     launch Model Context Protocol (MCP) server over stdio

Exit codes: 0 clean, 1 findings, 2 usage error`;

const SEVERITIES = ["low", "medium", "high", "critical"];

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      target: { type: "string", default: "prompt" },
      schema: { type: "string" },
      config: { type: "string" },
      "fail-on": { type: "string" },
      disable: { type: "string" },
      normalize: { type: "boolean", default: false },
      structured: { type: "string" },
      html: { type: "string" },
      json: { type: "boolean", default: false },
      sarif: { type: "boolean", default: false },
      redact: { type: "boolean", default: false },
      pseudonymize: { type: "string" },
      mcp: { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
    },
  });

  if (values.help) {
    console.log(USAGE);
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
    console.error(`Bad config: ${(e as Error).message}`);
    return 2;
  }
  const failOn = (values["fail-on"] ?? cfg.failOn ?? "low") as Severity;
  if (!["prompt", "output"].includes(values.target!) || !SEVERITIES.includes(failOn)) {
    console.error(USAGE);
    return 2;
  }
  let custom;
  try {
    custom = buildCustomRules(cfg.rules);
  } catch (e) {
    console.error(`Invalid custom rule: ${(e as Error).message}`);
    return 2;
  }

  const schema = values.schema ? JSON.parse(readFileSync(values.schema, "utf8")) : undefined;
  const disable = [...(cfg.disable ?? []), ...(values.disable?.split(",").map((s) => s.trim()) ?? [])];
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
    });
    console.log(formatScanSummaryTerminal(summary));
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
      clearTerminal: true,
    });
    await watcher.start();
    console.log("[agentguard] Watching files for changes... (Ctrl+C to exit)");
    return new Promise<number>(() => {}); // Keep alive until interrupted
  }

  // Adversarial fuzzing command
  if (positionals[0] === "fuzz") {
    const src = positionals[1] ?? "-";
    const content = readFileSync(src === "-" ? 0 : src, "utf8");
    const attacks = content.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0 && !l.startsWith("#"));
    const report = fuzzPromptResilience(attacks.length ? attacks : [content]);
    console.log(formatFuzzReportTerminal(report));
    return report.resilienceScore >= 80 ? 0 : 1;
  }

  const src = positionals[0] ?? "-";
  let text = "";
  try {
    text = readFileSync(src === "-" ? 0 : src, "utf8");
  } catch (e) {
    console.error(`Error reading input: ${(e as Error).message}`);
    return 2;
  }

  let result;
  if (values.structured) {
    if (!["markdown", "chat-json"].includes(values.structured)) {
      console.error("Invalid --structured format. Must be 'markdown' or 'chat-json'.");
      return 2;
    }
    result = auditStructuredPrompt(text, values.structured as "markdown" | "chat-json", {
      schema,
      disable,
      rules,
    });
  } else {
    const auditFn = values.normalize ? auditWithNormalization : audit;
    result = auditFn(text, {
      target: values.target as Target,
      schema,
      disable,
      rules,
    });
  }

  if (values.pseudonymize) {
    const mode = values.pseudonymize as "redact" | "hash" | "synthetic";
    if (!["redact", "hash", "synthetic"].includes(mode)) {
      console.error("Invalid --pseudonymize mode. Must be 'redact', 'hash', or 'synthetic'.");
      return 2;
    }
    const pseudo = pseudonymizeText(text, result.findings, { mode });
    process.stdout.write(pseudo.text);
  } else if (values.html) {
    const html = generateHtmlReport(result, { inputSource: src === "-" ? "stdin" : src });
    if (values.html === "-" || values.html === "stdout") {
      process.stdout.write(html);
    } else {
      writeFileSync(values.html, html, "utf8");
      console.log(`[OK] HTML report written to ${values.html}`);
    }
  } else if (values.redact) {
    process.stdout.write(redactText(text, result.findings));
  } else if (values.sarif) {
    console.log(JSON.stringify(toSarif(result, src === "-" ? "stdin" : src), null, 2));
  } else if (values.json) {
    console.log(JSON.stringify(result, null, 2));
  } else if (result.ok) {
    console.log("[OK] no findings");
  } else {
    for (const f of result.findings) {
      console.log(`[${f.severity.toUpperCase()}] ${f.ruleId} ${f.message} @${f.start}-${f.end} ${f.match}`);
    }
  }

  return exceeds(result, failOn) ? 1 : 0;
}

main().then((code) => process.exit(code));
