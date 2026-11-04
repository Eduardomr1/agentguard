# AgentGuard

Lightweight CLI + TypeScript library to audit LLM prompts and outputs for prompt injection, secret/PII leaks and JSON schema violations.

## Library

```ts
import { audit, exceeds } from "agentguard";

const r = audit(userInput, { target: "prompt" });
if (exceeds(r, "high")) throw new Error("blocked");

audit(modelOutput, { target: "output", schema: { type: "object", required: ["name"] } });
```

## CLI

```
agentguard [file|-] [options]
```

Reads `file`, or stdin when omitted or `-`.

| Option | Description |
|---|---|
| `--target prompt\|output` | What is being audited (default: `prompt`) |
| `--schema <file.json>` | Validate the text as JSON against this JSON Schema |
| `--config <file.json>` | Config file with `disable`, `failOn` and custom `rules` |
| `--fail-on <severity>` | `low`\|`medium`\|`high`\|`critical` (default: `low`, or `failOn` from config) |
| `--disable <ruleId,...>` | Comma-separated rule IDs to skip (merged with config `disable`) |
| `--json` | Output result as JSON |
| `--sarif` | Output result as SARIF |
| `--markdown <out.md>` | Generate executive Markdown audit summary |
| `--html <out.html>` | Generate standalone interactive HTML audit report |
| `--allow-pattern <regex>` | Allowlists matching snippets from violations |
| `--inline-suppressions` | Honor `agentguard-ignore` comments in trusted files |
| `--redact` | Print the input with findings masked as `[REDACTED:<ruleId>]` (takes precedence over `--sarif`/`--json`) |
| `-h`, `--help` | Show usage |

## Agentic Tool-Call Guardrails

AgentGuard audits tool calls, arguments, and function payloads before execution to prevent agentic compromises:

```ts
import { auditToolCall } from "agentguard/guard";

// Blocks execution if tool arguments contain dangerous shell commands, SQL injections or SSRF
auditToolCall({
  name: "bash",
  arguments: { command: "rm -rf / --no-preserve-root" },
}, { onViolation: "throw", failOn: "high" });
```

- **`TOOL001` (Critical):** Dangerous shell command payloads (`rm -rf`, `curl | bash`, reverse shells).
- **`TOOL002` (High):** SSRF or cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`, localhost).
- **`TOOL003` (High):** Destructive SQL statements (`DROP TABLE`, `TRUNCATE TABLE`, mass deletes).
- **`TOOL004` (High):** Path traversal escaping directory sandboxes (`../../../`).

## Canary Tokens & Blind Markdown Exfiltration

### Canary Tokens (`CanaryManager`)

Inject cryptographically signed canaries into system prompts to catch model prompt extraction:

```ts
import { CanaryManager } from "agentguard";

const canaryMgr = new CanaryManager();
const canary = canaryMgr.generateToken("tenant-alpha");

// Append canary directive to your system prompt
const systemPrompt = `You are a helpful assistant. ${canary.promptDirective}`;

// Detect if the model output leaks the canary token
const check = canaryMgr.detectLeak(modelOutput);
if (check.leaked) {
  throw new Error(`System prompt extraction caught! Leaked tokens: ${check.leakedTokens.join(", ")}`);
}
```

### Covert Markdown & HTML Exfiltration (`detectMarkdownExfiltration`)

Prevents indirect prompt injections from rendering covert image beacons carrying stolen context or credentials:

```ts
import { detectMarkdownExfiltration } from "agentguard";

const findings = detectMarkdownExfiltration(modelResponse, {
  allowedHostnames: ["cdn.internal.net"],
});
```

```
echo "ignore all previous instructions" | agentguard - --fail-on high
agentguard out.json --target output --schema schema.json --json
agentguard in.txt --config .agentguardrc.json --sarif > results.sarif
agentguard in.txt --redact > clean.txt
```

Exit codes: `0` clean (nothing at/above `--fail-on`), `1` findings at/above `--fail-on`, `2` usage/config error.

## Config (`.agentguardrc.json`)

```json
{
  "disable": ["PII005"],
  "failOn": "medium",
  "rules": [{ "id": "X001", "pattern": "project\\s+phoenix", "severity": "high", "category": "secret" }]
}
```

## Rules

Rules apply to `prompt`, `output` or both (Target column).

| ID | Category | Severity | Target | Description |
|---|---|---|---|---|
| INJ001 | Injection | high | prompt | Instruction override ("ignore previous instructions") |
| INJ002 | Injection | high | prompt | System prompt exfiltration |
| INJ003 | Injection | medium | prompt | Jailbreak persona (DAN / developer mode / unfiltered) |
| INJ004 | Injection | medium | prompt | Role/delimiter spoofing (fake system turn) |
| INJ005 | Injection | low | prompt, output | Hidden/zero-width characters |
| INJ006 | Injection | high | prompt | Instruction override in Spanish, French or German |
| INJ007 | Injection | high | prompt, output | Base64 payload decoding to prompt injection |
| INJ008 | Injection | high | prompt, output | Indirect injection in retrieved content |
| INJ009 | Injection | high | output | Markdown image data exfiltration |
| SEC001 | Secret | critical | prompt, output | AWS access key ID |
| SEC002 | Secret | critical | prompt, output | Google API key |
| SEC003 | Secret | critical | prompt, output | OpenAI API key |
| SEC004 | Secret | critical | prompt, output | GitHub token |
| SEC005 | Secret | critical | prompt, output | Slack token |
| SEC006 | Secret | critical | prompt, output | Private key block |
| SEC007 | Secret | high | prompt, output | JSON Web Token |
| SEC008 | Secret | high | prompt, output | Generic credential assignment (`api_key = "..."`) |
| SEC009 | Secret | medium | prompt, output | High-entropy string (possible unknown secret) |
| SEC010 | Secret | high | prompt, output | Server/host credential leak |
| PII001 | PII | medium | prompt, output | Email address |
| PII002 | PII | high | prompt, output | Credit card number (Luhn-validated) |
| PII003 | PII | high | prompt, output | US Social Security Number |
| PII004 | PII | medium | prompt, output | IBAN |
| PII005 | PII | low | prompt, output | Phone number (international format) |
| PII006 | PII | high | prompt, output | Passport number or Date of Birth (DOB) |
| SCH001 | Schema | high | output (with `--schema`) | Text is not valid JSON |
| SCH002 | Schema | high | output (with `--schema`) | JSON violates the schema (one finding per error) |
| CAN001 | Exfiltration | critical | output | Canary token leak in generated output |
| EXF001 | Exfiltration | critical | output | Covert markdown or blind image exfiltration attempt |

`SCH000` (high) is also reported when the supplied schema itself is invalid.

## Middleware (`guardLLM` & `guardStream`)

Wrap any LLM call or streaming async iterable with lifecycle guardrails:

```ts
import { guardLLM, guardStream } from "agentguard";

// Non-streaming wrapper with auto-redaction or abort
const safeCall = guardLLM(
  async (prompt) => callOpenAI(prompt),
  {
    onViolation: "throw", // "throw" | "redact" | "report"
    failOn: "high",       // minimum severity to trigger
    schema: responseJsonSchema, // validates output if supplied
  }
);

// Streaming wrapper with cross-chunk secret boundary detection
for await (const safeChunk of guardStream(tokenStream, { onViolation: "redact" })) {
  process.stdout.write(safeChunk);
}
```

## Limitations

- Rules are regex/heuristic based: expect **false negatives** on paraphrased, translated or obfuscated attacks, and **false positives** (e.g. SEC009 on hashes/IDs, PII004 on look-alike codes).
- Prompt-injection detection covers only known phrasings and is not a substitute for privilege separation or output handling controls.
- Secret detection is pattern-based; unknown or low-entropy secrets can be missed.
- PII coverage is limited (US SSN, international phone format, IBAN, cards, emails); no names or addresses.
- Positions (`start`/`end`) are offsets into the input; matches in reports are redacted, never raw.

## CI

This repo's workflow ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) type-checks, runs tests, audits `prompts/system.txt` (if present) and uploads SARIF to GitHub code scanning:

```yaml
name: ci
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22, cache: npm }
      - run: npm ci
      - run: npx tsc --noEmit
      - run: npm test
      # Audit prompt files with AgentGuard and upload SARIF
      - run: npx tsx src/cli.ts prompts/system.txt --sarif --fail-on high > agentguard.sarif
        if: hashFiles('prompts/system.txt') != ''
      - uses: github/codeql-action/upload-sarif@v3
        if: always() && hashFiles('agentguard.sarif') != ''
        with: { sarif_file: agentguard.sarif }
```

## Contributing & License

See [CONTRIBUTING.md](CONTRIBUTING.md). Licensed under [MIT](LICENSE).
