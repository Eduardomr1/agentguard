import { audit, exceeds } from "./engine.js";
import { redactText } from "./redact.js";
import type { AuditResult, Finding, Rule, Severity, Target } from "./types.js";

export type OnViolation = "throw" | "redact" | "report";

export interface GuardOptions {
  /** Default "throw". */
  onViolation?: OnViolation;
  /** Minimum severity that counts as a violation. Default "high". */
  failOn?: Severity;
  rules?: Rule[];
  disable?: string[];
  /** JSON Schema applied to the output only. */
  schema?: object;
  /** Called with every audit that has findings (all modes). */
  onReport?: (target: Target, result: AuditResult) => void;
  /** Stream only: chars held back so secrets split across chunks are caught. Default 64. */
  overlap?: number;
}

export class AgentGuardError extends Error {
  constructor(
    public readonly target: Target,
    public readonly findings: Finding[],
  ) {
    super(
      `AgentGuard blocked ${target}: ` +
        findings.map((f) => `${f.ruleId}(${f.severity})`).join(", "),
    );
    this.name = "AgentGuardError";
  }
}

function run(text: string, target: Target, o: GuardOptions): AuditResult {
  const res = audit(text, {
    target,
    rules: o.rules,
    disable: o.disable,
    schema: target === "output" ? o.schema : undefined,
  });
  if (res.findings.length) o.onReport?.(target, res);
  return res;
}

/** Audit text and apply policy; returns text to use (possibly redacted). */
function enforce(text: string, target: Target, o: GuardOptions): string {
  const res = run(text, target, o);
  if (!exceeds(res, o.failOn ?? "high")) return text;
  const mode = o.onViolation ?? "throw";
  if (mode === "report") return text;
  if (mode === "throw") throw new AgentGuardError(target, res.findings);
  const redacted = redactText(text, res.findings);
  // Anything redaction cannot fix (injection/schema) still blocks.
  const left = run(redacted, target, o);
  if (exceeds(left, o.failOn ?? "high")) throw new AgentGuardError(target, left.findings);
  return redacted;
}

/** Wrap an LLM function: audits prompt before and output after. */
export function guardLLM(
  fn: (prompt: string) => Promise<string>,
  opts: GuardOptions = {},
): (prompt: string) => Promise<string> {
  return async (prompt) => {
    const safePrompt = enforce(prompt, "prompt", opts);
    const out = await fn(safePrompt);
    return enforce(out, "output", opts);
  };
}

/**
 * Wrap a stream of text chunks. Yields chunks with a held-back tail
 * (`overlap` chars) so split secrets are detected before release; the
 * full text is audited at the end. In "throw" mode, throws as soon as a
 * violation is seen; in "redact" mode emitted text is redacted.
 */
export async function* guardStream(
  source: AsyncIterable<string>,
  opts: GuardOptions = {},
): AsyncGenerator<string, void, void> {
  const overlap = Math.max(0, opts.overlap ?? 64);
  const mode = opts.onViolation ?? "throw";
  const failOn = opts.failOn ?? "high";
  let raw = "";
  let emitted = 0;

  const release = function (upTo: number, findings: Finding[]): string {
    const slice = raw.slice(emitted, upTo);
    const inside = findings
      .filter((f) => f.start >= emitted && f.end <= upTo)
      .map((f) => ({ ...f, start: f.start - emitted, end: f.end - emitted }));
    emitted = upTo;
    return mode === "redact" ? redactText(slice, inside) : slice;
  };

  for await (const chunk of source) {
    raw += chunk;
    // Interim audit without schema/report noise.
    const res = audit(raw, { target: "output", rules: opts.rules, disable: opts.disable });
    if (mode === "throw" && exceeds(res, failOn)) {
      run(raw, "output", { ...opts, schema: undefined });
      throw new AgentGuardError("output", res.findings);
    }
    let safeEnd = raw.length - overlap;
    for (const f of res.findings) if (f.start < safeEnd && f.end > safeEnd) safeEnd = f.start;
    if (safeEnd > emitted) {
      const out = release(safeEnd, res.findings);
      if (out) yield out;
    }
  }

  const final = run(raw, "output", opts);
  if (exceeds(final, failOn)) {
    if (mode === "throw") throw new AgentGuardError("output", final.findings);
    if (mode === "redact") {
      const red = redactText(raw, final.findings);
      if (exceeds(run(red, "output", opts), failOn))
        throw new AgentGuardError("output", final.findings);
    }
  }
  const tail = release(raw.length, final.findings);
  if (tail) yield tail;
}
