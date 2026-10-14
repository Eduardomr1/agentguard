import { audit, exceeds } from "../engine.js";
import { redactText } from "../redact.js";
import { AgentGuardError } from "../guard.js";
import type { GuardOptions } from "../guard.js";
import type { Finding, AuditResult } from "../types.js";
import { TransformStream as NodeTransformStream } from "node:stream/web";
import type { TransformStream } from "node:stream/web";

/**
 * Creates a standard Web Streams TransformStream compatible with JavaScript streams
 * and the Vercel AI SDK (e.g., `textStream.pipeThrough(createAgentGuardStreamTransform(...))`).
 *
 * Audits output token chunks in real time, holding back `overlap` characters to catch
 * secrets split across chunk boundaries.
 * - In "throw" mode (default): errors the stream with AgentGuardError as soon as a violation occurs.
 * - In "redact" mode: redacts secret and PII matches on the fly and emits clean chunks.
 * - In "report" mode: calls `onReport` and passes chunks through unmodified.
 */
export function createAgentGuardStreamTransform(
  options: GuardOptions = {},
): TransformStream<string, string> {
  const overlap = Math.max(0, options.overlap ?? 64);
  const mode = options.onViolation ?? "throw";
  const failOn = options.failOn ?? "high";
  let raw = "";
  let emitted = 0;

  function runAudit(text: string): AuditResult {
    const res = audit(text, {
      target: "output",
      rules: options.rules,
      disable: options.disable,
      schema: options.schema,
    });
    if (res.findings.length > 0) {
      options.onReport?.("output", res);
    }
    return res;
  }

  function release(upTo: number, findings: Finding[]): string {
    const slice = raw.slice(emitted, upTo);
    const inside = findings
      .filter((f) => f.start >= emitted && f.end <= upTo)
      .map((f) => ({ ...f, start: f.start - emitted, end: f.end - emitted }));
    emitted = upTo;
    return mode === "redact" ? redactText(slice, inside) : slice;
  }

  const StreamCtor =
    typeof globalThis.TransformStream !== "undefined"
      ? (globalThis.TransformStream as typeof NodeTransformStream)
      : NodeTransformStream;

  return new StreamCtor<string, string>({
    transform(chunk, controller) {
      raw += typeof chunk === "string" ? chunk : String(chunk);

      // Interim audit without schema/report noise
      const res = audit(raw, {
        target: "output",
        rules: options.rules,
        disable: options.disable,
      });

      if (mode === "throw" && exceeds(res, failOn)) {
        runAudit(raw);
        controller.error(new AgentGuardError("output", res.findings));
        return;
      }

      let safeEnd = raw.length - overlap;
      for (const f of res.findings) {
        if (f.start < safeEnd && f.end > safeEnd) {
          safeEnd = f.start;
        }
      }

      if (safeEnd > emitted) {
        const out = release(safeEnd, res.findings);
        if (out) controller.enqueue(out);
      }
    },

    flush(controller) {
      const final = runAudit(raw);

      if (exceeds(final, failOn)) {
        if (mode === "throw") {
          controller.error(new AgentGuardError("output", final.findings));
          return;
        }
        if (mode === "redact") {
          const red = redactText(raw, final.findings);
          const left = audit(red, {
            target: "output",
            rules: options.rules,
            disable: options.disable,
            schema: options.schema,
          });
          if (exceeds(left, failOn)) {
            controller.error(new AgentGuardError("output", left.findings));
            return;
          }
        }
      }

      const tail = release(raw.length, final.findings);
      if (tail) controller.enqueue(tail);
    },
  });
}
