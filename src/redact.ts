import type { Finding } from "./types.js";

/**
 * Replace secret/PII spans with `[REDACTED:<ruleId>]`.
 * Overlapping spans are merged; injection/schema findings are left untouched.
 */
export function redactText(text: string, findings: Finding[]): string {
  const spans = findings
    .filter((f) => f.category === "secret" || f.category === "pii")
    .map((f) => ({ start: f.start, end: f.end, id: f.ruleId, critical: f.category === "secret" }))
    .sort((a, b) => a.start - b.start || b.end - a.end);

  let out = "";
  let pos = 0;
  for (const s of spans) {
    if (s.start < pos) continue; // overlaps an earlier span
    out += text.slice(pos, s.start) + `[REDACTED:${s.id}]`;
    pos = s.end;
  }
  return out + text.slice(pos);
}
