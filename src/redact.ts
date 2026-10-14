import { audit } from "./engine.js";
import { SEVERITY_ORDER } from "./types.js";
import type { Category, Finding, Rule, Severity, Target } from "./types.js";

export type RedactionStyle = "tag" | "partial" | "stars";

export interface RedactSensitiveOptions {
  style?: RedactionStyle;
  categories?: Category[];
  minSeverity?: Severity;
  disable?: string[];
  rules?: Rule[];
  target?: Target;
  customReplacement?: (finding: Finding, rawMatch: string) => string;
}

export interface RedactSensitiveResult {
  text: string;
  redactedCount: number;
  findings: Finding[];
  redactedRuleIds: string[];
}

/**
 * Formats a safe masked representation of a raw sensitive match without leaking secret material.
 */
export function maskValue(
  raw: string,
  ruleId: string,
  style: RedactionStyle = "tag",
): string {
  if (style === "tag") {
    return `[REDACTED:${ruleId}]`;
  }
  if (style === "stars") {
    return "*".repeat(Math.max(4, raw.length));
  }
  // style === "partial"
  if (ruleId === "PII001" && raw.includes("@")) {
    const [local, domain] = raw.split("@");
    const safeLocal = local && local.length > 1 ? `${local[0]}***` : "***";
    const dotIdx = domain ? domain.lastIndexOf(".") : -1;
    if (domain && dotIdx > 1) {
      const tld = domain.slice(dotIdx);
      return `${safeLocal}@${domain[0]}***${tld}`;
    }
    return `${safeLocal}@***`;
  }
  if (raw.length < 10) {
    return "*".repeat(Math.max(4, raw.length));
  }
  return `${raw.slice(0, 2)}****${raw.slice(-2)}`;
}

/**
 * Replace secret/PII spans with `[REDACTED:<ruleId>]` (or configurable mask style).
 * Overlapping spans are merged; injection/schema findings are left untouched by default.
 */
export function redactText(
  text: string,
  findings: Finding[],
  options?: Pick<RedactSensitiveOptions, "style" | "categories" | "minSeverity" | "customReplacement">,
): string {
  const allowedCategories = new Set<Category>(options?.categories ?? ["secret", "pii"]);
  const minOrder = options?.minSeverity ? SEVERITY_ORDER[options.minSeverity] : 0;
  const style = options?.style ?? "tag";

  const spans = findings
    .filter(
      (f) =>
        allowedCategories.has(f.category) && SEVERITY_ORDER[f.severity] >= minOrder,
    )
    .sort(
      (a, b) =>
        a.start - b.start ||
        b.end - a.end ||
        SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity],
    );

  let out = "";
  let pos = 0;
  for (const f of spans) {
    if (f.start < pos) continue; // overlaps an earlier span
    const rawSlice = text.slice(f.start, f.end);
    const replacement = options?.customReplacement
      ? options.customReplacement(f, rawSlice)
      : maskValue(rawSlice, f.ruleId, style);
    out += text.slice(pos, f.start) + replacement;
    pos = f.end;
  }
  return out + text.slice(pos);
}

/**
 * Audits input text and masks sensitive findings in a single pass with configurable masking style,
 * severity threshold, and category filters.
 */
export function redactSensitive(
  text: string,
  options: RedactSensitiveOptions = {},
): RedactSensitiveResult {
  const result = audit(text, {
    target: options.target ?? "prompt",
    disable: options.disable,
    rules: options.rules,
  });

  const allowedCategories = new Set<Category>(options.categories ?? ["secret", "pii"]);
  const minOrder = options.minSeverity ? SEVERITY_ORDER[options.minSeverity] : 0;
  const style = options.style ?? "tag";

  const candidates = result.findings
    .filter(
      (f) =>
        allowedCategories.has(f.category) && SEVERITY_ORDER[f.severity] >= minOrder,
    )
    .sort(
      (a, b) =>
        a.start - b.start ||
        b.end - a.end ||
        SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity],
    );

  let out = "";
  let pos = 0;
  let redactedCount = 0;
  const appliedRules = new Set<string>();

  for (const f of candidates) {
    if (f.start < pos) continue;
    const rawSlice = text.slice(f.start, f.end);
    const replacement = options.customReplacement
      ? options.customReplacement(f, rawSlice)
      : maskValue(rawSlice, f.ruleId, style);
    out += text.slice(pos, f.start) + replacement;
    pos = f.end;
    redactedCount++;
    appliedRules.add(f.ruleId);
  }
  out += text.slice(pos);

  return {
    text: out,
    redactedCount,
    findings: result.findings,
    redactedRuleIds: [...appliedRules],
  };
}
