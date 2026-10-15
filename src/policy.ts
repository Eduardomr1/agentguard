import { calculateSecurityScore } from "./reporter.js";
import { SEVERITY_ORDER } from "./types.js";
import type {
  AllowlistConfig,
  AuditResult,
  Category,
  Finding,
  PolicyConfig,
  Severity,
} from "./types.js";

export interface InlineSuppressionMap {
  /** Maps 1-based line number to a Set of suppressed rule IDs, or "*" for all rules on that line. */
  lineRules: Map<number, Set<string>>;
  /** Maps 0-based character offset to 1-based line number. */
  lineOfOffset: (offset: number) => number;
}

export interface PolicyGateOptions {
  failOn?: Severity;
  maxFindings?: number;
  minSecurityScore?: number;
}

export interface PolicyGateVerdict {
  passed: boolean;
  reasons: string[];
  securityScore: number;
}

function toRegExp(pattern: string | RegExp): RegExp {
  return pattern instanceof RegExp ? pattern : new RegExp(pattern);
}

function parseRuleList(rawList: string | undefined): Set<string> {
  if (!rawList) return new Set(["*"]);
  const cleaned = rawList
    .replace(/-->.*$/, "")
    .trim();
  if (!cleaned) return new Set(["*"]);
  const tokens = cleaned
    .split(/[,\s]+/)
    .map((s) => s.trim().toUpperCase())
    .filter((s) => /^[A-Z]{2,6}\d{2,4}$/.test(s));
  return tokens.length > 0 ? new Set(tokens) : new Set(["*"]);
}

/**
 * Parses developer inline suppression comments (`agentguard-ignore`,
 * `agentguard-disable-line`, and `agentguard-disable-next-line`) from prompt template files.
 *
 * Security note: Inline suppressions are disabled by default during runtime `audit()` calls
 * (`honorInlineSuppressions: false`) so untrusted end-user inputs cannot self-suppress detections.
 */
export function parseInlineSuppressions(text: string): InlineSuppressionMap {
  const lineStarts: number[] = [0];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "\n") {
      lineStarts.push(i + 1);
    }
  }

  const lineRules = new Map<number, Set<string>>();
  const addSuppression = (lineNum: number, rules: Set<string>): void => {
    const existing = lineRules.get(lineNum) ?? new Set<string>();
    for (const r of rules) existing.add(r);
    lineRules.set(lineNum, existing);
  };

  const lines = text.split(/\r?\n/);
  const sameLineRe =
    /(?:#|\/\/|<!--)\s*agentguard-(?:ignore|disable-line)(?:\s+([A-Za-z0-9_,\s-]+?))?(?:\s*-->|\s*$)/i;
  const nextLineRe =
    /(?:#|\/\/|<!--)\s*agentguard-(?:ignore-next-line|disable-next-line)(?:\s+([A-Za-z0-9_,\s-]+?))?(?:\s*-->|\s*$)/i;

  for (let idx = 0; idx < lines.length; idx++) {
    const lineNum = idx + 1;
    const line = lines[idx] ?? "";

    const nextMatch = line.match(nextLineRe);
    if (nextMatch) {
      addSuppression(lineNum + 1, parseRuleList(nextMatch[1]));
      continue;
    }

    const sameMatch = line.match(sameLineRe);
    if (sameMatch) {
      addSuppression(lineNum, parseRuleList(sameMatch[1]));
    }
  }

  const lineOfOffset = (offset: number): number => {
    const clamped = Math.max(0, Math.min(offset, text.length));
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      if ((lineStarts[mid] ?? 0) <= clamped) {
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return Math.max(1, hi + 1);
  };

  return { lineRules, lineOfOffset };
}

/**
 * Applies policy filtering (category filter, allowlist patterns/values/byRule,
 * opt-in inline comment suppressions, severity overrides, and minSeverity threshold)
 * to raw audit findings.
 */
export function applyPolicy(
  text: string,
  findings: Finding[],
  policy?: PolicyConfig,
): Finding[] {
  if (!policy) return findings;

  const allowedCategories = policy.categories ? new Set<Category>(policy.categories) : null;
  const exactValues = policy.allowlist?.values ? new Set(policy.allowlist.values) : null;
  const globalPatterns = (policy.allowlist?.patterns ?? []).map(toRegExp);
  const byRulePatterns = new Map<string, RegExp[]>();
  if (policy.allowlist?.byRule) {
    for (const [ruleId, patterns] of Object.entries(policy.allowlist.byRule)) {
      byRulePatterns.set(ruleId, patterns.map(toRegExp));
    }
  }

  const suppressions = policy.honorInlineSuppressions ? parseInlineSuppressions(text) : null;
  const minOrder = policy.minSeverity ? SEVERITY_ORDER[policy.minSeverity] : 0;

  const filtered: Finding[] = [];

  for (const finding of findings) {
    if (allowedCategories && !allowedCategories.has(finding.category)) {
      continue;
    }

    const rawSlice = text.slice(finding.start, finding.end);

    if (exactValues && exactValues.has(rawSlice)) {
      continue;
    }

    if (globalPatterns.some((re) => re.test(rawSlice))) {
      continue;
    }

    const ruleSpecific = byRulePatterns.get(finding.ruleId);
    if (ruleSpecific && ruleSpecific.some((re) => re.test(rawSlice))) {
      continue;
    }

    if (suppressions) {
      const lineNum = suppressions.lineOfOffset(finding.start);
      const suppressedSet = suppressions.lineRules.get(lineNum);
      if (suppressedSet && (suppressedSet.has("*") || suppressedSet.has(finding.ruleId.toUpperCase()))) {
        continue;
      }
    }

    const overriddenSeverity = policy.severityOverrides?.[finding.ruleId] ?? finding.severity;
    if (SEVERITY_ORDER[overriddenSeverity] < minOrder) {
      continue;
    }

    filtered.push(
      overriddenSeverity === finding.severity
        ? finding
        : { ...finding, severity: overriddenSeverity },
    );
  }

  filtered.sort(
    (a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.start - b.start,
  );

  return filtered;
}

/**
 * Evaluates an AuditResult against CI/CD quality gate thresholds (`failOn`, `maxFindings`, `minSecurityScore`).
 */
export function evaluatePolicyGate(
  result: AuditResult,
  options: PolicyGateOptions = {},
): PolicyGateVerdict {
  const reasons: string[] = [];
  const securityScore = calculateSecurityScore(result);

  if (options.failOn) {
    const threshold = SEVERITY_ORDER[options.failOn];
    const violating = result.findings.filter((f) => SEVERITY_ORDER[f.severity] >= threshold);
    if (violating.length > 0) {
      reasons.push(
        `${violating.length} finding(s) meet or exceed severity '${options.failOn}'`,
      );
    }
  }

  if (options.maxFindings !== undefined && result.findings.length > options.maxFindings) {
    reasons.push(
      `Total findings (${result.findings.length}) exceed maxFindings (${options.maxFindings})`,
    );
  }

  if (options.minSecurityScore !== undefined && securityScore < options.minSecurityScore) {
    reasons.push(
      `Security score (${securityScore}) is below minSecurityScore (${options.minSecurityScore})`,
    );
  }

  return {
    passed: reasons.length === 0,
    reasons,
    securityScore,
  };
}

/**
 * Merges a base PolicyConfig (e.g. from `.agentguardrc.json`) with runtime/CLI overrides.
 * Allowlist arrays and per-rule patterns are concatenated; scalar thresholds and overrides take precedence from `override`.
 */
export function mergePolicies(
  base?: PolicyConfig,
  override?: PolicyConfig,
): PolicyConfig | undefined {
  if (!base && !override) return undefined;
  if (!base) return override;
  if (!override) return base;

  const patterns = [
    ...(base.allowlist?.patterns ?? []),
    ...(override.allowlist?.patterns ?? []),
  ];
  const values = [
    ...(base.allowlist?.values ?? []),
    ...(override.allowlist?.values ?? []),
  ];

  const byRule: Record<string, Array<string | RegExp>> = {};
  for (const [k, v] of Object.entries(base.allowlist?.byRule ?? {})) {
    byRule[k] = [...v];
  }
  for (const [k, v] of Object.entries(override.allowlist?.byRule ?? {})) {
    byRule[k] = [...(byRule[k] ?? []), ...v];
  }

  const hasAllowlist =
    patterns.length > 0 || values.length > 0 || Object.keys(byRule).length > 0;
  const allowlist: AllowlistConfig | undefined = hasAllowlist
    ? {
        ...(patterns.length > 0 ? { patterns } : {}),
        ...(values.length > 0 ? { values } : {}),
        ...(Object.keys(byRule).length > 0 ? { byRule } : {}),
      }
    : undefined;

  const mergedSeverityOverrides =
    base.severityOverrides || override.severityOverrides
      ? { ...(base.severityOverrides ?? {}), ...(override.severityOverrides ?? {}) }
      : undefined;

  return {
    allowlist,
    severityOverrides: mergedSeverityOverrides,
    categories: override.categories ?? base.categories,
    minSeverity: override.minSeverity ?? base.minSeverity,
    honorInlineSuppressions:
      override.honorInlineSuppressions ?? base.honorInlineSuppressions,
  };
}
