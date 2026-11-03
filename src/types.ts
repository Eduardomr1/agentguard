export type Severity = "low" | "medium" | "high" | "critical";
export type Category = "injection" | "secret" | "pii" | "schema" | "tool" | "exfiltration";
export type Target = "prompt" | "output" | "tool";

export interface Finding {
  ruleId: string;
  category: Category;
  severity: Severity;
  message: string;
  /** Redacted snippet of the match (never the raw secret). */
  match: string;
  start: number;
  end: number;
}

export interface RuleMatch {
  start: number;
  end: number;
  message?: string;
}

export interface Rule {
  id: string;
  category: Category;
  severity: Severity;
  description: string;
  /** Which text kinds this rule applies to. */
  targets: Target[];
  detect(text: string): RuleMatch[];
}

export interface AllowlistConfig {
  /** Regex patterns matched against the raw matched substring; matching spans are ignored. */
  patterns?: Array<string | RegExp>;
  /** Exact literal values (e.g. placeholder tokens or dummy emails) to ignore. */
  values?: string[];
  /** Per-rule regex allowlist patterns, keyed by ruleId. */
  byRule?: Record<string, Array<string | RegExp>>;
}

export interface PolicyConfig {
  /** Allowlist configuration for suppressing known-safe placeholders and domains. */
  allowlist?: AllowlistConfig;
  /** Override severity per rule ID (e.g. { INJ005: "high", PII001: "low" }). */
  severityOverrides?: Record<string, Severity>;
  /** Restrict auditing to specific categories. */
  categories?: Category[];
  /** Minimum severity to retain in audit findings. */
  minSeverity?: Severity;
  /** Opt-in support for inline suppression comments in trusted prompt templates. Default false. */
  honorInlineSuppressions?: boolean;
}

export interface AuditOptions {
  target?: Target;
  rules?: Rule[];
  /** Rule ids to skip. */
  disable?: string[];
  /** Optional JSON Schema; text is parsed as JSON and validated (outputs). */
  schema?: object;
  /** Optional policy for allowlists, severity overrides, category filters, and inline suppressions. */
  policy?: PolicyConfig;
}

export interface AuditResult {
  ok: boolean;
  findings: Finding[];
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};
