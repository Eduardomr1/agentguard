export type Severity = "low" | "medium" | "high" | "critical";
export type Category = "injection" | "secret" | "pii" | "schema";
export type Target = "prompt" | "output";

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

export interface AuditOptions {
  target?: Target;
  rules?: Rule[];
  /** Rule ids to skip. */
  disable?: string[];
  /** Optional JSON Schema; text is parsed as JSON and validated (outputs). */
  schema?: object;
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
