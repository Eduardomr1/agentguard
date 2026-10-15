import { readFileSync } from "node:fs";
import type { AllowlistConfig, Category, PolicyConfig, Rule, Severity, Target } from "./types.js";
import { regexMatches } from "./rules/util.js";

export interface CustomRuleConfig {
  id: string;
  pattern: string;
  flags?: string;
  severity?: Severity;
  category?: Category;
  targets?: Target[];
  message?: string;
}

export interface AgentGuardConfig {
  disable?: string[];
  failOn?: Severity;
  rules?: CustomRuleConfig[];
  allowlist?: {
    patterns?: string[];
    values?: string[];
    byRule?: Record<string, string[]>;
  };
  severityOverrides?: Record<string, Severity>;
  categories?: Category[];
  minSeverity?: Severity;
  honorInlineSuppressions?: boolean;
}

export function extractPolicyFromConfig(cfg: AgentGuardConfig): PolicyConfig | undefined {
  const allowlist: AllowlistConfig | undefined = cfg.allowlist
    ? {
        patterns: cfg.allowlist.patterns,
        values: cfg.allowlist.values,
        byRule: cfg.allowlist.byRule,
      }
    : undefined;

  if (
    !allowlist &&
    !cfg.severityOverrides &&
    !cfg.categories &&
    !cfg.minSeverity &&
    cfg.honorInlineSuppressions === undefined
  ) {
    return undefined;
  }

  return {
    allowlist,
    severityOverrides: cfg.severityOverrides,
    categories: cfg.categories,
    minSeverity: cfg.minSeverity,
    honorInlineSuppressions: cfg.honorInlineSuppressions,
  };
}

export function buildCustomRules(configs: CustomRuleConfig[] = []): Rule[] {
  return configs.map((c) => {
    const re = new RegExp(c.pattern, c.flags ?? "i"); // throws on invalid regex
    return {
      id: c.id,
      category: c.category ?? "injection",
      severity: c.severity ?? "medium",
      description: c.message ?? `Custom rule ${c.id}`,
      targets: c.targets ?? ["prompt", "output"],
      detect: (t: string) => regexMatches(t, re, c.message),
    };
  });
}

export function loadConfig(path: string): AgentGuardConfig {
  return JSON.parse(readFileSync(path, "utf8")) as AgentGuardConfig;
}
