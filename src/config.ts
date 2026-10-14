import { readFileSync } from "node:fs";
import type { Category, Rule, Severity, Target } from "./types.js";
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
