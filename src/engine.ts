import { applyPolicy } from "./policy.js";
import { injectionRules } from "./rules/injection.js";
import { piiRules } from "./rules/pii.js";
import { secretRules } from "./rules/secrets.js";
import { redact } from "./rules/util.js";
import { validateSchema } from "./schema.js";
import { SEVERITY_ORDER } from "./types.js";
import type { AuditOptions, AuditResult, Finding, Rule, Severity } from "./types.js";

export const defaultRules: Rule[] = [...injectionRules, ...secretRules, ...piiRules];

export function audit(text: string, options: AuditOptions = {}): AuditResult {
  const target = options.target ?? "prompt";
  const disabled = new Set(options.disable ?? []);
  const rules = (options.rules ?? defaultRules).filter(
    (r) => r.targets.includes(target) && !disabled.has(r.id),
  );

  const findings: Finding[] = [];
  for (const rule of rules) {
    for (const m of rule.detect(text)) {
      findings.push({
        ruleId: rule.id,
        category: rule.category,
        severity: rule.severity,
        message: m.message ?? rule.description,
        match: redact(text.slice(m.start, m.end)),
        start: m.start,
        end: m.end,
      });
    }
  }

  if (options.schema) findings.push(...validateSchema(text, options.schema));

  const effectiveFindings = options.policy ? applyPolicy(text, findings, options.policy) : findings;
  effectiveFindings.sort(
    (a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.start - b.start,
  );
  return { ok: effectiveFindings.length === 0, findings: effectiveFindings };
}

/** True if any finding meets or exceeds the given severity. */
export function exceeds(result: AuditResult, min: Severity): boolean {
  return result.findings.some((f) => SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[min]);
}
