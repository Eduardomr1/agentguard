import type { AuditResult, Severity } from "./types.js";

const LEVEL: Record<Severity, string> = { low: "note", medium: "warning", high: "error", critical: "error" };

/** Convert an audit result to a SARIF 2.1.0 log (for GitHub code scanning etc.). */
export function toSarif(result: AuditResult, uri = "input.txt") {
  const ruleIds = [...new Set(result.findings.map((f) => f.ruleId))];
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "AgentGuard", rules: ruleIds.map((id) => ({ id })) } },
        results: result.findings.map((f) => ({
          ruleId: f.ruleId,
          level: LEVEL[f.severity],
          message: { text: `${f.message} (${f.match})` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri },
                region: { charOffset: f.start, charLength: f.end - f.start },
              },
            },
          ],
        })),
      },
    ],
  };
}
