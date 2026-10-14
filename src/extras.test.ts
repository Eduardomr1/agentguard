import { describe, expect, it } from "vitest";
import { audit, defaultRules } from "./engine.js";
import { buildCustomRules } from "./config.js";
import { toSarif } from "./sarif.js";

describe("custom rules", () => {
  it("builds and runs regex rules from config", () => {
    const custom = buildCustomRules([{ id: "X001", pattern: "project\\s+phoenix", severity: "high", category: "secret" }]);
    const r = audit("Details of Project  Phoenix", { rules: [...defaultRules, ...custom] });
    expect(r.findings.map((f) => f.ruleId)).toContain("X001");
  });
  it("throws on invalid regex", () => {
    expect(() => buildCustomRules([{ id: "X", pattern: "(" }])).toThrow();
  });
});

describe("sarif", () => {
  it("maps findings to SARIF results", () => {
    const sarif = toSarif(audit("AKIAIOSFODNN7EXAMPLE"), "a.txt");
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].results[0].ruleId).toBe("SEC001");
    expect(sarif.runs[0].results[0].level).toBe("error");
  });
});
