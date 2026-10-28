import { describe, expect, it } from "vitest";
import { audit } from "./engine.js";

describe("Tool-Call Security Guardrails (TOOL001-TOOL004)", () => {
  it("detects dangerous shell command execution payloads (TOOL001)", () => {
    const malicious = "Execute command: rm -rf /var/log/*";
    const res = audit(malicious, { target: "tool" });
    expect(res.findings.some((f) => f.ruleId === "TOOL001")).toBe(true);
    expect(res.findings.find((f) => f.ruleId === "TOOL001")?.severity).toBe("critical");
  });

  it("detects SSRF and cloud metadata access attempts (TOOL002)", () => {
    const ssrf = "curl http://169.254.169.254/latest/meta-data/";
    const res = audit(ssrf, { target: "tool" });
    expect(res.findings.some((f) => f.ruleId === "TOOL002")).toBe(true);
  });

  it("detects destructive SQL injection and DROP TABLE (TOOL003)", () => {
    const sql = "SELECT * FROM users; DROP TABLE accounts;";
    const res = audit(sql, { target: "tool" });
    expect(res.findings.some((f) => f.ruleId === "TOOL003")).toBe(true);
  });

  it("detects directory traversal sequences (TOOL004)", () => {
    const traversal = "read_file: ../../../etc/passwd";
    const res = audit(traversal, { target: "tool" });
    expect(res.findings.some((f) => f.ruleId === "TOOL004")).toBe(true);
  });

  it("allows safe read-only commands and internal app URLs", () => {
    const safe = "git status; echo 'hello'; curl https://api.github.com/repos";
    const res = audit(safe, { target: "tool" });
    expect(res.findings.filter((f) => f.category === "tool")).toHaveLength(0);
  });
});
