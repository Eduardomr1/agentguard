import { describe, expect, it } from "vitest";
import {
  calculateSecurityScore,
  countBySeverity,
  generateHtmlReport,
  getOwaspCategoryForFinding,
  getOwaspComplianceSummary,
  OWASP_LLM_CATEGORIES,
} from "./reporter.js";
import type { AuditResult, Finding } from "./types.js";

describe("generateHtmlReport", () => {
  const cleanResult: AuditResult = {
    ok: true,
    findings: [],
  };

  const sampleFindings: Finding[] = [
    {
      ruleId: "INJ001",
      category: "injection",
      severity: "high",
      message: "Instruction override detected",
      match: "ignore previous instructions",
      start: 0,
      end: 28,
    },
    {
      ruleId: "SEC001",
      category: "secret",
      severity: "critical",
      message: "AWS Access Key detected",
      match: "AKIA****************",
      start: 35,
      end: 55,
    },
    {
      ruleId: "PII001",
      category: "pii",
      severity: "medium",
      message: "Email address detected",
      match: "user@example.com",
      start: 60,
      end: 76,
    },
    {
      ruleId: "SCH001",
      category: "schema",
      severity: "low",
      message: "Invalid JSON format",
      match: "unstructured-text",
      start: 80,
      end: 97,
    },
  ];

  const violationResult: AuditResult = {
    ok: false,
    findings: sampleFindings,
  };

  describe("HTML structure & standalone validity", () => {
    it("generates a valid standalone HTML document", () => {
      const html = generateHtmlReport(cleanResult);
      expect(html.startsWith("<!DOCTYPE html>")).toBe(true);
      expect(html).toContain("<html lang=\"en\">");
      expect(html).toContain("</html>");
      expect(html).toContain("<head>");
      expect(html).toContain("</head>");
      expect(html).toContain("<body>");
      expect(html).toContain("</body>");
    });

    it("has zero external dependencies or remote stylesheets/scripts", () => {
      const html = generateHtmlReport(violationResult);
      expect(html).not.toMatch(/src=["']https?:\/\//i);
      expect(html).not.toMatch(/href=["']https?:\/\//i);
    });

    it("includes inline CSS with dark/light mode support via media query", () => {
      const html = generateHtmlReport(cleanResult);
      expect(html).toContain("<style>");
      expect(html).toContain("@media (prefers-color-scheme: dark)");
      expect(html).toContain("[data-theme=\"dark\"]");
      expect(html).toContain("[data-theme=\"light\"]");
    });

    it("applies default title and options properly", () => {
      const htmlDefault = generateHtmlReport(cleanResult);
      expect(htmlDefault).toContain("AgentGuard Security Audit Report");
      expect(htmlDefault).toContain("Direct Input");

      const htmlCustom = generateHtmlReport(violationResult, {
        title: "Production LLM Pipeline Audit",
        inputSource: "pipeline/chat-completion.json",
      });
      expect(htmlCustom).toContain("Production LLM Pipeline Audit");
      expect(htmlCustom).toContain("pipeline/chat-completion.json");
    });
  });

  describe("Security Score & Findings Summary", () => {
    it("calculates a score of 100 for clean audits", () => {
      expect(calculateSecurityScore(cleanResult)).toBe(100);
      const html = generateHtmlReport(cleanResult);
      expect(html).toContain('<span class="score-number">100</span>');
      expect(html).toContain("✓ PASSED");
    });

    it("accurately penalizes score based on severity", () => {
      const criticalResult: AuditResult = {
        ok: false,
        findings: [
          {
            ruleId: "SEC001",
            category: "secret",
            severity: "critical",
            message: "Secret found",
            match: "REDACTED",
            start: 0,
            end: 10,
          },
        ],
      };
      // 100 - 25 = 75
      expect(calculateSecurityScore(criticalResult)).toBe(75);

      const multiCritical: AuditResult = {
        ok: false,
        findings: Array(6).fill({
          ruleId: "SEC001",
          category: "secret",
          severity: "critical",
          message: "Secret found",
          match: "REDACTED",
          start: 0,
          end: 10,
        }),
      };
      // Score cannot be lower than 0
      expect(calculateSecurityScore(multiCritical)).toBe(0);
    });

    it("counts findings by severity (Critical, High, Medium, Low)", () => {
      const counts = countBySeverity(sampleFindings);
      expect(counts.critical).toBe(1);
      expect(counts.high).toBe(1);
      expect(counts.medium).toBe(1);
      expect(counts.low).toBe(1);

      const html = generateHtmlReport(violationResult);
      expect(html).toContain('<div class="stat-value" id="countCritical">1</div>');
      expect(html).toContain('<div class="stat-value" id="countHigh">1</div>');
      expect(html).toContain('<div class="stat-value" id="countMedium">1</div>');
      expect(html).toContain('<div class="stat-value" id="countLow">1</div>');
    });
  });

  describe("OWASP Top 10 for LLM Applications (2025/2026) Mapping", () => {
    it("maps injection category to LLM01: Prompt Injection", () => {
      const owasp = getOwaspCategoryForFinding("injection");
      expect(owasp).toBeDefined();
      expect(owasp?.id).toBe("LLM01");
      expect(owasp?.code).toBe("LLM01: Prompt Injection");
      expect(owasp?.categories).toContain("injection");
    });

    it("maps secret and pii categories to LLM02: Sensitive Information Disclosure", () => {
      const owaspSecret = getOwaspCategoryForFinding("secret");
      expect(owaspSecret?.id).toBe("LLM02");
      expect(owaspSecret?.code).toBe("LLM02: Sensitive Information Disclosure");
      expect(owaspSecret?.categories).toContain("secret");

      const owaspPii = getOwaspCategoryForFinding("pii");
      expect(owaspPii?.id).toBe("LLM02");
      expect(owaspPii?.code).toBe("LLM02: Sensitive Information Disclosure");
      expect(owaspPii?.categories).toContain("pii");
    });

    it("maps schema category to LLM05: Improper Output Handling / Unstructured Output", () => {
      const owasp = getOwaspCategoryForFinding("schema");
      expect(owasp?.id).toBe("LLM05");
      expect(owasp?.code).toBe("LLM05: Improper Output Handling / Unstructured Output");
      expect(owasp?.categories).toContain("schema");
    });

    it("computes OWASP compliance status PASS/FAIL correctly", () => {
      const cleanSummary = getOwaspComplianceSummary([]);
      expect(cleanSummary.LLM01.status).toBe("PASS");
      expect(cleanSummary.LLM02.status).toBe("PASS");
      expect(cleanSummary.LLM05.status).toBe("PASS");

      const violationSummary = getOwaspComplianceSummary(sampleFindings);
      expect(violationSummary.LLM01.status).toBe("FAIL");
      expect(violationSummary.LLM01.count).toBe(1);
      expect(violationSummary.LLM02.status).toBe("FAIL");
      expect(violationSummary.LLM02.count).toBe(2); // 1 secret + 1 pii
      expect(violationSummary.LLM05.status).toBe("FAIL");
      expect(violationSummary.LLM05.count).toBe(1);
    });

    it("renders the standard OWASP labels in the HTML report", () => {
      const html = generateHtmlReport(violationResult);
      expect(html).toContain("LLM01: Prompt Injection");
      expect(html).toContain("LLM02: Sensitive Information Disclosure");
      expect(html).toContain("LLM05: Improper Output Handling / Unstructured Output");
      expect(html).toContain("OWASP Top 10 for LLMs Compliance (2025/2026)");
    });
  });

  describe("Interactive Findings Table", () => {
    it("renders findings table with offsets, messages, and redacted snippets", () => {
      const html = generateHtmlReport(violationResult);
      // Table presence
      expect(html).toContain('id="findingsTable"');
      // Offsets
      expect(html).toContain("[0..28]");
      expect(html).toContain("[35..55]");
      expect(html).toContain("[60..76]");
      expect(html).toContain("[80..97]");
      // Messages
      expect(html).toContain("Instruction override detected");
      expect(html).toContain("AWS Access Key detected");
      expect(html).toContain("Email address detected");
      expect(html).toContain("Invalid JSON format");
      // Snippets
      expect(html).toContain("ignore previous instructions");
      expect(html).toContain("AKIA****************");
      expect(html).toContain("user@example.com");
      expect(html).toContain("unstructured-text");
      // Rule IDs
      expect(html).toContain("INJ001");
      expect(html).toContain("SEC001");
      expect(html).toContain("PII001");
      expect(html).toContain("SCH001");
    });

    it("renders an empty state when there are no findings", () => {
      const html = generateHtmlReport(cleanResult);
      expect(html).not.toContain('id="findingsTable"');
      expect(html).toContain("No security findings detected");
    });

    it("includes inline JavaScript for client-side search and filters", () => {
      const html = generateHtmlReport(violationResult);
      expect(html).toContain("<script>");
      expect(html).toContain("updateTableFilter");
      expect(html).toContain("searchInput");
    });
  });

  describe("Integrable JSON Export", () => {
    it("embeds a parseable structured JSON summary in a script element", () => {
      const html = generateHtmlReport(violationResult, {
        title: "Integration Test Audit",
        inputSource: "api/v1/chat",
      });

      const scriptMatch = html.match(
        /<script id="agentguard-report-data" type="application\/json">([\s\S]*?)<\/script>/,
      );
      expect(scriptMatch).not.toBeNull();
      const rawJson = scriptMatch![1].trim();
      const parsed = JSON.parse(rawJson);

      expect(parsed.title).toBe("Integration Test Audit");
      expect(parsed.inputSource).toBe("api/v1/chat");
      expect(parsed.ok).toBe(false);
      expect(typeof parsed.securityScore).toBe("number");
      expect(parsed.severityCounts).toEqual({
        critical: 1,
        high: 1,
        medium: 1,
        low: 1,
      });
      expect(parsed.owaspCompliance.LLM01.status).toBe("FAIL");
      expect(parsed.owaspCompliance.LLM01.count).toBe(1);
      expect(parsed.owaspCompliance.LLM02.status).toBe("FAIL");
      expect(parsed.owaspCompliance.LLM02.count).toBe(2);
      expect(parsed.owaspCompliance.LLM05.status).toBe("FAIL");
      expect(parsed.owaspCompliance.LLM05.count).toBe(1);
      expect(parsed.findings).toHaveLength(4);
    });
  });

  describe("Security and XSS Sanitization", () => {
    it("escapes malicious user-supplied content in title, inputSource, and findings", () => {
      const maliciousResult: AuditResult = {
        ok: false,
        findings: [
          {
            ruleId: "INJ<script>alert(1)</script>",
            category: "injection",
            severity: "high",
            message: "Attack <img src=x onerror=alert(2)>",
            match: "<script>evil()</script>",
            start: 1,
            end: 10,
          },
        ],
      };

      const html = generateHtmlReport(maliciousResult, {
        title: "<script>alert('title')</script>",
        inputSource: "\"><script>alert('source')</script>",
      });

      expect(html).not.toContain("<script>alert('title')</script>");
      expect(html).not.toContain("\"><script>alert('source')</script>");
      expect(html).not.toContain("INJ<script>alert(1)</script>");
      expect(html).not.toContain("<img src=x onerror=alert(2)>");
      expect(html).not.toContain("<script>evil()</script>");

      expect(html).toContain("&lt;script&gt;alert(&#039;title&#039;)&lt;/script&gt;");
      expect(html).toContain("&lt;img src=x onerror=alert(2)&gt;");
    });
  });
});
