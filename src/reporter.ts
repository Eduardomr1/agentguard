import type { AuditResult, Category, Finding, Severity } from "./types.js";

export interface ReportOptions {
  title?: string;
  inputSource?: string;
  timestamp?: string;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export type OwaspId = "LLM01" | "LLM02" | "LLM05";

export interface OwaspMappingInfo {
  id: OwaspId;
  code: string;
  name: string;
  categories: Category[];
  description: string;
}

export const OWASP_LLM_CATEGORIES: Record<OwaspId, OwaspMappingInfo> = {
  LLM01: {
    id: "LLM01",
    code: "LLM01: Prompt Injection",
    name: "Prompt Injection",
    categories: ["injection"],
    description: "Manipulación de prompts directos o indirectos para evadir guardrails, cambiar roles o ejecutar instrucciones no autorizadas.",
  },
  LLM02: {
    id: "LLM02",
    code: "LLM02: Sensitive Information Disclosure",
    name: "Sensitive Information Disclosure",
    categories: ["secret", "pii"],
    description: "Fuga involuntaria de credenciales, secretos, API keys o datos personales identificables (PII).",
  },
  LLM05: {
    id: "LLM05",
    code: "LLM05: Improper Output Handling / Unstructured Output",
    name: "Improper Output Handling / Unstructured Output",
    categories: ["schema"],
    description: "Salidas no estructuradas o malformadas que violan esquemas JSON previstos o reglas de formato.",
  },
};

export function getOwaspCategoryForFinding(category: Category): OwaspMappingInfo | undefined {
  if (category === "injection") return OWASP_LLM_CATEGORIES.LLM01;
  if (category === "secret" || category === "pii") return OWASP_LLM_CATEGORIES.LLM02;
  if (category === "schema") return OWASP_LLM_CATEGORIES.LLM05;
  return undefined;
}

export function countBySeverity(findings: Finding[]): SeverityCounts {
  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    if (f.severity in counts) {
      counts[f.severity]++;
    }
  }
  return counts;
}

export function calculateSecurityScore(result: AuditResult): number {
  if (result.findings.length === 0) return 100;
  const penalties: Record<Severity, number> = {
    critical: 25,
    high: 15,
    medium: 8,
    low: 3,
  };
  let deduction = 0;
  for (const f of result.findings) {
    deduction += penalties[f.severity] ?? 5;
  }
  return Math.max(0, Math.min(100, Math.round(100 - deduction)));
}

export interface OwaspComplianceSummaryItem {
  id: OwaspId;
  code: string;
  name: string;
  categories: Category[];
  description: string;
  count: number;
  status: "PASS" | "FAIL";
  findings: Finding[];
}

export function getOwaspComplianceSummary(
  findings: Finding[],
): Record<OwaspId, OwaspComplianceSummaryItem> {
  const llm01 = findings.filter((f) => f.category === "injection");
  const llm02 = findings.filter((f) => f.category === "secret" || f.category === "pii");
  const llm05 = findings.filter((f) => f.category === "schema");

  return {
    LLM01: {
      ...OWASP_LLM_CATEGORIES.LLM01,
      count: llm01.length,
      status: llm01.length === 0 ? "PASS" : "FAIL",
      findings: llm01,
    },
    LLM02: {
      ...OWASP_LLM_CATEGORIES.LLM02,
      count: llm02.length,
      status: llm02.length === 0 ? "PASS" : "FAIL",
      findings: llm02,
    },
    LLM05: {
      ...OWASP_LLM_CATEGORIES.LLM05,
      count: llm05.length,
      status: llm05.length === 0 ? "PASS" : "FAIL",
      findings: llm05,
    },
  };
}

export interface ReportJsonSummary {
  title: string;
  timestamp: string;
  inputSource: string;
  ok: boolean;
  securityScore: number;
  totalFindings: number;
  severityCounts: SeverityCounts;
  owaspCompliance: Record<
    OwaspId,
    {
      code: string;
      name: string;
      status: "PASS" | "FAIL";
      count: number;
      categories: Category[];
    }
  >;
  findings: Finding[];
}

export function buildReportJsonSummary(
  result: AuditResult,
  options?: ReportOptions,
): ReportJsonSummary {
  const title = options?.title ?? "AgentGuard Security Audit Report";
  const inputSource = options?.inputSource ?? "Direct Input";
  const timestamp = options?.timestamp ?? new Date().toISOString();
  const securityScore = calculateSecurityScore(result);
  const severityCounts = countBySeverity(result.findings);
  const compliance = getOwaspComplianceSummary(result.findings);

  return {
    title,
    timestamp,
    inputSource,
    ok: result.ok,
    securityScore,
    totalFindings: result.findings.length,
    severityCounts,
    owaspCompliance: {
      LLM01: {
        code: compliance.LLM01.code,
        name: compliance.LLM01.name,
        status: compliance.LLM01.status,
        count: compliance.LLM01.count,
        categories: compliance.LLM01.categories,
      },
      LLM02: {
        code: compliance.LLM02.code,
        name: compliance.LLM02.name,
        status: compliance.LLM02.status,
        count: compliance.LLM02.count,
        categories: compliance.LLM02.categories,
      },
      LLM05: {
        code: compliance.LLM05.code,
        name: compliance.LLM05.name,
        status: compliance.LLM05.status,
        count: compliance.LLM05.count,
        categories: compliance.LLM05.categories,
      },
    },
    findings: result.findings,
  };
}

export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function getScoreGrade(score: number): { grade: string; label: string; colorClass: string } {
  if (score >= 90) return { grade: "A", label: "Excellent", colorClass: "score-excellent" };
  if (score >= 75) return { grade: "B", label: "Good", colorClass: "score-good" };
  if (score >= 50) return { grade: "C", label: "Warning", colorClass: "score-warning" };
  return { grade: "F", label: "Critical Risk", colorClass: "score-danger" };
}

/**
 * Genera un documento HTML standalone (sin dependencias externas, con estilos CSS modernos inline, dark/light mode con media query) con:
 * - Resumen de hallazgos (Score de seguridad 0-100, conteo por severidad: Critical, High, Medium, Low).
 * - Mapeo al estándar OWASP Top 10 for LLM Applications (2025/2026):
 *   - LLM01: Prompt Injection (asociado a category: "injection")
 *   - LLM02: Sensitive Information Disclosure (asociado a category: "secret" y category: "pii")
 *   - LLM05: Improper Output Handling / Unstructured Output (asociado a category: "schema")
 * - Tabla interactiva de hallazgos con offsets, mensajes y snippets redactados.
 * - Exportación de resumen JSON integrable.
 */
export function generateHtmlReport(
  result: AuditResult,
  options?: { title?: string; inputSource?: string; timestamp?: string },
): string {
  const title = options?.title ?? "AgentGuard Security Audit Report";
  const inputSource = options?.inputSource ?? "Direct Input";
  const timestamp = options?.timestamp ?? new Date().toISOString();

  const score = calculateSecurityScore(result);
  const scoreInfo = getScoreGrade(score);
  const counts = countBySeverity(result.findings);
  const compliance = getOwaspComplianceSummary(result.findings);
  const jsonSummary = buildReportJsonSummary(result, { title, inputSource, timestamp });
  const jsonSummaryRaw = JSON.stringify(jsonSummary, null, 2);
  // Prevent </script> injection inside the json tag
  const safeJsonSummaryForScript = jsonSummaryRaw.replace(/</g, "\\u003c");

  const escapedTitle = escapeHtml(title);
  const escapedInputSource = escapeHtml(inputSource);
  const escapedTimestamp = escapeHtml(timestamp);

  const findingsRowsHtml = result.findings
    .map((f, index) => {
      const owasp = getOwaspCategoryForFinding(f.category);
      const owaspCode = owasp ? owasp.code : "Unmapped";
      const owaspId = owasp ? owasp.id : "OTHER";
      const safeRuleId = escapeHtml(f.ruleId);
      const safeCategory = escapeHtml(f.category);
      const safeSeverity = escapeHtml(f.severity);
      const safeMessage = escapeHtml(f.message);
      const safeMatch = escapeHtml(f.match);
      const searchTerms = escapeHtml(
        `${f.ruleId} ${f.category} ${f.severity} ${f.message} ${f.match} ${owaspCode}`,
      ).toLowerCase();

      return `
        <tr class="finding-row" data-index="${index}" data-severity="${safeSeverity}" data-owasp="${owaspId}" data-category="${safeCategory}" data-search="${searchTerms}">
          <td>
            <span class="badge badge-severity badge-${safeSeverity}">${safeSeverity.toUpperCase()}</span>
          </td>
          <td>
            <span class="badge badge-owasp" title="${escapeHtml(owaspCode)}">${escapeHtml(owasp ? owasp.id : "N/A")}</span>
            <span class="owasp-name-inline">${escapeHtml(owasp ? owasp.name : "Other")}</span>
          </td>
          <td><code class="code-pill">${safeRuleId}</code></td>
          <td><span class="badge badge-category">${safeCategory}</span></td>
          <td class="offset-cell">
            <span class="offset-badge">[${f.start}..${f.end}]</span>
            <span class="offset-len">(${f.end - f.start} chars)</span>
          </td>
          <td class="message-cell">${safeMessage}</td>
          <td class="snippet-cell">
            <code class="snippet-code">${safeMatch}</code>
          </td>
        </tr>`;
    })
    .join("\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapedTitle}</title>
  <style>
    :root {
      --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
      
      --bg: #f8fafc;
      --surface: #ffffff;
      --surface-subtle: #f1f5f9;
      --border: #e2e8f0;
      --text: #0f172a;
      --text-muted: #64748b;
      
      --primary: #4f46e5;
      --primary-hover: #4338ca;
      --primary-subtle: #eef2ff;

      --critical: #ef4444;
      --critical-bg: #fef2f2;
      --critical-border: #fecaca;

      --high: #f97316;
      --high-bg: #fff7ed;
      --high-border: #fed7aa;

      --medium: #f59e0b;
      --medium-bg: #fffbeb;
      --medium-border: #fde68a;

      --low: #3b82f6;
      --low-bg: #eff6ff;
      --low-border: #bfdbfe;

      --pass: #10b981;
      --pass-bg: #ecfdf5;
      --pass-border: #a7f3d0;

      --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
      --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
      --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
    }

    @media (prefers-color-scheme: dark) {
      :root:not([data-theme="light"]) {
        --bg: #090d16;
        --surface: #111827;
        --surface-subtle: #1f2937;
        --border: #374151;
        --text: #f9fafb;
        --text-muted: #9ca3af;
        
        --primary-subtle: #312e81;

        --critical-bg: #450a0a;
        --critical-border: #7f1d1d;

        --high-bg: #431407;
        --high-border: #7c2d12;

        --medium-bg: #451a03;
        --medium-border: #78350f;

        --low-bg: #172554;
        --low-border: #1e3a8a;

        --pass-bg: #064e3b;
        --pass-border: #065f46;
      }
    }

    [data-theme="dark"] {
      --bg: #090d16;
      --surface: #111827;
      --surface-subtle: #1f2937;
      --border: #374151;
      --text: #f9fafb;
      --text-muted: #9ca3af;

      --primary-subtle: #312e81;

      --critical-bg: #450a0a;
      --critical-border: #7f1d1d;

      --high-bg: #431407;
      --high-border: #7c2d12;

      --medium-bg: #451a03;
      --medium-border: #78350f;

      --low-bg: #172554;
      --low-border: #1e3a8a;

      --pass-bg: #064e3b;
      --pass-border: #065f46;
    }

    [data-theme="light"] {
      --bg: #f8fafc;
      --surface: #ffffff;
      --surface-subtle: #f1f5f9;
      --border: #e2e8f0;
      --text: #0f172a;
      --text-muted: #64748b;

      --primary-subtle: #eef2ff;

      --critical-bg: #fef2f2;
      --critical-border: #fecaca;

      --high-bg: #fff7ed;
      --high-border: #fed7aa;

      --medium-bg: #fffbeb;
      --medium-border: #fde68a;

      --low-bg: #eff6ff;
      --low-border: #bfdbfe;

      --pass-bg: #ecfdf5;
      --pass-border: #a7f3d0;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: var(--font-sans);
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 24px;
      transition: background-color 0.2s ease, color 0.2s ease;
    }

    .container {
      max-width: 1280px;
      margin: 0 auto;
      display: flex;
      flex-direction: column;
      gap: 24px;
    }

    header {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
      box-shadow: var(--shadow-sm);
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .header-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
    }

    .brand-group {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .brand-icon {
      font-size: 28px;
      background: var(--primary-subtle);
      border-radius: 8px;
      padding: 6px 10px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }

    .report-title {
      font-size: 24px;
      font-weight: 700;
      letter-spacing: -0.02em;
    }

    .report-subtitle {
      font-size: 13px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      font-weight: 600;
    }

    .header-actions {
      display: flex;
      gap: 10px;
      align-items: center;
    }

    button, .btn {
      cursor: pointer;
      font-family: inherit;
      font-size: 13px;
      font-weight: 500;
      padding: 8px 14px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--surface);
      color: var(--text);
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: all 0.15s ease;
    }

    button:hover, .btn:hover {
      background: var(--surface-subtle);
      border-color: var(--text-muted);
    }

    .btn-primary {
      background: var(--primary);
      border-color: var(--primary);
      color: #ffffff;
    }

    .btn-primary:hover {
      background: var(--primary-hover);
      border-color: var(--primary-hover);
    }

    .meta-bar {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
      padding-top: 14px;
      border-top: 1px solid var(--border);
      font-size: 13px;
    }

    .meta-item {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      color: var(--text-muted);
    }

    .meta-item strong {
      color: var(--text);
    }

    /* Summary Grid */
    .summary-grid {
      display: grid;
      grid-template-columns: 280px repeat(4, 1fr);
      gap: 16px;
    }

    @media (max-width: 1024px) {
      .summary-grid {
        grid-template-columns: 1fr 1fr;
      }
    }

    @media (max-width: 640px) {
      .summary-grid {
        grid-template-columns: 1fr;
      }
    }

    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      box-shadow: var(--shadow-sm);
      position: relative;
      overflow: hidden;
    }

    .score-card {
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      border-left: 5px solid var(--primary);
    }

    .score-header {
      font-size: 13px;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .score-display {
      display: flex;
      align-items: baseline;
      gap: 8px;
      margin: 12px 0;
    }

    .score-number {
      font-size: 48px;
      font-weight: 800;
      line-height: 1;
      letter-spacing: -0.03em;
    }

    .score-max {
      font-size: 20px;
      color: var(--text-muted);
      font-weight: 600;
    }

    .score-grade {
      font-size: 13px;
      font-weight: 700;
      padding: 4px 10px;
      border-radius: 6px;
      display: inline-block;
      width: fit-content;
    }

    .score-excellent { color: #059669; background: var(--pass-bg); border: 1px solid var(--pass-border); }
    .score-good { color: #0284c7; background: var(--low-bg); border: 1px solid var(--low-border); }
    .score-warning { color: #d97706; background: var(--medium-bg); border: 1px solid var(--medium-border); }
    .score-danger { color: #dc2626; background: var(--critical-bg); border: 1px solid var(--critical-border); }

    .stat-card {
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }

    .stat-card.stat-critical { border-top: 4px solid var(--critical); }
    .stat-card.stat-high { border-top: 4px solid var(--high); }
    .stat-card.stat-medium { border-top: 4px solid var(--medium); }
    .stat-card.stat-low { border-top: 4px solid var(--low); }

    .stat-label {
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
    }

    .stat-value {
      font-size: 36px;
      font-weight: 800;
      line-height: 1.1;
      margin: 8px 0;
    }

    .stat-card.stat-critical .stat-value { color: var(--critical); }
    .stat-card.stat-high .stat-value { color: var(--high); }
    .stat-card.stat-medium .stat-value { color: var(--medium); }
    .stat-card.stat-low .stat-value { color: var(--low); }

    .stat-caption {
      font-size: 12px;
      color: var(--text-muted);
    }

    /* OWASP Section */
    .section-title {
      font-size: 18px;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .section-desc {
      font-size: 13px;
      color: var(--text-muted);
      margin-top: 4px;
    }

    .owasp-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 16px;
      margin-top: 14px;
    }

    @media (max-width: 900px) {
      .owasp-grid {
        grid-template-columns: 1fr;
      }
    }

    .owasp-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      box-shadow: var(--shadow-sm);
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 14px;
    }

    .owasp-card-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 10px;
    }

    .owasp-code-title {
      font-size: 16px;
      font-weight: 700;
      line-height: 1.3;
    }

    .owasp-card-desc {
      font-size: 13px;
      color: var(--text-muted);
      line-height: 1.4;
    }

    .owasp-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      align-items: center;
    }

    .owasp-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-top: 12px;
      border-top: 1px solid var(--border);
      font-size: 12px;
    }

    .owasp-card.pass {
      border-left: 4px solid var(--pass);
    }

    .owasp-card.fail {
      border-left: 4px solid var(--critical);
    }

    /* Badges */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      padding: 3px 8px;
      border-radius: 6px;
      line-height: 1;
    }

    .badge-status-pass {
      background: var(--pass-bg);
      color: #059669;
      border: 1px solid var(--pass-border);
    }

    .badge-status-fail {
      background: var(--critical-bg);
      color: #dc2626;
      border: 1px solid var(--critical-border);
    }

    .badge-severity.badge-critical { background: var(--critical-bg); color: var(--critical); border: 1px solid var(--critical-border); }
    .badge-severity.badge-high { background: var(--high-bg); color: var(--high); border: 1px solid var(--high-border); }
    .badge-severity.badge-medium { background: var(--medium-bg); color: var(--medium); border: 1px solid var(--medium-border); }
    .badge-severity.badge-low { background: var(--low-bg); color: var(--low); border: 1px solid var(--low-border); }

    .badge-owasp {
      background: var(--primary-subtle);
      color: var(--primary);
      border: 1px solid var(--border);
      font-family: var(--font-mono);
    }

    .badge-category {
      background: var(--surface-subtle);
      color: var(--text-muted);
      border: 1px solid var(--border);
      font-size: 10px;
    }

    .code-pill {
      font-family: var(--font-mono);
      font-size: 12px;
      font-weight: 600;
      background: var(--surface-subtle);
      border: 1px solid var(--border);
      padding: 2px 6px;
      border-radius: 4px;
      color: var(--text);
    }

    /* Findings Table */
    .table-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      box-shadow: var(--shadow-sm);
      overflow: hidden;
    }

    .table-toolbar {
      padding: 16px 20px;
      border-bottom: 1px solid var(--border);
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      justify-content: space-between;
      align-items: center;
      background: var(--surface);
    }

    .filter-group {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      align-items: center;
    }

    .filter-btn {
      font-size: 12px;
      padding: 5px 10px;
      border-radius: 6px;
      background: var(--surface-subtle);
      border: 1px solid var(--border);
      color: var(--text-muted);
    }

    .filter-btn.active {
      background: var(--primary);
      color: #ffffff;
      border-color: var(--primary);
    }

    .search-box {
      min-width: 260px;
      padding: 7px 12px;
      font-size: 13px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--bg);
      color: var(--text);
      outline: none;
      font-family: inherit;
    }

    .search-box:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 2px var(--primary-subtle);
    }

    .table-container {
      overflow-x: auto;
      width: 100%;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 13px;
    }

    thead {
      background: var(--surface-subtle);
      border-bottom: 1px solid var(--border);
    }

    th {
      padding: 12px 16px;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      font-size: 11px;
      letter-spacing: 0.05em;
      white-space: nowrap;
    }

    td {
      padding: 14px 16px;
      border-bottom: 1px solid var(--border);
      vertical-align: middle;
    }

    tr.finding-row:hover {
      background: var(--surface-subtle);
    }

    .owasp-name-inline {
      margin-left: 6px;
      font-size: 12px;
      color: var(--text-muted);
    }

    .offset-cell {
      white-space: nowrap;
      font-family: var(--font-mono);
      font-size: 12px;
    }

    .offset-badge {
      font-weight: 600;
      color: var(--text);
    }

    .offset-len {
      color: var(--text-muted);
      margin-left: 4px;
      font-size: 11px;
    }

    .message-cell {
      max-width: 280px;
      font-weight: 500;
    }

    .snippet-cell {
      max-width: 320px;
    }

    .snippet-code {
      display: inline-block;
      max-width: 100%;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-family: var(--font-mono);
      font-size: 12px;
      background: var(--surface-subtle);
      border: 1px solid var(--border);
      padding: 4px 8px;
      border-radius: 4px;
      color: #d97706;
    }

    .empty-state {
      padding: 48px 24px;
      text-align: center;
      color: var(--text-muted);
    }

    .empty-icon {
      font-size: 40px;
      margin-bottom: 12px;
    }

    .empty-text {
      font-size: 15px;
      font-weight: 500;
    }

    /* JSON section */
    details.json-accordion {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      box-shadow: var(--shadow-sm);
      overflow: hidden;
    }

    details.json-accordion summary {
      padding: 16px 20px;
      font-weight: 600;
      font-size: 14px;
      cursor: pointer;
      display: flex;
      justify-content: space-between;
      align-items: center;
      user-select: none;
    }

    details.json-accordion summary:hover {
      background: var(--surface-subtle);
    }

    .json-content {
      padding: 0 20px 20px 20px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .json-actions {
      display: flex;
      gap: 8px;
      justify-content: flex-end;
    }

    pre.json-pre {
      background: var(--surface-subtle);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      font-family: var(--font-mono);
      font-size: 12px;
      overflow-x: auto;
      max-height: 400px;
      color: var(--text);
    }

    footer {
      text-align: center;
      font-size: 12px;
      color: var(--text-muted);
      padding: 16px 0;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="header-top">
        <div class="brand-group">
          <div class="brand-icon">🛡️</div>
          <div>
            <div class="report-subtitle">AgentGuard • LLM Security &amp; Safety Auditor</div>
            <h1 class="report-title">${escapedTitle}</h1>
          </div>
        </div>
        <div class="header-actions">
          <button id="themeToggleBtn" type="button" title="Toggle color scheme">🌓 Theme</button>
          <button id="copyJsonBtn" type="button" class="btn-primary" title="Copy structured JSON summary">📋 Copy JSON</button>
          <button id="downloadJsonBtn" type="button" title="Download JSON summary">💾 Download JSON</button>
        </div>
      </div>
      <div class="meta-bar">
        <span class="meta-item">
          Status:
          ${
            result.ok
              ? '<span class="badge badge-status-pass">✓ PASSED</span>'
              : '<span class="badge badge-status-fail">⚠ VIOLATIONS DETECTED</span>'
          }
        </span>
        <span class="meta-item">Input Source: <strong>${escapedInputSource}</strong></span>
        <span class="meta-item">Generated: <strong>${escapedTimestamp}</strong></span>
        <span class="meta-item">Total Findings: <strong>${result.findings.length}</strong></span>
      </div>
    </header>

    <!-- Resumen de Hallazgos -->
    <section>
      <div class="summary-grid">
        <div class="card score-card">
          <div class="score-header">Security Score</div>
          <div class="score-display">
            <span class="score-number">${score}</span>
            <span class="score-max">/100</span>
          </div>
          <div>
            <span class="score-grade ${scoreInfo.colorClass}">Grade ${scoreInfo.grade} • ${scoreInfo.label}</span>
          </div>
        </div>

        <div class="card stat-card stat-critical">
          <div class="stat-label">Critical</div>
          <div class="stat-value" id="countCritical">${counts.critical}</div>
          <div class="stat-caption">Immediate threat</div>
        </div>

        <div class="card stat-card stat-high">
          <div class="stat-label">High</div>
          <div class="stat-value" id="countHigh">${counts.high}</div>
          <div class="stat-caption">Severe risk</div>
        </div>

        <div class="card stat-card stat-medium">
          <div class="stat-label">Medium</div>
          <div class="stat-value" id="countMedium">${counts.medium}</div>
          <div class="stat-caption">Policy alert</div>
        </div>

        <div class="card stat-card stat-low">
          <div class="stat-label">Low</div>
          <div class="stat-value" id="countLow">${counts.low}</div>
          <div class="stat-caption">Informational</div>
        </div>
      </div>
    </section>

    <!-- Mapeo al estándar OWASP Top 10 for LLM Applications (2025/2026) -->
    <section>
      <div>
        <h2 class="section-title">OWASP Top 10 for LLMs Compliance (2025/2026)</h2>
        <p class="section-desc">Audit alignment against the OWASP Top 10 for Large Language Model Applications standard.</p>
      </div>

      <div class="owasp-grid">
        <!-- LLM01 -->
        <div class="owasp-card ${compliance.LLM01.status === "PASS" ? "pass" : "fail"}">
          <div class="owasp-card-header">
            <div>
              <span class="badge badge-owasp">LLM01</span>
              <h3 class="owasp-code-title">LLM01: Prompt Injection</h3>
            </div>
            <span class="badge ${compliance.LLM01.status === "PASS" ? "badge-status-pass" : "badge-status-fail"}">
              ${compliance.LLM01.status}
            </span>
          </div>
          <p class="owasp-card-desc">${escapeHtml(compliance.LLM01.description)}</p>
          <div class="owasp-meta">
            <span class="badge badge-category">category: "injection"</span>
          </div>
          <div class="owasp-footer">
            <span>Violations: <strong>${compliance.LLM01.count}</strong></span>
            <span>${compliance.LLM01.status === "PASS" ? "Compliant" : "Review Required"}</span>
          </div>
        </div>

        <!-- LLM02 -->
        <div class="owasp-card ${compliance.LLM02.status === "PASS" ? "pass" : "fail"}">
          <div class="owasp-card-header">
            <div>
              <span class="badge badge-owasp">LLM02</span>
              <h3 class="owasp-code-title">LLM02: Sensitive Information Disclosure</h3>
            </div>
            <span class="badge ${compliance.LLM02.status === "PASS" ? "badge-status-pass" : "badge-status-fail"}">
              ${compliance.LLM02.status}
            </span>
          </div>
          <p class="owasp-card-desc">${escapeHtml(compliance.LLM02.description)}</p>
          <div class="owasp-meta">
            <span class="badge badge-category">category: "secret"</span>
            <span class="badge badge-category">category: "pii"</span>
          </div>
          <div class="owasp-footer">
            <span>Violations: <strong>${compliance.LLM02.count}</strong></span>
            <span>${compliance.LLM02.status === "PASS" ? "Compliant" : "Review Required"}</span>
          </div>
        </div>

        <!-- LLM05 -->
        <div class="owasp-card ${compliance.LLM05.status === "PASS" ? "pass" : "fail"}">
          <div class="owasp-card-header">
            <div>
              <span class="badge badge-owasp">LLM05</span>
              <h3 class="owasp-code-title">LLM05: Improper Output Handling / Unstructured Output</h3>
            </div>
            <span class="badge ${compliance.LLM05.status === "PASS" ? "badge-status-pass" : "badge-status-fail"}">
              ${compliance.LLM05.status}
            </span>
          </div>
          <p class="owasp-card-desc">${escapeHtml(compliance.LLM05.description)}</p>
          <div class="owasp-meta">
            <span class="badge badge-category">category: "schema"</span>
          </div>
          <div class="owasp-footer">
            <span>Violations: <strong>${compliance.LLM05.count}</strong></span>
            <span>${compliance.LLM05.status === "PASS" ? "Compliant" : "Review Required"}</span>
          </div>
        </div>
      </div>
    </section>

    <!-- Tabla interactiva de hallazgos -->
    <section>
      <div class="table-card">
        <div class="table-toolbar">
          <div class="filter-group">
            <span style="font-size: 12px; font-weight: 600; color: var(--text-muted); margin-right: 4px;">Severity:</span>
            <button type="button" class="filter-btn active" data-filter-type="severity" data-filter-val="all">All (${result.findings.length})</button>
            <button type="button" class="filter-btn" data-filter-type="severity" data-filter-val="critical">Critical (${counts.critical})</button>
            <button type="button" class="filter-btn" data-filter-type="severity" data-filter-val="high">High (${counts.high})</button>
            <button type="button" class="filter-btn" data-filter-type="severity" data-filter-val="medium">Medium (${counts.medium})</button>
            <button type="button" class="filter-btn" data-filter-type="severity" data-filter-val="low">Low (${counts.low})</button>
          </div>

          <div class="filter-group">
            <span style="font-size: 12px; font-weight: 600; color: var(--text-muted); margin-right: 4px;">OWASP:</span>
            <button type="button" class="filter-btn active" data-filter-type="owasp" data-filter-val="all">All</button>
            <button type="button" class="filter-btn" data-filter-type="owasp" data-filter-val="LLM01">LLM01</button>
            <button type="button" class="filter-btn" data-filter-type="owasp" data-filter-val="LLM02">LLM02</button>
            <button type="button" class="filter-btn" data-filter-type="owasp" data-filter-val="LLM05">LLM05</button>
          </div>

          <div>
            <input type="text" id="searchInput" class="search-box" placeholder="Filter findings (rule, text, match)...">
          </div>
        </div>

        <div class="table-container">
          ${
            result.findings.length === 0
              ? `<div class="empty-state">
                  <div class="empty-icon">🎉</div>
                  <div class="empty-text">No security findings detected. Prompt and output passed all active guardrails.</div>
                </div>`
              : `<table id="findingsTable">
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>OWASP Mapping</th>
                      <th>Rule ID</th>
                      <th>Category</th>
                      <th>Offsets</th>
                      <th>Message</th>
                      <th>Redacted Match</th>
                    </tr>
                  </thead>
                  <tbody id="findingsTableBody">
                    ${findingsRowsHtml}
                  </tbody>
                </table>
                <div id="noMatchMessage" class="empty-state" style="display: none;">
                  <div class="empty-icon">🔍</div>
                  <div class="empty-text">No findings match the selected filters.</div>
                </div>`
          }
        </div>
      </div>
    </section>

    <!-- Exportación de resumen JSON integrable -->
    <section>
      <details class="json-accordion">
        <summary>
          <span>📦 Integrable JSON Summary</span>
          <span style="font-size: 12px; color: var(--text-muted);">Click to expand</span>
        </summary>
        <div class="json-content">
          <div class="json-actions">
            <button type="button" id="copyJsonBtnInner">📋 Copy JSON</button>
            <button type="button" id="downloadJsonBtnInner">💾 Download JSON</button>
          </div>
          <pre class="json-pre"><code id="jsonDisplay">${escapeHtml(jsonSummaryRaw)}</code></pre>
        </div>
      </details>
    </section>

    <footer>
      AgentGuard Security Reporter • OWASP Top 10 for LLM Applications (2025/2026) Compliant
    </footer>
  </div>

  <!-- Raw Integrable JSON Data Script Element -->
  <script id="agentguard-report-data" type="application/json">
${safeJsonSummaryForScript}
  </script>

  <script>
    (function() {
      // JSON summary payload
      const dataScript = document.getElementById("agentguard-report-data");
      const jsonData = dataScript ? JSON.parse(dataScript.textContent || "{}") : {};

      // Theme toggle
      const themeBtn = document.getElementById("themeToggleBtn");
      let currentTheme = localStorage.getItem("agentguard_theme") || "auto";

      function applyTheme(theme) {
        if (theme === "dark") {
          document.documentElement.setAttribute("data-theme", "dark");
        } else if (theme === "light") {
          document.documentElement.setAttribute("data-theme", "light");
        } else {
          document.documentElement.removeAttribute("data-theme");
        }
      }
      applyTheme(currentTheme);

      if (themeBtn) {
        themeBtn.addEventListener("click", function() {
          const isDark = document.documentElement.getAttribute("data-theme") === "dark" ||
            (!document.documentElement.getAttribute("data-theme") && window.matchMedia("(prefers-color-scheme: dark)").matches);
          const nextTheme = isDark ? "light" : "dark";
          localStorage.setItem("agentguard_theme", nextTheme);
          applyTheme(nextTheme);
        });
      }

      // Copy & Download JSON
      function copyJson(btn) {
        const text = JSON.stringify(jsonData, null, 2);
        navigator.clipboard.writeText(text).then(function() {
          const orig = btn.textContent;
          btn.textContent = "✓ Copied!";
          setTimeout(function() { btn.textContent = orig; }, 2000);
        }).catch(function() {
          alert("Could not copy to clipboard.");
        });
      }

      function downloadJson() {
        const text = JSON.stringify(jsonData, null, 2);
        const blob = new Blob([text], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "agentguard-audit-summary.json";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }

      const copyBtn = document.getElementById("copyJsonBtn");
      if (copyBtn) copyBtn.addEventListener("click", function() { copyJson(copyBtn); });
      const copyBtnInner = document.getElementById("copyJsonBtnInner");
      if (copyBtnInner) copyBtnInner.addEventListener("click", function() { copyJson(copyBtnInner); });

      const dlBtn = document.getElementById("downloadJsonBtn");
      if (dlBtn) dlBtn.addEventListener("click", downloadJson);
      const dlBtnInner = document.getElementById("downloadJsonBtnInner");
      if (dlBtnInner) dlBtnInner.addEventListener("click", downloadJson);

      // Filtering Table
      let selectedSeverity = "all";
      let selectedOwasp = "all";
      let searchQuery = "";

      const rows = Array.from(document.querySelectorAll(".finding-row"));
      const noMatchMsg = document.getElementById("noMatchMessage");
      const searchInput = document.getElementById("searchInput");

      function updateTableFilter() {
        let visibleCount = 0;
        rows.forEach(function(row) {
          const rowSeverity = row.getAttribute("data-severity");
          const rowOwasp = row.getAttribute("data-owasp");
          const searchContent = row.getAttribute("data-search") || "";

          const matchSev = selectedSeverity === "all" || rowSeverity === selectedSeverity;
          const matchOwasp = selectedOwasp === "all" || rowOwasp === selectedOwasp;
          const matchSearch = !searchQuery || searchContent.indexOf(searchQuery.toLowerCase()) !== -1;

          if (matchSev && matchOwasp && matchSearch) {
            row.style.display = "";
            visibleCount++;
          } else {
            row.style.display = "none";
          }
        });

        if (noMatchMsg) {
          noMatchMsg.style.display = (visibleCount === 0 && rows.length > 0) ? "block" : "none";
        }
      }

      // Severity & OWASP Buttons
      const filterBtns = document.querySelectorAll(".filter-btn");
      filterBtns.forEach(function(btn) {
        btn.addEventListener("click", function() {
          const type = btn.getAttribute("data-filter-type");
          const val = btn.getAttribute("data-filter-val");

          // Deactivate siblings
          filterBtns.forEach(function(b) {
            if (b.getAttribute("data-filter-type") === type) {
              b.classList.remove("active");
            }
          });
          btn.classList.add("active");

          if (type === "severity") selectedSeverity = val;
          if (type === "owasp") selectedOwasp = val;
          updateTableFilter();
        });
      });

      if (searchInput) {
        searchInput.addEventListener("input", function(e) {
          searchQuery = (e.target.value || "").trim();
          updateTableFilter();
        });
      }
    })();
  </script>
</body>
</html>`;
}

/**
 * Generates an executive Markdown report suitable for GitHub PR comments,
 * CI job summaries ($GITHUB_STEP_SUMMARY), or terminal viewing.
 */
export function generateMarkdownReport(
  result: AuditResult,
  options: ReportOptions = {}
): string {
  const counts = countBySeverity(result.findings);
  const score = calculateSecurityScore(result);
  const title = options.title ?? "AgentGuard Security Audit Report";
  const source = options.inputSource ? `\n**Source:** \`${options.inputSource}\`` : "";
  const isPassed = result.ok ?? (result as { passed?: boolean }).passed ?? (result.findings.length === 0);
  const status = isPassed ? "✅ **PASSED**" : "❌ **FAILED (Action Required)**";

  const rows = result.findings.map((f, i) => {
    return `| ${i + 1} | \`${f.ruleId}\` | **${f.severity.toUpperCase()}** | ${f.category} | \`${f.match.replace(/\|/g, "\\|")}\` | ${f.message.replace(/\|/g, "\\|")} |`;
  });

  const tableHeader = [
    "| # | Rule | Severity | Category | Snippet | Details |",
    "|---|------|----------|----------|---------|---------|",
  ];

  const findingsSection =
    result.findings.length > 0
      ? [...tableHeader, ...rows].join("\n")
      : "_No security violations or sensitive data leaks detected._";

  return `# 🛡️ ${title}
${source}
- **Status:** ${status}
- **Security Posture Score:** \`${score}/100\`
- **Findings Summary:** ${counts.critical} Critical, ${counts.high} High, ${counts.medium} Medium, ${counts.low} Low

---

## Findings Details

${findingsSection}
`;
}
