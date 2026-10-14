import type { Rule, RuleMatch } from "../types.js";
import { entropy, regexMatches } from "./util.js";

export interface JwtInspectionResult {
  validStructure: boolean;
  algorithm?: string;
  tokenType?: string;
  isUnsignedNoneAlg: boolean;
  isExpired?: boolean;
  expiresAt?: number;
  issuedAt?: number;
  sensitiveClaims: string[];
  header?: Record<string, unknown>;
  payloadKeys: string[];
}

const SENSITIVE_JWT_CLAIMS = new Set([
  "email",
  "sub",
  "role",
  "roles",
  "permissions",
  "scope",
  "scp",
  "admin",
  "is_admin",
  "phone_number",
  "api_key",
  "secret",
  "groups",
]);

function decodeBase64UrlJson(segment: string): Record<string, unknown> | null {
  try {
    const normalized = segment.replace(/-/g, "+").replace(/_/g, "/");
    const padLen = (4 - (normalized.length % 4)) % 4;
    const padded = normalized + "=".repeat(padLen);
    const jsonText = Buffer.from(padded, "base64").toString("utf8");
    const parsed: unknown = JSON.parse(jsonText);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Inspects a JWT string without exposing raw claim values, checking structural validity,
 * insecure `alg: "none"` configuration, expiration (`exp`), and sensitive payload claim names.
 */
export function inspectJwtToken(
  token: string,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): JwtInspectionResult {
  const parts = token.trim().split(".");
  if (parts.length !== 3 || !parts[0] || !parts[1]) {
    return {
      validStructure: false,
      isUnsignedNoneAlg: false,
      sensitiveClaims: [],
      payloadKeys: [],
    };
  }

  const header = decodeBase64UrlJson(parts[0]);
  const payload = decodeBase64UrlJson(parts[1]);
  if (!header || !payload) {
    return {
      validStructure: false,
      isUnsignedNoneAlg: false,
      sensitiveClaims: [],
      payloadKeys: [],
    };
  }

  const algorithm = typeof header.alg === "string" ? header.alg : undefined;
  const tokenType = typeof header.typ === "string" ? header.typ : undefined;
  const signature = parts[2] ?? "";
  const isUnsignedNoneAlg =
    (algorithm !== undefined && algorithm.toLowerCase() === "none") || signature.length === 0;

  const expiresAt = typeof payload.exp === "number" ? payload.exp : undefined;
  const issuedAt = typeof payload.iat === "number" ? payload.iat : undefined;
  const isExpired = expiresAt !== undefined ? expiresAt < nowSeconds : undefined;

  const payloadKeys = Object.keys(payload);
  const sensitiveClaims = payloadKeys.filter((k) => SENSITIVE_JWT_CLAIMS.has(k.toLowerCase()));

  return {
    validStructure: true,
    algorithm,
    tokenType,
    isUnsignedNoneAlg,
    isExpired,
    expiresAt,
    issuedAt,
    sensitiveClaims,
    header,
    payloadKeys,
  };
}

function secret(
  id: string,
  description: string,
  re: RegExp,
  severity: Rule["severity"] = "critical",
): Rule {
  return {
    id,
    category: "secret",
    severity,
    description,
    targets: ["prompt", "output"],
    detect: (t) => regexMatches(t, re, description),
  };
}

export const secretRules: Rule[] = [
  secret("SEC001", "AWS access key ID", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/),
  secret("SEC002", "Google API key", /\bAIza[0-9A-Za-z_-]{35}\b/),
  secret("SEC003", "OpenAI API key", /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}\b/),
  secret("SEC004", "GitHub token", /\bgh[pousr]_[A-Za-z0-9]{36,}\b/),
  secret("SEC005", "Slack token", /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/),
  secret(
    "SEC006",
    "Private key block",
    /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----/,
  ),
  {
    id: "SEC007",
    category: "secret",
    severity: "high",
    description: "JSON Web Token",
    targets: ["prompt", "output"],
    detect: (t) => {
      const out: RuleMatch[] = [];
      const jwtRe = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.(?:[A-Za-z0-9_-]{8,})?(?![A-Za-z0-9_-])/g;
      for (const m of t.matchAll(jwtRe)) {
        const info = inspectJwtToken(m[0]);
        // Require either a non-empty signature or a valid decoded JWT header with alg:none
        const hasSig = (m[0].split(".")[2] ?? "").length >= 8;
        if (!hasSig && !info.validStructure) continue;
        let message = "JSON Web Token";
        if (info.validStructure && info.isUnsignedNoneAlg) {
          message = "JSON Web Token (insecure unsigned alg=none)";
        } else if (info.validStructure && info.sensitiveClaims.length > 0) {
          message = `JSON Web Token (claims: ${info.sensitiveClaims.join(", ")})`;
        }
        out.push({
          start: m.index!,
          end: m.index! + m[0].length,
          message,
        });
      }
      return out;
    },
  },
  secret(
    "SEC008",
    "Generic credential assignment",
    /\b(?:api[_-]?key|secret|token|passw(?:or)?d)\b["']?\s*[:=]\s*["'][^"'\s]{12,}["']/i,
    "high",
  ),
  {
    id: "SEC009",
    category: "secret",
    severity: "medium",
    description: "High-entropy string (possible unknown secret)",
    targets: ["prompt", "output"],
    detect: (t) =>
      regexMatches(t, /[A-Za-z0-9+/_=-]{24,}/, "High-entropy token").filter((m) => {
        const s = t.slice(m.start, m.end);
        // Exclude pure hex hashes, checksums and 0x addresses
        if (/^(?:0x)?[0-9a-fA-F]+$/i.test(s)) return false;
        // require letters + digits and high entropy to avoid long words / paths
        return /[A-Za-z]/.test(s) && /\d/.test(s) && entropy(s) >= 4.0;
      }),
  },
  {
    id: "SEC010",
    category: "secret",
    severity: "high",
    description: "Server/host credential leak",
    targets: ["prompt", "output"],
    detect: (t) =>
      regexMatches(
        t,
        /\b(?:server|host|database|db)\s+(?:at\s+)?(?:\d{1,3}\.){3}\d{1,3}\s+(?:user|username|pass|password)\s+\S+/i,
        "Server credential leak",
      ),
  },
  secret(
    "SEC011",
    "Anthropic or Hugging Face API token",
    /\b(?:sk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{30,})\b/,
  ),
  secret(
    "SEC012",
    "Stripe API key or npm access token",
    /\b(?:(?:sk|rk)_(?:live|test)_[A-Za-z0-9_]{16,}|npm_[A-Za-z0-9]{36,})\b/,
  ),
  secret(
    "SEC013",
    "Database or broker connection URI with embedded credentials",
    /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?):\/\/[^:\s/@"']+:[^@\s/"']+@[A-Za-z0-9._-]+(?::\d{2,5})?(?:\/[^\s"']*)?/i,
  ),
  secret(
    "SEC014",
    "Azure Storage AccountKey or SendGrid API key",
    /(?:\bAccountKey=[A-Za-z0-9+/]{40,}={0,2}|\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b)/,
  ),
];
