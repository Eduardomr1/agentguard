import type { Rule } from "../types.js";
import { entropy, regexMatches } from "./util.js";

function secret(id: string, description: string, re: RegExp, severity: Rule["severity"] = "critical"): Rule {
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
  secret("SEC003", "OpenAI API key", /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/),
  secret("SEC004", "GitHub token", /\bgh[pousr]_[A-Za-z0-9]{36,}\b/),
  secret("SEC005", "Slack token", /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/),
  secret("SEC006", "Private key block", /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----/),
  secret("SEC007", "JSON Web Token", /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/, "high"),
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
];
