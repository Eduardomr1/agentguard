import { createHash } from "node:crypto";
import { audit } from "./engine.js";
import { SEVERITY_ORDER } from "./types.js";
import type { AuditOptions, Category, Finding } from "./types.js";

export type MaskMode = "redact" | "hash" | "synthetic";

export interface PseudonymizeOptions {
  mode?: MaskMode;
  salt?: string;
  preserveStructure?: boolean;
  categories?: Category[];
}

export interface PseudonymizeResult {
  text: string;
  mapping: Map<string, string>;
  reverseMapping: Map<string, string>;
  deanonymize: (response: string) => string;
  findings: Finding[];
}

class CounterMap {
  private counts = new Map<string, number>();

  next(key: string): number {
    const current = (this.counts.get(key) ?? 0) + 1;
    this.counts.set(key, current);
    return current;
  }
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function formatHashPseudonym(
  finding: Finding,
  original: string,
  hash: string,
  preserveStructure: boolean,
): string {
  const { ruleId, category } = finding;

  if (ruleId === "PII001") {
    if (preserveStructure && original.includes("@")) {
      const domain = original.split("@")[1];
      return `email_${hash}@${domain}`;
    }
    return `email_${hash}@masked.local`;
  }

  if (ruleId === "PII002") {
    return `card_${hash}`;
  }

  if (ruleId === "PII003") {
    return `ssn_${hash}`;
  }

  if (ruleId === "PII004") {
    return `iban_${hash}`;
  }

  if (ruleId === "PII005") {
    return `phone_${hash}`;
  }

  if (ruleId === "PII006") {
    return /DOB/i.test(original) ? `dob_${hash}` : `passport_${hash}`;
  }

  if (ruleId === "PII007") return `curp_${hash}`;
  if (ruleId === "PII008") return `dni_${hash}`;
  if (ruleId === "PII009") return `cpf_${hash}`;

  // Secrets
  if (ruleId === "SEC001") return `aws_${hash}`;
  if (ruleId === "SEC002") return `google_${hash}`;
  if (ruleId === "SEC003") return `openai_${hash}`;
  if (ruleId === "SEC004") return `github_${hash}`;
  if (ruleId === "SEC005") return `slack_${hash}`;
  if (ruleId === "SEC006") return `privatekey_${hash}`;
  if (ruleId === "SEC007") return `jwt_${hash}`;
  if (ruleId === "SEC008") return `credential_${hash}`;
  if (ruleId === "SEC009") return `secret_${hash}`;
  if (ruleId === "SEC010") return `server_${hash}`;
  if (ruleId === "SEC011") return `aitoken_${hash}`;
  if (ruleId === "SEC012") return `pkgkey_${hash}`;
  if (ruleId === "SEC013") return `dburi_${hash}`;
  if (ruleId === "SEC014") return `cloudkey_${hash}`;

  if (category === "secret") return `secret_${hash}`;
  if (category === "pii") return `pii_${hash}`;
  return `${ruleId.toLowerCase()}_${hash}`;
}

function formatSyntheticPseudonym(
  finding: Finding,
  original: string,
  preserveStructure: boolean,
  counters: CounterMap,
): string {
  const { ruleId, category } = finding;

  if (ruleId === "PII001") {
    const count = counters.next("PII001");
    if (preserveStructure && original.includes("@")) {
      const domain = original.split("@")[1];
      return `user${count}@${domain}`;
    }
    return `user${count}@example.com`;
  }

  if (ruleId === "PII002") {
    const count = counters.next("PII002");
    const suffix = String(count * 10).padStart(4, "0");
    const defaultCard = `4000-1234-5678-${suffix}`;
    if (preserveStructure) {
      if (original.includes(" ")) {
        return defaultCard.replace(/-/g, " ");
      }
      if (!original.includes("-") && !original.includes(" ")) {
        return defaultCard.replace(/-/g, "");
      }
    }
    return defaultCard;
  }

  if (ruleId === "PII005") {
    const count = counters.next("PII005");
    const suffix = String(100 + count - 1).padStart(4, "0");
    const defaultPhone = `+1-555-${suffix}`;
    if (preserveStructure && original.includes(" ") && !original.includes("-")) {
      return defaultPhone.replace(/-/g, " ");
    }
    return defaultPhone;
  }

  if (ruleId === "PII003") {
    const count = counters.next("PII003");
    const suffix = String(6780 + count).padStart(4, "0");
    return `123-45-${suffix}`;
  }

  if (ruleId === "PII004") {
    const count = counters.next("PII004");
    const suffix = String(10 + count - 1).padStart(2, "0");
    if (preserveStructure && original.includes(" ")) {
      return `GB29 NWBK 6016 1331 9268 ${suffix}`;
    }
    return `GB29NWBK601613319268${suffix}`;
  }

  if (ruleId === "PII006") {
    if (/DOB/i.test(original)) {
      const count = counters.next("PII006_DOB");
      const year = 1990 + ((count - 1) % 30);
      return `DOB: ${year}-01-01`;
    }
    const count = counters.next("PII006_PASSPORT");
    const num = String(1000000 + count).slice(1);
    return `passport: A${num}`;
  }

  if (ruleId === "PII007") {
    const count = counters.next("PII007");
    const idx = String(count % 10);
    return `XXXX000101HDFXXX0${idx}`;
  }

  if (ruleId === "PII008") {
    const count = counters.next("PII008");
    const idx = String(10000000 + count);
    return `${idx}Z`;
  }

  if (ruleId === "PII009") {
    const count = counters.next("PII009");
    const suffix = String(count % 100).padStart(2, "0");
    return `000.000.000-${suffix}`;
  }

  if (ruleId === "SEC001") {
    const count = counters.next("SEC001");
    const idx = String(count).padStart(2, "0");
    return `AKIAIOSFODNN7EXAMP${idx}`;
  }

  if (ruleId === "SEC002") {
    const count = counters.next("SEC002");
    const idx = String(count).padStart(2, "0");
    return `AIzaSyEXAMPLE_KEY_00000000000000000${idx}`;
  }

  if (ruleId === "SEC003") {
    const count = counters.next("SEC003");
    const idx = String(count).padStart(2, "0");
    return `sk-proj-EXAMPLE000000000000000000000000000${idx}`;
  }

  if (ruleId === "SEC004") {
    const count = counters.next("SEC004");
    const idx = String(count).padStart(2, "0");
    return `ghp_EXAMPLE0000000000000000000000000000000${idx}`;
  }

  if (ruleId === "SEC005") {
    const count = counters.next("SEC005");
    const idx = String(count).padStart(2, "0");
    return `xoxb-EXAMPLE-TOKEN-00000000000000000000${idx}`;
  }

  if (ruleId === "SEC006") {
    return `-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC6EXAMPLE\n-----END PRIVATE KEY-----`;
  }

  if (ruleId === "SEC007") {
    const count = counters.next("SEC007");
    const idx = String(count).padStart(2, "0");
    return `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.synthetic_signature_${idx}`;
  }

  if (ruleId === "SEC008") {
    const count = counters.next("SEC008");
    const idx = String(count).padStart(2, "0");
    return `credential = "synthetic_secret_${idx}"`;
  }

  if (ruleId === "SEC009") {
    const count = counters.next("SEC009");
    const idx = String(count).padStart(2, "0");
    return `synthetic_secret_token_${idx}_xyz`;
  }

  if (ruleId === "SEC010") {
    const count = counters.next("SEC010");
    const idx = String(count).padStart(2, "0");
    return `server at 127.0.0.1 user admin password synthetic_pass_${idx}`;
  }

  if (ruleId === "SEC011") {
    const count = counters.next("SEC011");
    const idx = String(count).padStart(2, "0");
    return `sk-ant-api03-EXAMPLE000000000000000000${idx}`;
  }

  if (ruleId === "SEC012") {
    const count = counters.next("SEC012");
    const idx = String(count).padStart(2, "0");
    return `sk_test_EXAMPLE000000000000${idx}`;
  }

  if (ruleId === "SEC013") {
    const count = counters.next("SEC013");
    const idx = String(count).padStart(2, "0");
    return `postgres://user_${idx}:synthetic_pass@localhost:5432/app`;
  }

  if (ruleId === "SEC014") {
    const count = counters.next("SEC014");
    const idx = String(count).padStart(2, "0");
    return `SG.EXAMPLE_KEY_00000${idx}.EXAMPLE_SECRET_00000${idx}`;
  }

  if (category === "secret") {
    const count = counters.next("SECRET_GENERIC");
    const idx = String(count).padStart(2, "0");
    return `synthetic_secret_${idx}`;
  }

  if (category === "pii") {
    const count = counters.next("PII_GENERIC");
    return `synthetic_pii_${count}`;
  }

  const count = counters.next(ruleId);
  return `synthetic_${ruleId.toLowerCase()}_${count}`;
}

function generatePseudonym(
  finding: Finding,
  original: string,
  mode: MaskMode,
  salt: string,
  preserveStructure: boolean,
  counters: CounterMap,
  reverseMapping: Map<string, string>,
): string {
  if (mode === "redact") {
    return `[REDACTED:${finding.ruleId}]`;
  }

  if (mode === "hash") {
    const rawHash = createHash("sha256").update(salt + original).digest("hex");
    let hashLen = 4;
    let candidate = "";

    while (hashLen <= rawHash.length) {
      const h = rawHash.slice(0, hashLen);
      candidate = formatHashPseudonym(finding, original, h, preserveStructure);
      if (!reverseMapping.has(candidate) || reverseMapping.get(candidate) === original) {
        return candidate;
      }
      hashLen += 2;
    }
    return candidate;
  }

  // mode === "synthetic"
  return formatSyntheticPseudonym(finding, original, preserveStructure, counters);
}

export function pseudonymizeText(
  text: string,
  options?: AuditOptions & PseudonymizeOptions,
): PseudonymizeResult;
export function pseudonymizeText(
  text: string,
  findings: Finding[],
  options?: PseudonymizeOptions,
): PseudonymizeResult;
export function pseudonymizeText(
  text: string,
  findingsOrOptions?: Finding[] | (AuditOptions & PseudonymizeOptions),
  options?: PseudonymizeOptions,
): PseudonymizeResult {
  let findings: Finding[];
  let resolvedOptions: PseudonymizeOptions;

  if (Array.isArray(findingsOrOptions)) {
    findings = findingsOrOptions;
    resolvedOptions = options ?? {};
  } else if (findingsOrOptions && typeof findingsOrOptions === "object") {
    resolvedOptions = { ...findingsOrOptions, ...options };
    const auditOpts: AuditOptions = findingsOrOptions;
    findings = audit(text, auditOpts).findings;
  } else {
    resolvedOptions = options ?? {};
    findings = audit(text).findings;
  }

  const mode: MaskMode = resolvedOptions.mode ?? "hash";
  const salt = resolvedOptions.salt ?? "";
  const preserveStructure = Boolean(resolvedOptions.preserveStructure);
  const targetCategories = resolvedOptions.categories ?? ["secret", "pii"];

  const targetFindings = findings.filter((f) => targetCategories.includes(f.category));

  // Sort findings: start ascending, then longer spans first, then higher severity first
  const sortedFindings = [...targetFindings].sort(
    (a, b) =>
      a.start - b.start ||
      (b.end - b.start) - (a.end - a.start) ||
      SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity],
  );

  // Filter out overlapping spans
  const nonOverlapping: Finding[] = [];
  let lastEnd = 0;
  for (const f of sortedFindings) {
    if (f.start < lastEnd) continue;
    nonOverlapping.push(f);
    lastEnd = f.end;
  }

  const mapping = new Map<string, string>();
  const reverseMapping = new Map<string, string>();
  const normalizedKeyMap = new Map<string, string>();

  const counters = new CounterMap();

  for (const f of nonOverlapping) {
    const original = text.slice(f.start, f.end);
    const normKey = f.ruleId === "PII001" ? original.toLowerCase() : original;

    let pseudonym: string | undefined;

    if (mapping.has(original)) {
      pseudonym = mapping.get(original)!;
    } else if (normalizedKeyMap.has(normKey)) {
      pseudonym = normalizedKeyMap.get(normKey)!;
      mapping.set(original, pseudonym);
    } else {
      pseudonym = generatePseudonym(
        f,
        original,
        mode,
        salt,
        preserveStructure,
        counters,
        reverseMapping,
      );
      mapping.set(original, pseudonym);
      normalizedKeyMap.set(normKey, pseudonym);
      if (!reverseMapping.has(pseudonym)) {
        reverseMapping.set(pseudonym, original);
      }
    }
  }

  let out = "";
  let pos = 0;
  for (const f of nonOverlapping) {
    const original = text.slice(f.start, f.end);
    const pseudonym = mapping.get(original)!;
    out += text.slice(pos, f.start) + pseudonym;
    pos = f.end;
  }
  out += text.slice(pos);

  const deanonymize = (response: string): string => {
    if (!response || reverseMapping.size === 0) return response ?? "";
    const keys = Array.from(reverseMapping.keys())
      .filter((k) => k.length > 0)
      .sort((a, b) => b.length - a.length);
    if (keys.length === 0) return response;
    const pattern = new RegExp(keys.map(escapeRegex).join("|"), "g");
    return response.replace(pattern, (match) => reverseMapping.get(match) ?? match);
  };

  return {
    text: out,
    mapping,
    reverseMapping,
    deanonymize,
    findings,
  };
}
