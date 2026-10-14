import type { Rule } from "../types.js";
import { luhn, regexMatches } from "./util.js";

const SPANISH_ID_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE";
const CURP_CHARSET = "0123456789ABCDEFGHIJKLMNÑOPQRSTUVWXYZ";

const CURP_REGEX =
  /^[A-Z][AEIOUX][A-Z]{2}(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[HMX](AS|BC|BS|CC|CS|CH|CL|CM|DF|DG|GT|GR|HG|JC|MC|MN|MS|NT|NL|OC|PL|QT|QR|SP|SL|SR|TC|TS|TL|VZ|YN|ZS|NE)[B-DF-HJ-NP-TV-Z]{3}[A-Z0-9]\d$/;

/** Computes the official RENAPO Modulo-10 check digit for the first 17 characters of a Mexican CURP. */
export function computeCurpCheckDigit(curp17: string): number {
  const upper = curp17.toUpperCase();
  let sum = 0;
  for (let i = 0; i < 17; i++) {
    const idx = CURP_CHARSET.indexOf(upper[i] ?? "");
    if (idx === -1) return -1;
    sum += idx * (18 - i);
  }
  return (10 - (sum % 10)) % 10;
}

/**
 * Validates a Mexican CURP (18 characters): checks RENAPO state code, consonant block,
 * calendar month/day bounds, and optionally the Modulo-10 check digit.
 */
export function validateMexicanCurp(value: string, strictChecksum = false): boolean {
  const upper = value.trim().toUpperCase();
  const m = upper.match(CURP_REGEX);
  if (!m) return false;
  const month = Number(m[2]);
  const day = Number(m[3]);
  if (month === 2 && day > 29) return false;
  if ([4, 6, 9, 11].includes(month) && day > 30) return false;
  if (strictChecksum) {
    const expected = computeCurpCheckDigit(upper.slice(0, 17));
    return expected === Number(upper[17]);
  }
  return true;
}

/**
 * Validates a Spanish DNI (8 digits + letter) or NIE (X/Y/Z + 7 digits + letter)
 * using the official Interior Ministry Modulo-23 check letter.
 */
export function validateSpanishId(value: string): boolean {
  const clean = value.trim().toUpperCase().replace(/[-\s]/g, "");
  if (!/^(?:\d{8}|[XYZ]\d{7})[A-HJ-NP-TV-Z]$/.test(clean)) return false;
  const prefixReplaced = clean
    .slice(0, 8)
    .replace(/^X/, "0")
    .replace(/^Y/, "1")
    .replace(/^Z/, "2");
  const num = Number.parseInt(prefixReplaced, 10);
  if (Number.isNaN(num)) return false;
  const expectedLetter = SPANISH_ID_LETTERS[num % 23];
  return clean[8] === expectedLetter;
}

/**
 * Validates a Brazilian CPF (11 digits) using the official two-digit Modulo-11 checksum
 * and rejecting uniform repeated-digit sequences.
 */
export function validateBrazilianCpf(value: string): boolean {
  const digits = value.replace(/\D/g, "");
  if (digits.length !== 11 || /^(\d)\1{10}$/.test(digits)) return false;

  let sum1 = 0;
  for (let i = 0; i < 9; i++) {
    sum1 += (digits.charCodeAt(i) - 48) * (10 - i);
  }
  const rem1 = (sum1 * 10) % 11;
  const check1 = rem1 === 10 ? 0 : rem1;
  if (check1 !== digits.charCodeAt(9) - 48) return false;

  let sum2 = 0;
  for (let i = 0; i < 10; i++) {
    sum2 += (digits.charCodeAt(i) - 48) * (11 - i);
  }
  const rem2 = (sum2 * 10) % 11;
  const check2 = rem2 === 10 ? 0 : rem2;
  return check2 === digits.charCodeAt(10) - 48;
}

export const piiRules: Rule[] = [
  {
    id: "PII001",
    category: "pii",
    severity: "medium",
    description: "Email address",
    targets: ["prompt", "output"],
    detect: (t) =>
      regexMatches(t, /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/, "Email address"),
  },
  {
    id: "PII002",
    category: "pii",
    severity: "high",
    description: "Credit card number (Luhn-validated)",
    targets: ["prompt", "output"],
    detect: (t) =>
      regexMatches(t, /\b(?:\d[ -]?){13,19}\b/, "Credit card number").filter((m) => {
        const digits = t.slice(m.start, m.end).replace(/[ -]/g, "");
        return digits.length >= 13 && digits.length <= 19 && luhn(digits);
      }),
  },
  {
    id: "PII003",
    category: "pii",
    severity: "high",
    description: "US Social Security Number",
    targets: ["prompt", "output"],
    detect: (t) =>
      regexMatches(t, /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/, "US SSN"),
  },
  {
    id: "PII004",
    category: "pii",
    severity: "medium",
    description: "IBAN",
    targets: ["prompt", "output"],
    detect: (t) =>
      regexMatches(t, /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,4})?\b/, "IBAN"),
  },
  {
    id: "PII005",
    category: "pii",
    severity: "low",
    description: "Phone number (international format)",
    targets: ["prompt", "output"],
    detect: (t) =>
      regexMatches(
        t,
        /(?<![\w.])\+\d{1,3}[ -]?\(?\d{2,4}\)?[ -]?\d{3,4}[ -]?\d{3,4}\b/,
        "Phone number",
      ),
  },
  {
    id: "PII006",
    category: "pii",
    severity: "high",
    description: "Passport number or Date of Birth (DOB)",
    targets: ["prompt", "output"],
    detect: (t) =>
      regexMatches(
        t,
        /\b(?:passport(?:\s+(?:number|no|#))?[:\s]+[A-Z0-9]{6,12}|DOB[:\s]+\d{4}[-/.]\d{2}[-/.]\d{2})\b/i,
        "Passport or Date of Birth",
      ),
  },
  {
    id: "PII007",
    category: "pii",
    severity: "high",
    description: "Mexican CURP personal identifier",
    targets: ["prompt", "output"],
    detect: (t) =>
      regexMatches(
        t,
        /\b[A-Z][AEIOUX][A-Z]{2}\d{6}[HMX][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[A-Z0-9]\d\b/,
        "Mexican CURP",
      ).filter((m) => validateMexicanCurp(t.slice(m.start, m.end))),
  },
  {
    id: "PII008",
    category: "pii",
    severity: "high",
    description: "Spanish DNI or NIE national identifier (Modulo-23 validated)",
    targets: ["prompt", "output"],
    detect: (t) =>
      regexMatches(
        t,
        /\b(?:\d{8}|[XYZ]\d{7})-?[A-HJ-NP-TV-Z]\b/,
        "Spanish DNI/NIE",
      ).filter((m) => validateSpanishId(t.slice(m.start, m.end))),
  },
  {
    id: "PII009",
    category: "pii",
    severity: "high",
    description: "Brazilian CPF tax identifier (Modulo-11 validated)",
    targets: ["prompt", "output"],
    detect: (t) =>
      regexMatches(
        t,
        /\b(?:\d{3}\.\d{3}\.\d{3}-\d{2}|CPF[:\s#-]*\d{11})\b/i,
        "Brazilian CPF",
      ).filter((m) => validateBrazilianCpf(t.slice(m.start, m.end))),
  },
];
