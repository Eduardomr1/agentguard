import type { Rule } from "../types.js";
import { luhn, regexMatches } from "./util.js";

export const piiRules: Rule[] = [
  {
    id: "PII001",
    category: "pii",
    severity: "medium",
    description: "Email address",
    targets: ["prompt", "output"],
    detect: (t) => regexMatches(t, /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/, "Email address"),
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
    detect: (t) => regexMatches(t, /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,4})?\b/, "IBAN"),
  },
  {
    id: "PII005",
    category: "pii",
    severity: "low",
    description: "Phone number (international format)",
    targets: ["prompt", "output"],
    detect: (t) => regexMatches(t, /(?<![\w.])\+\d{1,3}[ -]?\(?\d{2,4}\)?[ -]?\d{3,4}[ -]?\d{3,4}\b/, "Phone number"),
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
];
