import type { RuleMatch } from "../types.js";

export function regexMatches(text: string, re: RegExp, message?: string): RuleMatch[] {
  const flags = re.flags.includes("g") ? re.flags : re.flags + "g";
  const g = new RegExp(re.source, flags);
  const out: RuleMatch[] = [];
  for (const m of text.matchAll(g)) {
    out.push({ start: m.index!, end: m.index! + m[0].length, message });
  }
  return out;
}

/** Mask a matched value so reports never leak it. */
export function redact(value: string): string {
  if (value.length <= 8) return "*".repeat(value.length);
  return value.slice(0, 4) + "..." + "*".repeat(4) + ` (${value.length} chars)`;
}

/** Luhn checksum for credit-card validation. */
export function luhn(digits: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return digits.length > 0 && sum % 10 === 0;
}

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}
