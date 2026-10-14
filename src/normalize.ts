import { audit } from "./engine.js";
import { redact } from "./rules/util.js";
import { SEVERITY_ORDER } from "./types.js";
import type { AuditOptions, AuditResult, Finding } from "./types.js";

/** Common visual homoglyphs and confusables mapped to standard Latin characters. */
const HOMOGLYPHS: Record<string, string> = {
  // Cyrillic lowercase
  "\u0430": "a", // а
  "\u0432": "b", // в
  "\u0433": "r", // г
  "\u0435": "e", // е
  "\u043A": "k", // к
  "\u043C": "m", // м
  "\u043D": "h", // н
  "\u043E": "o", // о
  "\u043F": "n", // п
  "\u0440": "p", // р
  "\u0441": "c", // с
  "\u0442": "t", // т
  "\u0443": "y", // у
  "\u0445": "x", // х
  "\u0454": "e", // Ukrainian є
  "\u0456": "i", // Ukrainian і
  "\u0457": "i", // Ukrainian ї
  "\u0458": "j", // Serbian ј
  "\u0455": "s", // Macedonian ѕ
  "\u0501": "d", // Komi ԁ
  "\u051B": "q", // Cyrillic ԛ
  "\u051D": "w", // Cyrillic ԝ

  // Cyrillic uppercase
  "\u0410": "A", // А
  "\u0412": "B", // В
  "\u0413": "F", // Г
  "\u0415": "E", // Е
  "\u041D": "H", // Н
  "\u041A": "K", // К
  "\u041C": "M", // М
  "\u041E": "O", // О
  "\u041F": "N", // П
  "\u0420": "P", // Р
  "\u0421": "C", // С
  "\u0422": "T", // Т
  "\u0423": "Y", // У
  "\u0425": "X", // Х
  "\u0404": "E", // Ukrainian Є
  "\u0406": "I", // Ukrainian І
  "\u0407": "I", // Ukrainian Ї
  "\u0408": "J", // Serbian Ј
  "\u0405": "S", // Macedonian Ѕ

  // Greek lowercase
  "\u03B1": "a", // α
  "\u03B2": "b", // β
  "\u03B5": "e", // ε
  "\u03B7": "n", // η
  "\u03B9": "i", // ι
  "\u03BA": "k", // κ
  "\u03BD": "v", // ν
  "\u03BF": "o", // ο
  "\u03C1": "p", // ρ
  "\u03C4": "t", // τ
  "\u03C5": "u", // υ
  "\u03C7": "x", // χ
  "\u03C9": "w", // ω

  // Greek uppercase
  "\u0391": "A", // Α
  "\u0392": "B", // Β
  "\u0395": "E", // Ε
  "\u0396": "Z", // Ζ
  "\u0397": "H", // Η
  "\u0399": "I", // Ι
  "\u039A": "K", // Κ
  "\u039C": "M", // Μ
  "\u039D": "N", // Ν
  "\u039F": "O", // Ο
  "\u03A1": "P", // Ρ
  "\u03A4": "T", // Τ
  "\u03A5": "Y", // Υ
  "\u03A7": "X", // Χ

  // Latin IPA / lookalikes
  "\u0251": "a", // ɑ
  "\u0252": "o", // ɒ
  "\u0261": "g", // ɡ
  "\u0269": "i", // ɩ
  "\u026A": "I", // ɪ
  "\u026B": "l", // ɫ
  "\u026C": "l", // ɬ
  "\u0275": "o", // ɵ
  "\u027F": "r", // ɿ
  "\u0281": "r", // ʁ
  "\u0282": "s", // ʂ
  "\u0283": "s", // ʃ
  "\u0287": "t", // ʇ
  "\u028A": "u", // ʊ
  "\u028B": "v", // ʋ
  "\u028C": "v", // ʌ
  "\u028D": "w", // ʍ
  "\u028F": "Y", // ʏ
  "\u0290": "z", // ʐ
  "\u0291": "z", // ʑ
  "\u0292": "z", // ʒ
};

/** Standard leetspeak substitutions. */
const LEET_MAP: Record<string, string> = {
  "0": "o",
  "1": "i",
  "3": "e",
  "4": "a",
  "5": "s",
  "7": "t",
  "@": "a",
  "$": "s",
};

/** Returns true for zero-width, invisible, and format control characters. */
function isInvisible(codePoint: number): boolean {
  return (
    (codePoint >= 0x200b && codePoint <= 0x200f) || // Zero-width space, marks
    (codePoint >= 0x202a && codePoint <= 0x202e) || // Directional formatting
    (codePoint >= 0x2060 && codePoint <= 0x2064) || // Word joiner, invisible operators
    (codePoint >= 0x2066 && codePoint <= 0x2069) || // Directional isolates
    codePoint === 0xfeff || // Zero-width no-break space / BOM
    codePoint === 0x00ad // Soft hyphen
  );
}

export interface NormalizeOptions {
  /** If true, decode basic leetspeak substitutions ('1'->'i', '3'->'e', etc.). Default false. */
  leet?: boolean;
}

export interface NormalizeResult {
  normalized: string;
  mapIndex: (normIdx: number) => number;
}

/**
 * Normalizes text to counter adversarial obfuscation:
 * - Homoglyphs/confusables (Cyrillic, Greek, IPA -> Latin)
 * - Fullwidth characters (FF01-FF5E -> ASCII, U+3000 -> space)
 * - Strips invisible and zero-width characters (U+200B-U+200F, U+FEFF, U+2060, etc.)
 * - Strips combining diacritics and decomposes accented Latin letters
 * - Optionally decodes leetspeak ('1'->'i', '3'->'e', '0'->'o', '4'->'a', '5'->'s', '7'->'t')
 * - Preserves index mapping from normalized coordinates back to original text coordinates
 */
export function normalizeText(text: string, options?: NormalizeOptions): NormalizeResult {
  const normChars: string[] = [];
  const origIndices: number[] = [];
  const origEndIndices: number[] = [];

  let i = 0;
  while (i < text.length) {
    const codePoint = text.codePointAt(i)!;
    const codeUnitLength = codePoint > 0xffff ? 2 : 1;
    const startIdx = i;
    const endIdx = i + codeUnitLength;
    i += codeUnitLength;

    // 1. Skip zero-width & invisible characters
    if (isInvisible(codePoint)) {
      continue;
    }

    // 2. Skip combining diacritical marks
    if (codePoint >= 0x0300 && codePoint <= 0x036f) {
      continue;
    }

    let ch: string;

    // 3. Fullwidth characters (FF01..FF5E -> ASCII, 3000 -> space)
    if (codePoint >= 0xff01 && codePoint <= 0xff5e) {
      ch = String.fromCharCode(codePoint - 0xfee0);
    } else if (codePoint === 0x3000) {
      ch = " ";
    } else {
      const rawChar = String.fromCodePoint(codePoint);
      if (HOMOGLYPHS[rawChar]) {
        ch = HOMOGLYPHS[rawChar];
      } else if (
        (codePoint >= 0x1d400 && codePoint <= 0x1d7ff) ||
        (codePoint >= 0x24b6 && codePoint <= 0x24e9)
      ) {
        ch = rawChar.normalize("NFKD");
      } else {
        ch = rawChar;
      }
    }

    // 4. Decompose accents on Latin characters if any
    if (ch.length > 0) {
      ch = ch.normalize("NFKD").replace(/[\u0300-\u036F]/g, "");
    }

    // 5. Optional leetspeak decoding
    if (options?.leet) {
      if (LEET_MAP[ch]) {
        ch = LEET_MAP[ch];
      } else if (ch === "!" && i < text.length && /[a-zA-Z]/.test(text[i])) {
        ch = "i";
      }
    }

    for (let c = 0; c < ch.length; c++) {
      normChars.push(ch[c]);
      origIndices.push(startIdx);
      origEndIndices.push(endIdx);
    }
  }

  const normalized = normChars.join("");
  const N = normalized.length;

  const mapIndex = (normIdx: number): number => {
    if (N === 0) return 0;
    if (normIdx <= 0) return 0;
    if (normIdx >= N) return origEndIndices[N - 1] ?? text.length;
    return origIndices[normIdx];
  };

  return { normalized, mapIndex };
}

/**
 * Decodes basic leetspeak patterns in text:
 * '1gn0r3' -> 'ignore', '3'->'e', '1'->'i', '0'->'o', '4'->'a', '5'->'s', '7'->'t', '@'->'a', '$'->'s'.
 */
export function normalizeLeetspeak(text: string): string {
  return text
    .replace(/[\uFF01-\uFF5E]/g, (c) => String.fromCharCode(c.charCodeAt(0) - 0xfee0))
    .replace(/[013457@$]/g, (ch) => LEET_MAP[ch] ?? ch)
    .replace(/!(?=[a-zA-Z])/g, "i");
}

/**
 * Audits text with adversarial deobfuscation:
 * 1. Audits raw text.
 * 2. Audits normalized text (homoglyphs, fullwidth, zero-width stripped).
 * 3. Audits leetspeak-normalized text (handling mixed leet + homoglyphs).
 * Mappping findings back to original text coordinates and deduplicating by (ruleId, start, end).
 */
export function auditWithNormalization(text: string, options: AuditOptions = {}): AuditResult {
  const allFindings: Finding[] = [];

  // 1. Raw text audit
  const rawResult = audit(text, options);
  allFindings.push(...rawResult.findings);

  // 2. Homoglyph & fullwidth & zero-width normalization
  const norm = normalizeText(text, { leet: false });
  if (norm.normalized !== text) {
    const normResult = audit(norm.normalized, { ...options, schema: undefined });
    for (const f of normResult.findings) {
      const start = norm.mapIndex(f.start);
      const end = norm.mapIndex(f.end);
      allFindings.push({
        ...f,
        start,
        end,
        match: redact(text.slice(start, end)),
      });
    }
  }

  // 3. Combined leetspeak + homoglyph normalization
  const normLeet = normalizeText(text, { leet: true });
  if (normLeet.normalized !== text && normLeet.normalized !== norm.normalized) {
    const leetResult = audit(normLeet.normalized, { ...options, schema: undefined });
    for (const f of leetResult.findings) {
      const start = normLeet.mapIndex(f.start);
      const end = normLeet.mapIndex(f.end);
      allFindings.push({
        ...f,
        start,
        end,
        match: redact(text.slice(start, end)),
      });
    }
  }

  // Deduplicate findings by (ruleId, start, end)
  const seen = new Set<string>();
  const uniqueFindings: Finding[] = [];
  for (const f of allFindings) {
    const key = `${f.ruleId}:${f.start}:${f.end}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniqueFindings.push(f);
    }
  }

  uniqueFindings.sort(
    (a, b) =>
      SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
      a.start - b.start ||
      a.end - b.end,
  );

  return {
    ok: uniqueFindings.length === 0,
    findings: uniqueFindings,
  };
}
