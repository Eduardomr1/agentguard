import type { Rule, RuleMatch } from "../types.js";
import { regexMatches } from "./util.js";

function containsEncodedDirective(decoded: string): boolean {
  if (!decoded || decoded.includes("\ufffd")) return false;
  return /\b(ignore|disregard|forget|override)\b[\s\S]{0,40}\b(instructions?|prompts?|rules?|directives?|guardrails?)\b|\bsystem\s+prompt\b|\b(?:you\s+are\s+DAN|do\s+anything\s+now|developer\s+mode)\b/i.test(
    decoded,
  );
}

export const injectionRules: Rule[] = [
  {
    id: "INJ001",
    category: "injection",
    severity: "high",
    description: "Instruction override ('ignore previous instructions')",
    targets: ["prompt"],
    detect: (t) =>
      regexMatches(
        t,
        /\b(ignore|disregard|forget|override)\b[^.\n]{0,30}(?:\b(previous|prior|above|earlier|all|system)\b[^.\n]{0,30}\b(instructions?|prompts?|rules?|directives?|guidelines?|constraints?|guardrails?)\b|\beverything\s+(?:you\s+were\s+told|prior|above)\b|\byour\s+(?:instructions?|guidelines?|rules?|directives?|guardrails?)\b)/i,
        "Attempt to override prior instructions",
      ),
  },
  {
    id: "INJ002",
    category: "injection",
    severity: "high",
    description: "System prompt exfiltration",
    targets: ["prompt"],
    detect: (t) =>
      regexMatches(
        t,
        /\b(?:(?:reveal|show|print|repeat|leak|output|display)\b[^.\n]{0,30}\b(system|initial|hidden|original)\s+(prompt|instructions?|message)\b|what\s+(?:is|was)\s+(?:your\s+)?(system|initial|hidden|original)\s+(prompt|instructions?|message)\b)/i,
        "Attempt to extract the system prompt",
      ),
  },
  {
    id: "INJ003",
    category: "injection",
    severity: "medium",
    description: "Jailbreak persona (DAN / developer mode / unfiltered)",
    targets: ["prompt"],
    detect: (t) =>
      regexMatches(
        t,
        /\b(?:you\s+are\s+DAN\b|as\s+DAN\b|DAN\s+(?:mode|persona|jailbreak)\b|DAN\s*:\s*do\s+anything\s+now|do\s+anything\s+now\b|(?:enable|enter|activate|turn\s+on|switch\s+to)\s+developer\s+mode\b|developer\s+mode\s+(?:is\s+)?(?:enabled|activated|on|output)\b|jailbreak(?:ed)?\b|no\s+(?:restrictions|filters|limitations)|without\s+(?:any\s+)?(?:restrictions|filters|limitations)|unfiltered\s+(?:ai|assistant|model|mode)\b)/i,
        "Known jailbreak phrasing",
      ),
  },
  {
    id: "INJ004",
    category: "injection",
    severity: "medium",
    description: "Role/delimiter spoofing (fake system turn)",
    targets: ["prompt"],
    detect: (t) =>
      regexMatches(
        t,
        /(^|\n)\s*(#{2,}\s*)?(system|assistant)\s*:|<\|(?:im_start|im_end|system)\|>|\[\/?INST\]/i,
        "Spoofed role marker or chat-template token",
      ),
  },
  {
    id: "INJ005",
    category: "injection",
    severity: "low",
    description: "Hidden/zero-width characters",
    targets: ["prompt", "output"],
    detect: (t) => regexMatches(t, /[\u200B-\u200F\u202A-\u202E\u2060\uFEFF]/, "Invisible Unicode characters"),
  },
  {
    id: "INJ006",
    category: "injection",
    severity: "high",
    description: "Instruction override in Spanish, French or German",
    targets: ["prompt"],
    detect: (t) =>
      regexMatches(
        t,
        new RegExp(
          [
            "\\b(ignora|olvida|omite|descarta)\\b[^.\\n]{0,30}\\b(instrucciones|indicaciones|reglas)\\b[^.\\n]{0,20}\\b(anteriores|previas|previos|del sistema)\\b",
            "\\b(ignora|olvida)\\b[^.\\n]{0,15}\\b(todo lo anterior|todas las instrucciones)\\b",
            "\\b(ignore[zr]?|oublie[zr]?|néglige[zr]?)\\b[^.\\n]{0,30}\\b(instructions|consignes|règles|regles)\\b[^.\\n]{0,20}\\b(précédentes|precedentes|antérieures|anterieures|ci-dessus|du système|du systeme)\\b",
            "\\b(ignoriere|ignorieren sie|vergiss|vergessen sie|missachte)\\b[^.\\n]{0,30}\\b(anweisungen|instruktionen|regeln|befehle)\\b",
          ].join("|"),
          "i",
        ),
        "Multilingual attempt to override prior instructions",
      ),
  },
  {
    id: "INJ007",
    category: "injection",
    severity: "high",
    description: "Base64-encoded injection payload",
    targets: ["prompt", "output"],
    detect: (t) => {
      const out: RuleMatch[] = [];
      for (const m of t.matchAll(/[A-Za-z0-9+/]{24,}={0,2}/g)) {
        const decoded = Buffer.from(m[0], "base64").toString("utf8");
        if (containsEncodedDirective(decoded)) {
          out.push({
            start: m.index!,
            end: m.index! + m[0].length,
            message: "Base64 payload decodes to injection text",
          });
        }
      }
      return out;
    },
  },
  {
    id: "INJ008",
    category: "injection",
    severity: "high",
    description: "Indirect injection in retrieved content",
    targets: ["prompt", "output"],
    detect: (t) =>
      regexMatches(
        t,
        /\b(when|if)\s+(the\s+)?(assistant|ai|model|llm|agent)\s+(reads?|sees?|processes|retrieves?)\s+this\b|(^|\n)\s*[[<]?\s*(IMPORTANT|ATTENTION|NOTE TO (?:THE )?(?:ASSISTANT|AI))\s*[\]>]?\s*:\s*(new|updated|override)\s+instructions?\b/i,
        "Instructions embedded in retrieved content aimed at the assistant",
      ),
  },
  {
    id: "INJ009",
    category: "injection",
    severity: "high",
    description: "Markdown image data exfiltration",
    targets: ["output"],
    detect: (t) =>
      regexMatches(
        t,
        /!\[[^\]]*\]\(\s*https?:\/\/[^)\s]*\?[^)\s]*(?:data|q|d|content|secret|token|prompt|history)=[^)\s]{40,}\)/i,
        "Markdown image URL carries long query payload (possible exfiltration)",
      ),
  },
  {
    id: "INJ010",
    category: "injection",
    severity: "high",
    description: "Unicode Tag block steganography or bidirectional override smuggling",
    targets: ["prompt", "output"],
    detect: (t) => {
      const out: RuleMatch[] = [];
      for (const m of t.matchAll(/[\u{E0000}-\u{E007F}]{2,}/gu)) {
        const start = m.index!;
        // Exclude subdivision emoji flag sequences immediately preceded by WAVING BLACK FLAG (U+1F3F4)
        const prevPair = start >= 2 ? t.codePointAt(start - 2) : undefined;
        if (prevPair === 0x1f3f4) continue;
        let ascii = "";
        for (const ch of m[0]) {
          const cp = ch.codePointAt(0)!;
          if (cp >= 0xe0020 && cp <= 0xe007e) ascii += String.fromCharCode(cp - 0xe0000);
        }
        const message = containsEncodedDirective(ascii)
          ? "Unicode Tag block smuggles hidden prompt-injection directive"
          : "Invisible Unicode Tag block steganography detected";
        out.push({ start, end: start + m[0].length, message });
      }
      for (const m of t.matchAll(/[\u202D\u202E\u2066-\u2069]/g)) {
        out.push({
          start: m.index!,
          end: m.index! + m[0].length,
          message: "Bidirectional override/isolate control character (Trojan Source smuggling)",
        });
      }
      return out;
    },
  },
  {
    id: "INJ011",
    category: "injection",
    severity: "high",
    description: "Hex or URL-percent encoded injection payload",
    targets: ["prompt", "output"],
    detect: (t) => {
      const out: RuleMatch[] = [];
      // 1. Continuous or \x-escaped or space-separated hex byte sequences
      const hexPatterns = [
        /\b(?:0x)?([0-9a-fA-F]{32,})\b/g,
        /(?:\\x[0-9a-fA-F]{2}){16,}/g,
        /\b(?:[0-9a-fA-F]{2}\s+){15,}[0-9a-fA-F]{2}\b/g,
      ];
      for (const re of hexPatterns) {
        for (const m of t.matchAll(re)) {
          const cleanHex = m[0].replace(/^0x/i, "").replace(/\\x|\s+/g, "");
          if (cleanHex.length % 2 !== 0) continue;
          const decoded = Buffer.from(cleanHex, "hex").toString("utf8");
          if (containsEncodedDirective(decoded)) {
            out.push({
              start: m.index!,
              end: m.index! + m[0].length,
              message: "Hex-encoded payload decodes to prompt-injection directive",
            });
          }
        }
      }
      // 2. URL percent-encoded sequences
      for (const m of t.matchAll(/(?:%[0-9a-fA-F]{2}[A-Za-z0-9_.~+-]*){8,}/g)) {
        try {
          const decoded = decodeURIComponent(m[0].replace(/\+/g, " "));
          if (containsEncodedDirective(decoded)) {
            out.push({
              start: m.index!,
              end: m.index! + m[0].length,
              message: "URL percent-encoded payload decodes to prompt-injection directive",
            });
          }
        } catch {
          // Malformed URI sequence
        }
      }
      return out;
    },
  },
  {
    id: "INJ012",
    category: "injection",
    severity: "high",
    description: "Hidden HTML/Markdown comment or zero-visibility style injection",
    targets: ["prompt", "output"],
    detect: (t) => {
      const out: RuleMatch[] = [];
      const directiveRe =
        /\b(ignore|disregard|forget|override|system\s+prompt|new\s+instructions?|assistant\s*:|you\s+are\s+now|do\s+not\s+mention|exfiltrate)\b/i;

      for (const m of t.matchAll(/<!--([\s\S]{1,1500}?)-->/g)) {
        if (directiveRe.test(m[1])) {
          out.push({
            start: m.index!,
            end: m.index! + m[0].length,
            message: "HTML/Markdown comment embeds hidden instructions",
          });
        }
      }

      const hiddenTagRe =
        /<([a-zA-Z][a-zA-Z0-9]*)\b[^>]*\bstyle\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?(?=[;"'\s])|font-size\s*:\s*0(?:px|pt|em|rem|%)?(?=[;"'\s]))[^"']*["'][^>]*>([\s\S]{1,1500}?)<\/\1>/gi;
      for (const m of t.matchAll(hiddenTagRe)) {
        if (directiveRe.test(m[2])) {
          out.push({
            start: m.index!,
            end: m.index! + m[0].length,
            message: "Zero-visibility HTML element embeds hidden instructions",
          });
        }
      }
      return out;
    },
  },
];
