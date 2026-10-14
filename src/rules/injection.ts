import type { Rule, RuleMatch } from "../types.js";
import { regexMatches } from "./util.js";

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
        if (decoded.includes("\ufffd")) continue;
        if (/\b(ignore|disregard)\b[\s\S]{0,40}\b(instructions?|prompts?)\b|system\s+prompt/i.test(decoded)) {
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
];
