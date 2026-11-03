import type { Rule, RuleMatch } from "../types.js";
import { detectMarkdownExfiltration } from "../markdownExfiltration.js";

export const exfiltrationRules: Rule[] = [
  {
    id: "EXF001",
    category: "exfiltration",
    severity: "critical",
    description: "Covert markdown or blind image exfiltration attempt",
    targets: ["output"],
    detect: (text: string): RuleMatch[] => {
      const findings = detectMarkdownExfiltration(text);
      return findings.map((f) => {
        const idx = text.indexOf(f.url);
        const start = idx !== -1 ? idx : 0;
        const end = idx !== -1 ? idx + f.url.length : text.length;
        return {
          start,
          end,
          message: f.suspiciousReason,
        };
      });
    },
  },
  {
    id: "CAN001",
    category: "exfiltration",
    severity: "critical",
    description: "Canary token leak in generated output",
    targets: ["output"],
    detect: (text: string): RuleMatch[] => {
      const matches: RuleMatch[] = [];
      const regex = /\bCANARY_[A-Za-z0-9_]{16,}\b/g;
      let m: RegExpExecArray | null;
      while ((m = regex.exec(text)) !== null) {
        matches.push({
          start: m.index,
          end: m.index + m[0].length,
          message: `Canary security token "${m[0]}" leaked in model output.`,
        });
      }
      return matches;
    },
  },
];
