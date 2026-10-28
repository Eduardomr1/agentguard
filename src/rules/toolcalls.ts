import type { Rule } from "../types.js";
import { regexMatches } from "./util.js";

/**
 * Rules targeting agentic tool calls and LLM outputs that trigger external actions.
 */
export const toolCallRules: Rule[] = [
  {
    id: "TOOL001",
    category: "tool",
    severity: "critical",
    description: "Dangerous shell command execution payload in tool call arguments",
    targets: ["output", "tool"],
    detect: (t) =>
      regexMatches(
        t,
        /(?:rm\s+-[rf]{1,2}\s+[\/~\*]|mkfs\.[a-z0-9]+\s+|curl\s+[^|\n]+\|\s*(?:ba)?sh|nc\s+-[e]\s+\/bin\/(?:ba)?sh|chmod\s+-R\s+777\s+\/)/i,
        "Dangerous shell command detected in tool payload"
      ),
  },
  {
    id: "TOOL002",
    category: "tool",
    severity: "high",
    description: "SSRF or cloud metadata service endpoint access in tool URL arguments",
    targets: ["output", "tool"],
    detect: (t) =>
      regexMatches(
        t,
        /(?:https?:\/\/)?(?:169\.254\.169\.254|metadata\.google\.internal|127\.0\.0\.1|localhost(?::\d+)?)\b/i,
        "Target points to local or cloud metadata SSRF address"
      ),
  },
  {
    id: "TOOL003",
    category: "tool",
    severity: "high",
    description: "Destructive SQL command pattern in database tool argument",
    targets: ["output", "tool"],
    detect: (t) =>
      regexMatches(
        t,
        /\b(?:DROP\s+TABLE|TRUNCATE\s+TABLE|DELETE\s+FROM\s+\w+\s+WHERE\s+1\s*=\s*1)\b/i,
        "Destructive SQL command pattern detected"
      ),
  },
  {
    id: "TOOL004",
    category: "tool",
    severity: "high",
    description: "Path traversal sequence escaping workspace directory sandbox",
    targets: ["output", "tool"],
    detect: (t) =>
      regexMatches(
        t,
        /(?:(?:\.\.[\/\\]){2,}[a-zA-Z0-9_\-\.]+)/i,
        "Path traversal detected escaping workspace sandbox"
      ),
  },
];
