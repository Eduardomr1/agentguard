import { audit } from "./engine.js";
import { SEVERITY_ORDER } from "./types.js";
import type { AuditOptions, AuditResult, Finding, Target } from "./types.js";

export type Role = "system" | "user" | "assistant" | "unknown";

export interface MarkdownSection {
  role: Role;
  text: string;
  start: number;
  end: number;
}

export interface ParsedPromptMarkdown {
  frontmatter?: Record<string, string>;
  sections: MarkdownSection[];
}

export interface ChatMessage {
  role: string;
  content: string;
  path: string;
}

/**
 * Normalizes common role strings to standard prompt roles.
 */
function normalizeRole(raw: string): Role {
  const r = raw.toLowerCase().trim();
  if (["system", "developer", "sys"].includes(r)) return "system";
  if (["user", "human"].includes(r)) return "user";
  if (["assistant", "ai", "bot", "model", "agent"].includes(r)) return "assistant";
  return "unknown";
}

/**
 * Parses simple YAML frontmatter key-value pairs into Record<string, string>.
 */
function parseSimpleYaml(yamlText: string): Record<string, string> {
  const result: Record<string, string> = {};
  const lines = yamlText.split(/\r?\n/);
  let currentKey: string | null = null;
  let multilineVal: string[] = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const kvMatch = line.match(/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/);
    if (kvMatch) {
      if (currentKey && multilineVal.length > 0) {
        result[currentKey] = multilineVal.join("\n").trim();
        multilineVal = [];
      }
      currentKey = kvMatch[1];
      let val = kvMatch[2].trim();
      if (!val.startsWith('"') && !val.startsWith("'")) {
        const commentIdx = val.indexOf(" #");
        if (commentIdx !== -1) val = val.slice(0, commentIdx).trim();
      }
      if (
        (val.startsWith('"') && val.endsWith('"') && val.length >= 2) ||
        (val.startsWith("'") && val.endsWith("'") && val.length >= 2)
      ) {
        val = val.slice(1, -1);
      }
      if (val === "|" || val === ">") {
        multilineVal = [];
      } else if (val !== "") {
        result[currentKey] = val;
        currentKey = null;
      }
    } else if (currentKey && (line.startsWith("  ") || line.startsWith("\t"))) {
      multilineVal.push(trimmed);
    }
  }

  if (currentKey && multilineVal.length > 0) {
    result[currentKey] = multilineVal.join("\n").trim();
  }

  return result;
}

interface Marker {
  role?: Role;
  isClose?: boolean;
  start: number;
  end: number;
}

/**
 * Parses a markdown prompt with optional YAML frontmatter into structured role sections.
 * Detects headers such as `# System`, `## User`, `### Assistant`, `[SYSTEM]`, `[USER]`,
 * delimiter lines, and XML-style delimited blocks.
 */
export function parsePromptMarkdown(content: string): ParsedPromptMarkdown {
  let bodyStart = 0;
  let frontmatter: Record<string, string> | undefined;

  // 1. Detect YAML frontmatter delimited by `---` at the beginning
  const fmMatch =
    content.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/) ??
    content.match(/^---\r?\n---\r?\n?/);
  if (fmMatch) {
    frontmatter = parseSimpleYaml(fmMatch[1] ?? "");
    bodyStart = fmMatch[0].length;
  }

  const body = content.slice(bodyStart);
  if (!body) {
    return { frontmatter, sections: [] };
  }

  // 2. Scan lines for section markers
  const markers: Marker[] = [];
  const lines = body.split(/(\r?\n)/);
  let currentOffset = bodyStart;
  let inCodeBlock = false;

  const roleKeywords = "system|developer|sys|user|human|assistant|ai|bot|model|agent";
  const roleHeadingRegex = new RegExp(
    `^(?:role:\\s*)?(${roleKeywords})(?:\\s+(?:prompt|message|input|output|response|instructions|turn))?:?$`,
    "i"
  );
  const bracketOpenRegex = new RegExp(
    `^\\[\\s*(?:role:\\s*)?(${roleKeywords})(?:\\s+(?:prompt|message|input|output|response|instructions|turn))?:?\\s*\\]$`,
    "i"
  );
  const bracketCloseRegex = new RegExp(
    `^\\[\\/\\s*(${roleKeywords})\\s*\\]$`,
    "i"
  );
  const delimLineRegex = new RegExp(
    `^(?:---|===|\\*\\*\\*)\\s*(${roleKeywords})(?:\\s+(?:prompt|message|input|output|response|instructions|turn))?:?\\s*(?:---|===|\\*\\*\\*)$`,
    "i"
  );
  const colonTurnRegex = new RegExp(
    `^(${roleKeywords})\\s*:\\s*$`,
    "i"
  );
  const colonLineRegex = new RegExp(
    `^(${roleKeywords})\\s*:\\s+`,
    "i"
  );

  for (let i = 0; i < lines.length; i += 2) {
    const line = lines[i];
    const delim = lines[i + 1] ?? "";
    const lineLen = line.length + delim.length;
    const lineStart = currentOffset;
    const lineEnd = lineStart + lineLen;

    const trimmed = line.trim();

    // Code fence toggle
    if (/^\s*(```|~~~)/.test(line)) {
      inCodeBlock = !inCodeBlock;
      currentOffset = lineEnd;
      continue;
    }

    if (!inCodeBlock && trimmed) {
      // Markdown header: # System, ## User, etc.
      const hMatch = trimmed.match(/^(#{1,6})\s+(.+)$/);
      if (hMatch) {
        const title = hMatch[2].trim().replace(/^\[|\]$/g, "");
        const roleM = title.match(roleHeadingRegex);
        if (roleM) {
          markers.push({
            role: normalizeRole(roleM[1]),
            start: lineStart,
            end: lineEnd,
          });
          currentOffset = lineEnd;
          continue;
        }
      }

      // Bracket header alone on line: [SYSTEM], [USER]
      const bOpen = trimmed.match(bracketOpenRegex);
      if (bOpen) {
        markers.push({
          role: normalizeRole(bOpen[1]),
          start: lineStart,
          end: lineEnd,
        });
        currentOffset = lineEnd;
        continue;
      }

      // Bracket closing tag: [/SYSTEM]
      const bClose = trimmed.match(bracketCloseRegex);
      if (bClose) {
        markers.push({
          isClose: true,
          role: normalizeRole(bClose[1]),
          start: lineStart,
          end: lineEnd,
        });
        currentOffset = lineEnd;
        continue;
      }

      // Delimiter line: === USER === or --- SYSTEM ---
      const dMatch = trimmed.match(delimLineRegex);
      if (dMatch) {
        markers.push({
          role: normalizeRole(dMatch[1]),
          start: lineStart,
          end: lineEnd,
        });
        currentOffset = lineEnd;
        continue;
      }

      // Colon alone: System:
      const cMatch = trimmed.match(colonTurnRegex);
      if (cMatch) {
        markers.push({
          role: normalizeRole(cMatch[1]),
          start: lineStart,
          end: lineEnd,
        });
        currentOffset = lineEnd;
        continue;
      }

      // Colon at line start with content: User: hello
      const colLine = line.match(colonLineRegex);
      if (colLine) {
        markers.push({
          role: normalizeRole(colLine[1]),
          start: lineStart,
          end: lineStart + colLine[0].length,
        });
        // Note: content follows on the same line
      }

      // XML tags on line: <system>, </system>, etc.
      const xmlRegex = new RegExp(
        `<(\\/?)\\s*(${roleKeywords})\\b[^>]*>`,
        "gi"
      );
      let xmlMatch: RegExpExecArray | null;
      while ((xmlMatch = xmlRegex.exec(line)) !== null) {
        const isClose = xmlMatch[1] === "/";
        const role = normalizeRole(xmlMatch[2]);
        const tagStart = lineStart + xmlMatch.index;
        const tagEnd = tagStart + xmlMatch[0].length;
        markers.push({
          role,
          isClose,
          start: tagStart,
          end: tagEnd,
        });
      }
    }

    currentOffset = lineEnd;
  }

  markers.sort((a, b) => a.start - b.start);

  const sections: MarkdownSection[] = [];
  let currentRole: Role = "unknown";
  let currentPos = bodyStart;

  for (const marker of markers) {
    if (marker.start > currentPos) {
      const raw = content.slice(currentPos, marker.start);
      const trimmed = raw.trim();
      if (trimmed.length > 0 || currentRole !== "unknown") {
        const leadingWs = raw.search(/\S/);
        const start = leadingWs !== -1 ? currentPos + leadingWs : currentPos;
        const end = leadingWs !== -1 ? currentPos + raw.trimEnd().length : currentPos;
        sections.push({
          role: currentRole,
          text: content.slice(start, end),
          start,
          end,
        });
      }
    }

    if (marker.isClose) {
      currentRole = "unknown";
      currentPos = marker.end;
    } else {
      currentRole = marker.role ?? "unknown";
      currentPos = marker.end;
    }
  }

  // Tail content after the last marker
  if (currentPos < content.length) {
    const raw = content.slice(currentPos);
    const trimmed = raw.trim();
    if (trimmed.length > 0 || currentRole !== "unknown") {
      const leadingWs = raw.search(/\S/);
      const start = leadingWs !== -1 ? currentPos + leadingWs : currentPos;
      const end = leadingWs !== -1 ? currentPos + raw.trimEnd().length : currentPos;
      sections.push({
        role: currentRole,
        text: content.slice(start, end),
        start,
        end,
      });
    }
  }

  return { frontmatter, sections };
}

/**
 * Extracts a flattened string from various message content representations
 * (string, array of text parts/blocks, parts object, etc.).
 */
function extractContentString(val: unknown): string {
  if (typeof val === "string") return val;
  if (Array.isArray(val)) {
    return val
      .map((item) => {
        if (typeof item === "string") return item;
        if (item && typeof item === "object") {
          const obj = item as Record<string, unknown>;
          if (typeof obj.text === "string") return obj.text;
          if (typeof obj.content === "string") return obj.content;
          if (obj.parts && Array.isArray(obj.parts)) return extractContentString(obj.parts);
        }
        return "";
      })
      .filter((s) => s.length > 0)
      .join("\n");
  }
  if (val && typeof val === "object") {
    const obj = val as Record<string, unknown>;
    if (typeof obj.text === "string") return obj.text;
    if (typeof obj.content === "string") return extractContentString(obj.content);
    if (Array.isArray(obj.parts)) return extractContentString(obj.parts);
  }
  return val ? String(val) : "";
}

/**
 * Parses conversational turns from YAML format.
 */
export function parseYamlTurns(yamlContent: string): ChatMessage[] {
  const trimmed = yamlContent.trim();
  if (!trimmed) return [];

  const lines = yamlContent.split(/\r?\n/);
  const messages: ChatMessage[] = [];
  let currentRole: string | null = null;
  let currentContent: string[] = [];
  let isBlockScalar = false;
  let turnIndex = 0;
  let prefix = "";

  function flush() {
    if (currentRole !== null) {
      messages.push({
        role: currentRole,
        content: currentContent.join("\n").trim(),
        path: prefix ? `${prefix}[${turnIndex}]` : `[${turnIndex}]`,
      });
      turnIndex++;
      currentRole = null;
      currentContent = [];
      isBlockScalar = false;
    }
  }

  for (const line of lines) {
    const lTrim = line.trim();
    if (!lTrim || lTrim.startsWith("#")) continue;

    // Check if wrapping key e.g. "messages:" or "turns:"
    if (/^(?:messages|turns|conversation)\s*:$/i.test(lTrim)) {
      prefix = lTrim.replace(/:$/, "");
      continue;
    }

    // New item indicator: "- role: user" or "- user: hello"
    const dashMatch = line.match(/^\s*-\s+(?:role:\s*([A-Za-z0-9_-]+)|([A-Za-z0-9_-]+)\s*:\s*(.*))$/i);
    if (dashMatch) {
      flush();
      if (dashMatch[1]) {
        currentRole = dashMatch[1];
      } else if (dashMatch[2]) {
        currentRole = dashMatch[2];
        let val = (dashMatch[3] ?? "").trim();
        if (
          (val.startsWith('"') && val.endsWith('"') && val.length >= 2) ||
          (val.startsWith("'") && val.endsWith("'") && val.length >= 2)
        ) {
          val = val.slice(1, -1);
        }
        if (val) currentContent.push(val);
      }
      continue;
    }

    // Standalone dash: "- "
    if (/^\s*-\s*$/.test(line)) {
      flush();
      continue;
    }

    // "role: user" inside item
    const roleMatch = line.match(/^\s*role\s*:\s*([A-Za-z0-9_-]+)/i);
    if (roleMatch && currentRole === null) {
      currentRole = roleMatch[1];
      continue;
    }

    // "content: ..." inside item
    const contentMatch = line.match(/^\s*content\s*:\s*(.*)$/i);
    if (contentMatch) {
      let val = contentMatch[1].trim();
      if (val === "|" || val === ">") {
        isBlockScalar = true;
      } else {
        if (
          (val.startsWith('"') && val.endsWith('"') && val.length >= 2) ||
          (val.startsWith("'") && val.endsWith("'") && val.length >= 2)
        ) {
          val = val.slice(1, -1);
        }
        if (val) currentContent.push(val);
      }
      continue;
    }

    // Indented content continuation
    if (currentRole !== null && (line.startsWith("    ") || line.startsWith("  ") || line.startsWith("\t"))) {
      currentContent.push(isBlockScalar ? line.replace(/^\s{2,4}/, "") : lTrim);
    }
  }

  flush();
  return messages;
}

/**
 * Parses chat messages from OpenAI/Anthropic/Vercel/Gemini JSON, JSONL, or YAML turns.
 * Supports `{ messages: [...] }`, `[...]`, `{ contents: [...] }`, etc.
 */
export function parseChatMessages(jsonContent: string): ChatMessage[] {
  const trimmed = jsonContent.trim();
  if (!trimmed) return [];

  // 1. Standard JSON
  try {
    const parsed = JSON.parse(jsonContent);

    // Array at root: [ { role, content }, ... ]
    if (Array.isArray(parsed)) {
      return parsed.map((item, idx) => {
        const obj = (item && typeof item === "object" ? item : {}) as Record<string, unknown>;
        const role = String(obj.role ?? obj.speaker ?? obj.author ?? "user");
        const content = extractContentString(obj.content ?? obj.parts ?? obj.text ?? item);
        return { role, content, path: `[${idx}]` };
      });
    }

    // Object at root
    if (parsed && typeof parsed === "object") {
      const messages: ChatMessage[] = [];

      // Anthropic style: top-level "system" prompt
      if ("system" in parsed && parsed.system) {
        messages.push({
          role: "system",
          content: extractContentString(parsed.system),
          path: "system",
        });
      }

      // Check "messages" array (OpenAI / Anthropic / Vercel AI SDK)
      if (Array.isArray(parsed.messages)) {
        for (let i = 0; i < parsed.messages.length; i++) {
          const item = parsed.messages[i];
          const obj = (item && typeof item === "object" ? item : {}) as Record<string, unknown>;
          const role = String(obj.role ?? obj.speaker ?? "user");
          const content = extractContentString(obj.content ?? obj.parts ?? obj.text ?? item);
          messages.push({ role, content, path: `messages[${i}]` });
        }
        return messages;
      }

      // Check "contents" array (Google Gemini)
      if (Array.isArray(parsed.contents)) {
        for (let i = 0; i < parsed.contents.length; i++) {
          const item = parsed.contents[i];
          const obj = (item && typeof item === "object" ? item : {}) as Record<string, unknown>;
          const role = String(obj.role ?? "user");
          const content = extractContentString(obj.parts ?? obj.content ?? item);
          messages.push({ role, content, path: `contents[${i}]` });
        }
        return messages;
      }

      // Check "conversation" or "prompt" array
      if (Array.isArray(parsed.conversation)) {
        for (let i = 0; i < parsed.conversation.length; i++) {
          const item = parsed.conversation[i];
          const obj = (item && typeof item === "object" ? item : {}) as Record<string, unknown>;
          const role = String(obj.role ?? "user");
          const content = extractContentString(obj.content ?? obj.text ?? item);
          messages.push({ role, content, path: `conversation[${i}]` });
        }
        return messages;
      }

      // Single message object: { role: "user", content: "..." }
      if ("role" in parsed || "content" in parsed) {
        return [
          {
            role: String(parsed.role ?? "user"),
            content: extractContentString(parsed.content ?? parsed.text),
            path: "(root)",
          },
        ];
      }

      if (messages.length > 0) return messages;
    }
  } catch {
    // Fall through to JSONL or YAML
  }

  // 2. JSONL (JSON Lines)
  const lines = trimmed.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const jsonlMessages: ChatMessage[] = [];
  let isJsonl = false;

  for (let i = 0; i < lines.length; i++) {
    try {
      const lineObj = JSON.parse(lines[i]);
      if (lineObj && typeof lineObj === "object") {
        if ("role" in lineObj || "content" in lineObj) {
          isJsonl = true;
          jsonlMessages.push({
            role: String(lineObj.role ?? "user"),
            content: extractContentString(lineObj.content ?? lineObj.parts ?? lineObj.text),
            path: `[${i}]`,
          });
        } else if (Array.isArray(lineObj.messages)) {
          isJsonl = true;
          for (let m = 0; m < lineObj.messages.length; m++) {
            const item = lineObj.messages[m];
            jsonlMessages.push({
              role: String(item.role ?? "user"),
              content: extractContentString(item.content ?? item.text),
              path: `[${i}].messages[${m}]`,
            });
          }
        }
      }
    } catch {
      // not JSON line
    }
  }

  if (isJsonl && jsonlMessages.length > 0) {
    return jsonlMessages;
  }

  // 3. YAML turns fallback
  const yamlMessages = parseYamlTurns(jsonContent);
  if (yamlMessages.length > 0) {
    return yamlMessages;
  }

  return [];
}

/**
 * Audits a structured prompt (Markdown or Chat JSON), applying target "prompt" to
 * user/system turns and target "output" to assistant turns.
 */
export function auditStructuredPrompt(
  content: string,
  format: "markdown" | "chat-json",
  options?: AuditOptions
): AuditResult {
  const findings: Finding[] = [];

  if (format === "markdown") {
    const parsed = parsePromptMarkdown(content);

    // Audit markdown sections
    for (const section of parsed.sections) {
      if (!section.text) continue;
      const isAssistant = section.role === "assistant";
      const target: Target = isAssistant ? "output" : "prompt";
      const res = audit(section.text, {
        ...options,
        target,
        schema: isAssistant ? options?.schema : undefined,
      });

      for (const f of res.findings) {
        findings.push({
          ...f,
          start: section.start + f.start,
          end: section.start + f.end,
        });
      }
    }

    // Audit frontmatter values as "prompt" target
    if (parsed.frontmatter) {
      for (const val of Object.values(parsed.frontmatter)) {
        if (!val) continue;
        const res = audit(val, {
          ...options,
          target: "prompt",
          schema: undefined,
        });
        if (res.findings.length > 0) {
          const valIdx = content.indexOf(val);
          for (const f of res.findings) {
            findings.push({
              ...f,
              start: valIdx !== -1 ? valIdx + f.start : f.start,
              end: valIdx !== -1 ? valIdx + f.end : f.end,
            });
          }
        }
      }
    }
  } else if (format === "chat-json") {
    const messages = parseChatMessages(content);
    let searchOffset = 0;

    for (const msg of messages) {
      if (!msg.content) continue;
      const roleLower = msg.role.toLowerCase();
      const isAssistant = ["assistant", "model", "bot", "ai"].includes(roleLower);
      const target: Target = isAssistant ? "output" : "prompt";

      const res = audit(msg.content, {
        ...options,
        target,
        schema: isAssistant ? options?.schema : undefined,
      });

      // Map offset into raw content
      let msgOffset = content.indexOf(msg.content, searchOffset);
      if (msgOffset === -1) {
        // Try escaped representation
        try {
          const escaped = JSON.stringify(msg.content).slice(1, -1);
          msgOffset = content.indexOf(escaped, searchOffset);
          if (msgOffset === -1) msgOffset = content.indexOf(escaped);
          if (msgOffset !== -1) searchOffset = msgOffset + escaped.length;
        } catch {
          // ignore
        }
      }
      if (msgOffset === -1) {
        msgOffset = content.indexOf(msg.content);
      }
      if (msgOffset !== -1 && searchOffset < msgOffset + msg.content.length) {
        searchOffset = msgOffset + msg.content.length;
      }

      for (const f of res.findings) {
        findings.push({
          ...f,
          start: msgOffset !== -1 ? msgOffset + f.start : f.start,
          end: msgOffset !== -1 ? msgOffset + f.end : f.end,
        });
      }
    }
  }

  findings.sort(
    (a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.start - b.start
  );

  return {
    ok: findings.length === 0,
    findings,
  };
}
