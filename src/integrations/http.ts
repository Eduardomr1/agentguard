import { audit, exceeds } from "../engine.js";
import { redactText } from "../redact.js";
import type { GuardOptions } from "../guard.js";
import type { Finding, Severity } from "../types.js";

export interface HttpGuardOptions extends GuardOptions {
  /**
   * Strategy for extracting and inspecting text when `messages` array is provided:
   * - "last-user": inspects the last message with role "user" (or the last message if none with role "user").
   * - "concat": concatenates all message contents with newlines.
   * Default is "last-user".
   */
  messageStrategy?: "last-user" | "concat";
}

export interface AgentGuardHttpRequest {
  body?: any;
  sanitizedBody?: any;
  [key: string]: any;
}

export interface AgentGuardHttpResponse {
  statusCode?: number;
  status?(code: number): AgentGuardHttpResponse;
  setHeader?(name: string, value: string): void;
  json?(body: any): void;
  end?(data?: any): void;
  [key: string]: any;
}

export type AgentGuardHttpNext = (err?: any) => void;

export type AgentGuardMiddleware = (
  req: AgentGuardHttpRequest,
  res: AgentGuardHttpResponse,
  next: AgentGuardHttpNext,
) => void | Promise<void>;

export interface GuardFetchResult {
  ok: boolean;
  response?: Response;
  sanitizedBody?: any;
}

/** Extract text content from a message (string, object with content, or array of parts). */
function getMessageText(msg: any): string {
  if (typeof msg === "string") return msg;
  if (!msg || typeof msg !== "object") return "";
  if (typeof msg.content === "string") return msg.content;
  if (Array.isArray(msg.content)) {
    return msg.content
      .map((part: any) => (typeof part === "string" ? part : part?.text ?? ""))
      .join(" ");
  }
  if (typeof msg.text === "string") return msg.text;
  return "";
}

/** Set text content into a message preserving structure. */
function setMessageText(msg: any, newText: string): void {
  if (typeof msg.content === "string") {
    msg.content = newText;
  } else if (Array.isArray(msg.content)) {
    const textPart = msg.content.find(
      (p: any) => p && typeof p === "object" && typeof p.text === "string",
    );
    if (textPart) {
      textPart.text = newText;
    } else {
      msg.content = newText;
    }
  } else if (typeof msg.text === "string") {
    msg.text = newText;
  }
}

/** Locate the target user message for "last-user" strategy. */
function findLastUserMessage(
  messages: any[],
): { index: number; text: string; message: any } | null {
  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i];
    if (msg && typeof msg === "object" && msg.role === "user") {
      return { index: i, text: getMessageText(msg), message: msg };
    }
  }
  if (messages.length > 0) {
    const idx = messages.length - 1;
    const msg = messages[idx];
    return { index: idx, text: getMessageText(msg), message: msg };
  }
  return null;
}

interface AuditPayloadResult {
  ok: boolean;
  findings: Finding[];
}

/** Audits and optionally sanitizes a parsed JSON body containing `prompt` or `messages`. */
function auditPayload(body: any, options: HttpGuardOptions): AuditPayloadResult {
  if (!body || typeof body !== "object") {
    return { ok: true, findings: [] };
  }

  const failOn: Severity = options.failOn ?? "high";
  const mode = options.onViolation ?? "throw";
  const strategy = options.messageStrategy ?? "last-user";
  const allFindings: Finding[] = [];

  // 1. Audit `prompt` field if present
  if (typeof body.prompt === "string") {
    const res = audit(body.prompt, {
      target: "prompt",
      rules: options.rules,
      disable: options.disable,
    });

    if (res.findings.length > 0) {
      options.onReport?.("prompt", res);
    }

    if (exceeds(res, failOn)) {
      if (mode === "report") {
        // report mode: pass through without blocking
      } else if (mode === "redact") {
        const redacted = redactText(body.prompt, res.findings);
        const left = audit(redacted, {
          target: "prompt",
          rules: options.rules,
          disable: options.disable,
        });
        if (exceeds(left, failOn)) {
          // Violation remains (e.g. prompt injection cannot be redacted away)
          allFindings.push(...left.findings);
        } else {
          body.prompt = redacted;
        }
      } else {
        // "throw" or default
        allFindings.push(...res.findings);
      }
    }
  }

  // 2. Audit `messages` field if present
  if (Array.isArray(body.messages) && body.messages.length > 0) {
    if (strategy === "concat") {
      const concatenated = body.messages.map(getMessageText).filter(Boolean).join("\n");
      const res = audit(concatenated, {
        target: "prompt",
        rules: options.rules,
        disable: options.disable,
      });

      if (res.findings.length > 0) {
        options.onReport?.("prompt", res);
      }

      if (exceeds(res, failOn)) {
        if (mode === "report") {
          // report mode: pass through
        } else if (mode === "redact") {
          for (let i = 0; i < body.messages.length; i++) {
            const m = body.messages[i];
            const text = getMessageText(m);
            if (text) {
              const mAudit = audit(text, {
                target: "prompt",
                rules: options.rules,
                disable: options.disable,
              });
              if (mAudit.findings.length > 0) {
                const red = redactText(text, mAudit.findings);
                if (typeof m === "string") {
                  body.messages[i] = red;
                } else {
                  setMessageText(m, red);
                }
              }
            }
          }
          const reConcat = body.messages.map(getMessageText).filter(Boolean).join("\n");
          const left = audit(reConcat, {
            target: "prompt",
            rules: options.rules,
            disable: options.disable,
          });
          if (exceeds(left, failOn)) {
            allFindings.push(...left.findings);
          }
        } else {
          allFindings.push(...res.findings);
        }
      }
    } else {
      // Default: "last-user" strategy
      const target = findLastUserMessage(body.messages);
      if (target && target.text) {
        const res = audit(target.text, {
          target: "prompt",
          rules: options.rules,
          disable: options.disable,
        });

        if (res.findings.length > 0) {
          options.onReport?.("prompt", res);
        }

        if (exceeds(res, failOn)) {
          if (mode === "report") {
            // report mode: pass through
          } else if (mode === "redact") {
            const redacted = redactText(target.text, res.findings);
            const left = audit(redacted, {
              target: "prompt",
              rules: options.rules,
              disable: options.disable,
            });
            if (exceeds(left, failOn)) {
              allFindings.push(...left.findings);
            } else {
              if (typeof target.message === "string") {
                body.messages[target.index] = redacted;
              } else {
                setMessageText(target.message, redacted);
              }
            }
          } else {
            allFindings.push(...res.findings);
          }
        }
      }
    }
  }

  return {
    ok: allFindings.length === 0,
    findings: allFindings,
  };
}

/** Responds HTTP 400 Bad Request with standardized JSON error. */
function sendViolationResponse(res: AgentGuardHttpResponse, findings: Finding[]): void {
  const payload = {
    error: "Security policy violation",
    findings,
  };

  if (typeof res.status === "function") {
    const chained = res.status(400);
    if (chained && typeof chained.json === "function") {
      chained.json(payload);
      return;
    }
  } else {
    res.statusCode = 400;
  }

  if (typeof res.setHeader === "function") {
    res.setHeader("Content-Type", "application/json");
  }
  if (typeof res.json === "function") {
    res.json(payload);
  } else if (typeof res.end === "function") {
    res.end(JSON.stringify(payload));
  }
}

/**
 * Universal middleware for Express/Connect frameworks.
 *
 * Intercepts `req.body` looking for `prompt` or `messages` fields,
 * audits with AgentGuard, and if violated according to `failOn`,
 * responds HTTP 400 Bad Request with JSON `{ error: "Security policy violation", findings }`,
 * or sanitizes the body in place when `onViolation: "redact"`.
 */
export function createAgentGuardMiddleware(
  options: HttpGuardOptions = {},
): AgentGuardMiddleware {
  return function agentGuardMiddleware(
    req: AgentGuardHttpRequest,
    res: AgentGuardHttpResponse,
    next: AgentGuardHttpNext,
  ): void {
    if (!req || !req.body || typeof req.body !== "object") {
      return next();
    }

    const result = auditPayload(req.body, options);
    if (!result.ok) {
      sendViolationResponse(res, result.findings);
      return;
    }

    req.sanitizedBody = req.body;
    next();
  };
}

/**
 * Request guard handler for Fetch API, Cloudflare Workers, Edge, Next.js route handlers.
 *
 * Inspects `request` body looking for `prompt` or `messages`, audits with AgentGuard,
 * and returns `{ ok: boolean, response?: Response, sanitizedBody?: any }`.
 * When violated according to `failOn`, returns `{ ok: false, response: Response(400) }`.
 */
export async function guardFetchRequest(
  request: Request,
  options: HttpGuardOptions = {},
): Promise<GuardFetchResult> {
  let body: any = undefined;

  if (request && typeof request.json === "function") {
    try {
      const cloned = typeof request.clone === "function" ? request.clone() : request;
      body = await cloned.json();
    } catch {
      // Body is not JSON or cannot be read
    }
  } else if (request && (request as any).body !== undefined) {
    body = (request as any).body;
  }

  if (!body || typeof body !== "object") {
    return { ok: true, sanitizedBody: body };
  }

  const sanitizedBody = structuredClone(body);
  const result = auditPayload(sanitizedBody, options);

  if (!result.ok) {
    return {
      ok: false,
      response: new Response(
        JSON.stringify({
          error: "Security policy violation",
          findings: result.findings,
        }),
        {
          status: 400,
          headers: {
            "Content-Type": "application/json",
          },
        },
      ),
      sanitizedBody: undefined,
    };
  }

  return {
    ok: true,
    sanitizedBody,
  };
}
