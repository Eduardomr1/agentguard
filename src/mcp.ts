import * as readline from "node:readline";
import type { Readable, Writable } from "node:stream";
import { audit, exceeds } from "./engine.js";
import { redactText } from "./redact.js";
import type { Finding, Severity } from "./types.js";

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: any;
}

export interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: any;
  error?: {
    code: number;
    message: string;
    data?: any;
  };
}

export const JSON_RPC_ERRORS = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
};

export const MCP_TOOLS = [
  {
    name: "audit_prompt",
    description: "Audit an LLM prompt for prompt injection, leaked secrets, or PII",
    inputSchema: {
      type: "object",
      properties: {
        text: {
          type: "string",
          description: "Prompt text to audit",
        },
        failOn: {
          type: "string",
          enum: ["low", "medium", "high", "critical"],
          description: "Minimum severity to treat as violation",
        },
        disable: {
          type: "array",
          items: { type: "string" },
          description: "Rule IDs to skip during audit",
        },
      },
      required: ["text"],
    },
  },
  {
    name: "audit_output",
    description: "Audit an LLM output for leaked secrets, PII, or schema violations",
    inputSchema: {
      type: "object",
      properties: {
        text: {
          type: "string",
          description: "Output text to audit",
        },
        schema: {
          type: "object",
          description: "Optional JSON Schema to validate output against",
        },
        failOn: {
          type: "string",
          enum: ["low", "medium", "high", "critical"],
          description: "Minimum severity to treat as violation",
        },
        disable: {
          type: "array",
          items: { type: "string" },
          description: "Rule IDs to skip during audit",
        },
      },
      required: ["text"],
    },
  },
  {
    name: "redact_text",
    description: "Redact secrets and PII from text",
    inputSchema: {
      type: "object",
      properties: {
        text: {
          type: "string",
          description: "Text containing secrets or PII to redact",
        },
        disable: {
          type: "array",
          items: { type: "string" },
          description: "Rule IDs to skip during redaction",
        },
      },
      required: ["text"],
    },
  },
];

export class AgentGuardMcpServer {
  private rl?: readline.Interface;

  constructor() {}

  /**
   * Process a single raw line of JSON-RPC text.
   * Returns a JSON-RPC response string, or null if line was empty or a notification.
   */
  async processLine(line: string): Promise<string | null> {
    const trimmed = line.trim();
    if (!trimmed) return null;

    let parsed: any;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      return JSON.stringify({
        jsonrpc: "2.0",
        id: null,
        error: {
          code: JSON_RPC_ERRORS.PARSE_ERROR,
          message: "Parse error: Invalid JSON",
        },
      });
    }

    if (Array.isArray(parsed)) {
      const results = (
        await Promise.all(parsed.map((item) => this.handleMessage(item)))
      ).filter(Boolean);
      return results.length ? JSON.stringify(results) : null;
    }

    const response = await this.handleMessage(parsed);
    return response ? JSON.stringify(response) : null;
  }

  /**
   * Handle an already parsed JSON-RPC message object.
   */
  async handleMessage(message: any): Promise<JsonRpcResponse | null> {
    if (
      !message ||
      typeof message !== "object" ||
      message.jsonrpc !== "2.0" ||
      typeof message.method !== "string"
    ) {
      return {
        jsonrpc: "2.0",
        id: message?.id ?? null,
        error: {
          code: JSON_RPC_ERRORS.INVALID_REQUEST,
          message:
            "Invalid Request: Must be a JSON-RPC 2.0 object with a 'method' property",
        },
      };
    }

    const { id, method, params } = message;
    const isNotification = id === undefined || id === null;

    // Standard MCP notifications that should not generate a response
    if (
      method === "notifications/initialized" ||
      (method === "initialized" && isNotification) ||
      (method === "notifications/cancelled" && isNotification)
    ) {
      return null;
    }

    try {
      const result = await this.dispatch(method, params);
      if (isNotification) return null;
      return {
        jsonrpc: "2.0",
        id,
        result,
      };
    } catch (err: any) {
      if (isNotification) return null;
      const code =
        typeof err?.code === "number"
          ? err.code
          : JSON_RPC_ERRORS.INTERNAL_ERROR;
      const messageText = err?.message || "Internal error";
      return {
        jsonrpc: "2.0",
        id,
        error: {
          code,
          message: messageText,
          ...(err?.data !== undefined ? { data: err.data } : {}),
        },
      };
    }
  }

  private async dispatch(method: string, params: any): Promise<any> {
    switch (method) {
      case "initialize":
        return {
          protocolVersion: "2024-11-05",
          capabilities: {
            tools: {},
          },
          serverInfo: {
            name: "agentguard",
            version: "0.1.0",
          },
        };

      case "notifications/initialized":
      case "initialized":
      case "ping":
        return {};

      case "tools/list":
        return {
          tools: MCP_TOOLS,
        };

      case "tools/call":
        return this.handleToolCall(params);

      default:
        throw {
          code: JSON_RPC_ERRORS.METHOD_NOT_FOUND,
          message: `Method not found: ${method}`,
        };
    }
  }

  private handleToolCall(params: any): { content: Array<{ type: "text"; text: string }> } {
    if (!params || typeof params !== "object") {
      throw {
        code: JSON_RPC_ERRORS.INVALID_PARAMS,
        message: "Invalid params: object expected",
      };
    }

    const name = params.name;
    if (!name || typeof name !== "string") {
      throw {
        code: JSON_RPC_ERRORS.INVALID_PARAMS,
        message: "Missing or invalid tool name",
      };
    }

    const args =
      params.arguments && typeof params.arguments === "object"
        ? params.arguments
        : params;

    if (typeof args.text !== "string") {
      throw {
        code: JSON_RPC_ERRORS.INVALID_PARAMS,
        message: "Tool argument 'text' must be a string",
      };
    }

    const disable = Array.isArray(args.disable) ? args.disable : undefined;

    switch (name) {
      case "audit_prompt": {
        const auditRes = audit(args.text, {
          target: "prompt",
          disable,
        });
        const exceedsSeverity = args.failOn
          ? exceeds(auditRes, args.failOn as Severity)
          : undefined;
        const data = {
          ...auditRes,
          ...(args.failOn
            ? {
                failOn: args.failOn,
                exceeds: exceedsSeverity,
                passed: !exceedsSeverity,
              }
            : {}),
        };
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(data),
            },
          ],
        };
      }

      case "audit_output": {
        let schema = args.schema;
        if (typeof schema === "string") {
          try {
            schema = JSON.parse(schema);
          } catch {
            // leave schema as-is
          }
        }
        const schemaObj =
          schema && typeof schema === "object" ? schema : undefined;

        const auditRes = audit(args.text, {
          target: "output",
          schema: schemaObj,
          disable,
        });
        const exceedsSeverity = args.failOn
          ? exceeds(auditRes, args.failOn as Severity)
          : undefined;
        const data = {
          ...auditRes,
          ...(args.failOn
            ? {
                failOn: args.failOn,
                exceeds: exceedsSeverity,
                passed: !exceedsSeverity,
              }
            : {}),
        };
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(data),
            },
          ],
        };
      }

      case "redact_text": {
        const auditRes = audit(args.text, {
          disable,
        });
        const redacted = redactText(args.text, auditRes.findings);
        const data = {
          text: redacted,
          redacted,
          findings: auditRes.findings,
        };
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(data),
            },
          ],
        };
      }

      default:
        throw {
          code: JSON_RPC_ERRORS.METHOD_NOT_FOUND,
          message: `Unknown tool: ${name}`,
        };
    }
  }

  /**
   * Start listening on input stream (default process.stdin) and writing to output (default process.stdout).
   */
  start(
    input: Readable = process.stdin,
    output: Writable = process.stdout,
  ): void {
    this.rl = readline.createInterface({
      input,
      output: undefined,
      terminal: false,
    });

    this.rl.on("line", async (line: string) => {
      const response = await this.processLine(line);
      if (response) {
        output.write(response + "\n");
      }
    });
  }

  /**
   * Stop the server and close readline.
   */
  stop(): void {
    if (this.rl) {
      this.rl.close();
      this.rl = undefined;
    }
  }
}
