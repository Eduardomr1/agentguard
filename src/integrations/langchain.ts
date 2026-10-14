import { audit, exceeds } from "../engine.js";
import { redactText } from "../redact.js";
import { AgentGuardError } from "../guard.js";
import type { GuardOptions } from "../guard.js";
import type { AuditResult, Severity, Target } from "../types.js";

/**
 * Standard message interface compatible with LangChain / LangGraph BaseMessage / MessageLike.
 */
export interface LangChainMessage {
  role?: string;
  content: string | any;
  type?: string;
  name?: string;
  additional_kwargs?: Record<string, any>;
}

/**
 * Options for configuring LangChain runnable guards.
 */
export interface AgentGuardRunnableOptions<TInput = any, TOutput = any> extends GuardOptions {
  /** Optional underlying runnable, pipeline, or function to execute and audit. */
  runnable?:
    | { invoke: (input: TInput, ...args: any[]) => Promise<TOutput> }
    | ((input: TInput, ...args: any[]) => Promise<TOutput> | TOutput);
  /** Optional custom extractor for the input prompt string. */
  inputExtractor?: (input: TInput) => string;
  /** Optional custom extractor for the output response string. */
  outputExtractor?: (output: TOutput) => string;
}

/**
 * Runnable interface compatible with LangChain LCEL and LangGraph nodes.
 */
export interface AgentGuardRunnable<TInput = any, TOutput = any> {
  invoke(input: TInput, ...args: any[]): Promise<TOutput>;
  batch?(inputs: TInput[], ...args: any[]): Promise<TOutput[]>;
  pipe?<TNext>(next: any): AgentGuardRunnable<TInput, TNext>;
  transform?: (generator: AsyncIterable<TInput>, ...args: any[]) => AsyncGenerator<TOutput, void, void>;
}

/**
 * Tool interface compatible with LangChain StructuredTool / DynamicTool.
 */
export interface LangChainTool<TArgs = any, TResult = any> {
  name: string;
  description?: string;
  schema?: any;
  call?: (args: TArgs, ...rest: any[]) => Promise<TResult>;
  invoke?: (args: TArgs, ...rest: any[]) => Promise<TResult>;
  [key: string]: any;
}

/**
 * Chat model interface compatible with LangChain BaseChatModel.
 */
export interface LangChainChatModel {
  invoke: (input: any, ...args: any[]) => Promise<any>;
  call?: (input: any, ...args: any[]) => Promise<any>;
  [key: string]: any;
}

function runAudit(
  text: string,
  target: Target,
  options: GuardOptions,
  enableSchema: boolean = target === "output",
): AuditResult {
  const res = audit(text, {
    target,
    rules: options.rules,
    disable: options.disable,
    schema: enableSchema ? options.schema : undefined,
  });
  if (res.findings.length > 0) {
    options.onReport?.(target, res);
  }
  return res;
}

function enforcePolicy(
  text: string,
  target: Target,
  options: GuardOptions,
  enableSchema: boolean = target === "output",
): string {
  const res = runAudit(text, target, options, enableSchema);
  const failOn: Severity = options.failOn ?? "high";
  if (!exceeds(res, failOn)) return text;

  const mode = options.onViolation ?? "throw";
  if (mode === "report") return text;
  if (mode === "throw") throw new AgentGuardError(target, res.findings);

  // mode === "redact"
  const redacted = redactText(text, res.findings);
  const left = runAudit(redacted, target, options, enableSchema);
  if (exceeds(left, failOn)) {
    throw new AgentGuardError(target, left.findings);
  }
  return redacted;
}

/**
 * Extracts raw text from LangChain message representations.
 */
export function extractMessageText(msg: any): string {
  if (typeof msg === "string") return msg;
  if (!msg || typeof msg !== "object") return "";
  if (Array.isArray(msg)) {
    if (msg.length >= 2 && typeof msg[0] === "string" && typeof msg[1] === "string") {
      return msg[1];
    }
    return msg.map(extractMessageText).filter(Boolean).join("\n");
  }
  if (typeof msg.content === "string") return msg.content;
  if (Array.isArray(msg.content)) {
    return msg.content
      .map((part: any) => {
        if (typeof part === "string") return part;
        if (part && typeof part === "object") {
          if (typeof part.text === "string") return part.text;
          if (typeof part.content === "string") return part.content;
          return JSON.stringify(part);
        }
        return String(part ?? "");
      })
      .filter(Boolean)
      .join(" ");
  }
  if (typeof msg.text === "string") return msg.text;
  if (typeof msg.pageContent === "string") return msg.pageContent;
  if (typeof msg.toString === "function" && msg.toString !== Object.prototype.toString) {
    return msg.toString();
  }
  return "";
}

function isUserMessage(msg: any): boolean {
  if (!msg) return false;
  if (Array.isArray(msg) && typeof msg[0] === "string") {
    const role = msg[0].toLowerCase();
    return role === "user" || role === "human";
  }
  if (typeof msg === "object") {
    const role = (
      msg.role ||
      msg.type ||
      (typeof msg._getType === "function" ? msg._getType() : "")
    )?.toLowerCase();
    if (role === "user" || role === "human") return true;
    if (msg.constructor?.name === "HumanMessage") return true;
  }
  return false;
}

function findTargetMessage(messages: any[]): { index: number; text: string; message: any } | null {
  if (!Array.isArray(messages) || messages.length === 0) return null;

  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i];
    if (isUserMessage(msg)) {
      return { index: i, text: extractMessageText(msg), message: msg };
    }
  }

  const lastIndex = messages.length - 1;
  const lastMsg = messages[lastIndex];
  return { index: lastIndex, text: extractMessageText(lastMsg), message: lastMsg };
}

function setMessageContent(msg: any, newContent: string): any {
  if (typeof msg === "string") return newContent;
  if (Array.isArray(msg)) {
    if (msg.length >= 2 && typeof msg[0] === "string") {
      const cloned = [...msg];
      cloned[1] = newContent;
      return cloned;
    }
    return msg;
  }
  if (msg && typeof msg === "object") {
    const cloned = { ...msg };
    if (typeof cloned.content === "string") {
      cloned.content = newContent;
    } else if (Array.isArray(cloned.content)) {
      cloned.content = cloned.content.map((p: any) => {
        if (p && typeof p === "object" && typeof p.text === "string") {
          return { ...p, text: newContent };
        }
        return p;
      });
    } else if (typeof cloned.text === "string") {
      cloned.text = newContent;
    } else {
      cloned.content = newContent;
    }
    return cloned;
  }
  return msg;
}

export function extractTextFromUnknown(value: any): string {
  if (typeof value === "string") return value;
  if (value === null || value === undefined) return "";
  if (Array.isArray(value)) {
    const target = findTargetMessage(value);
    if (target && target.text) return target.text;
    return value.map(extractTextFromUnknown).filter(Boolean).join("\n");
  }
  if (typeof value === "object") {
    if (typeof value.content === "string") return value.content;
    if (typeof value.prompt === "string") return value.prompt;
    if (typeof value.input === "string") return value.input;
    if (typeof value.question === "string") return value.question;
    if (typeof value.query === "string") return value.query;
    if (typeof value.text === "string") return value.text;
    if (typeof value.output === "string") return value.output;
    if (typeof value.result === "string") return value.result;
    if (typeof value.response === "string") return value.response;
    if (Array.isArray(value.messages)) {
      const target = findTargetMessage(value.messages);
      if (target && target.text) return target.text;
      return value.messages.map(extractTextFromUnknown).filter(Boolean).join("\n");
    }
    if (typeof value.pageContent === "string") return value.pageContent;
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }
  return String(value);
}

function applyRedaction(original: any, newText: string): any {
  if (typeof original === "string") return newText;
  if (Array.isArray(original)) {
    const target = findTargetMessage(original);
    if (target) {
      const copy = [...original];
      copy[target.index] = setMessageContent(copy[target.index], newText);
      return copy;
    }
    return original;
  }
  if (original && typeof original === "object") {
    const copy = { ...original };
    if (typeof copy.content === "string") {
      copy.content = newText;
      return copy;
    }
    if (typeof copy.prompt === "string") {
      copy.prompt = newText;
      return copy;
    }
    if (typeof copy.input === "string") {
      copy.input = newText;
      return copy;
    }
    if (typeof copy.question === "string") {
      copy.question = newText;
      return copy;
    }
    if (typeof copy.query === "string") {
      copy.query = newText;
      return copy;
    }
    if (typeof copy.text === "string") {
      copy.text = newText;
      return copy;
    }
    if (typeof copy.output === "string") {
      copy.output = newText;
      return copy;
    }
    if (typeof copy.result === "string") {
      copy.result = newText;
      return copy;
    }
    if (typeof copy.response === "string") {
      copy.response = newText;
      return copy;
    }
    if (Array.isArray(copy.messages)) {
      const target = findTargetMessage(copy.messages);
      if (target) {
        copy.messages = [...copy.messages];
        copy.messages[target.index] = setMessageContent(copy.messages[target.index], newText);
        return copy;
      }
    }
    return copy;
  }
  return original;
}

/**
 * Creates an AgentGuard runnable compatible with LangChain / LangGraph LCEL (.invoke()).
 * Audits input (prompt), executes the wrapped runnable or pipeline function, and audits output.
 */
export function createAgentGuardRunnable<TInput = any, TOutput = any>(
  runnable:
    | { invoke: (input: TInput, ...args: any[]) => Promise<TOutput> }
    | ((input: TInput, ...args: any[]) => Promise<TOutput> | TOutput),
  options?: AgentGuardRunnableOptions<TInput, TOutput>,
): AgentGuardRunnable<TInput, TOutput>;

export function createAgentGuardRunnable<TInput = any, TOutput = any>(
  options: AgentGuardRunnableOptions<TInput, TOutput>,
): AgentGuardRunnable<TInput, TOutput>;

export function createAgentGuardRunnable<TInput = any, TOutput = any>(
  runnableOrOptions:
    | { invoke: (input: TInput, ...args: any[]) => Promise<TOutput> }
    | ((input: TInput, ...args: any[]) => Promise<TOutput> | TOutput)
    | AgentGuardRunnableOptions<TInput, TOutput>,
  maybeOptions?: AgentGuardRunnableOptions<TInput, TOutput>,
): AgentGuardRunnable<TInput, TOutput> {
  let runnable:
    | { invoke: (input: TInput, ...args: any[]) => Promise<TOutput> }
    | ((input: TInput, ...args: any[]) => Promise<TOutput> | TOutput)
    | undefined;
  let options: AgentGuardRunnableOptions<TInput, TOutput>;

  if (
    typeof runnableOrOptions === "function" ||
    (runnableOrOptions && typeof (runnableOrOptions as any).invoke === "function")
  ) {
    runnable = runnableOrOptions as any;
    options = maybeOptions ?? {};
  } else {
    options = (runnableOrOptions as AgentGuardRunnableOptions<TInput, TOutput>) ?? {};
    runnable = options.runnable;
  }

  const runnableInstance: AgentGuardRunnable<TInput, TOutput> = {
    async invoke(input: TInput, ...args: any[]): Promise<TOutput> {
      // 1. Audit Input (Prompt)
      const promptText = options.inputExtractor
        ? options.inputExtractor(input)
        : extractTextFromUnknown(input);

      const safePromptText = enforcePolicy(promptText, "prompt", options);
      const safeInput =
        safePromptText !== promptText
          ? applyRedaction(input, safePromptText)
          : input;

      // 2. Execute wrapped function or runnable
      let rawOutput: any;
      if (typeof runnable === "function") {
        rawOutput = await runnable(safeInput, ...args);
      } else if (runnable && typeof runnable.invoke === "function") {
        rawOutput = await runnable.invoke(safeInput, ...args);
      } else {
        rawOutput = safeInput;
      }

      // 3. Audit Output
      if (options.outputExtractor) {
        const outputText = options.outputExtractor(rawOutput);
        const safeOutputText = enforcePolicy(outputText, "output", options);
        return safeOutputText !== outputText
          ? applyRedaction(rawOutput, safeOutputText)
          : rawOutput;
      }

      if (runnable) {
        const outputText = extractTextFromUnknown(rawOutput);
        const safeOutputText = enforcePolicy(outputText, "output", options);
        return safeOutputText !== outputText
          ? applyRedaction(rawOutput, safeOutputText)
          : rawOutput;
      }

      return rawOutput;
    },

    async batch(inputs: TInput[], ...args: any[]): Promise<TOutput[]> {
      return Promise.all(inputs.map((inp) => runnableInstance.invoke(inp, ...args)));
    },

    pipe<TNext>(next: any): AgentGuardRunnable<TInput, TNext> {
      return createAgentGuardRunnable<TInput, TNext>({
        invoke: async (input: TInput, ...args: any[]) => {
          const intermediate = await runnableInstance.invoke(input, ...args);
          if (typeof next?.invoke === "function") {
            return next.invoke(intermediate, ...args);
          } else if (typeof next === "function") {
            return next(intermediate, ...args);
          }
          return intermediate as unknown as TNext;
        },
        ...options,
      } as any);
    },

    async *transform(generator: AsyncIterable<TInput>, ...args: any[]): AsyncGenerator<TOutput, void, void> {
      for await (const chunk of generator) {
        yield await runnableInstance.invoke(chunk, ...args);
      }
    },
  };

  return runnableInstance;
}

/**
 * Wraps a LangChain-compatible chat model (e.g. ChatOpenAI, ChatAnthropic).
 * Intercepts calls to `.invoke(messages)`, extracts text from the last user message
 * or array of messages, audits input before model invocation, and audits `response.content`
 * before returning.
 */
export function wrapLangChainChatModel<T extends LangChainChatModel>(
  model: T,
  options: GuardOptions = {},
): T {
  async function guardedInvoke(input: any, ...args: any[]): Promise<any> {
    // 1. Extract prompt text
    let targetText = "";
    let targetMsgInfo: { index: number; text: string; message: any } | null = null;
    let isArrayMessages = false;
    let isObjWithMessages = false;

    if (typeof input === "string") {
      targetText = input;
    } else if (Array.isArray(input)) {
      isArrayMessages = true;
      targetMsgInfo = findTargetMessage(input);
      targetText = targetMsgInfo ? targetMsgInfo.text : extractMessageText(input);
    } else if (input && typeof input === "object") {
      if (Array.isArray(input.messages)) {
        isObjWithMessages = true;
        targetMsgInfo = findTargetMessage(input.messages);
        targetText = targetMsgInfo ? targetMsgInfo.text : extractMessageText(input.messages);
      } else if (typeof input.content === "string") {
        targetText = input.content;
      } else {
        targetText = extractTextFromUnknown(input);
      }
    }

    // 2. Audit prompt
    const safeTargetText = enforcePolicy(targetText, "prompt", options);

    let safeInput = input;
    if (safeTargetText !== targetText) {
      if (typeof input === "string") {
        safeInput = safeTargetText;
      } else if (isArrayMessages && targetMsgInfo) {
        const copy = [...input];
        copy[targetMsgInfo.index] = setMessageContent(copy[targetMsgInfo.index], safeTargetText);
        safeInput = copy;
      } else if (isObjWithMessages && targetMsgInfo) {
        const copyMessages = [...input.messages];
        copyMessages[targetMsgInfo.index] = setMessageContent(copyMessages[targetMsgInfo.index], safeTargetText);
        safeInput = { ...input, messages: copyMessages };
      } else if (input && typeof input === "object" && typeof input.content === "string") {
        safeInput = { ...input, content: safeTargetText };
      }
    }

    // 3. Execute chat model invoke
    const response = await model.invoke(safeInput, ...args);

    // 4. Extract and audit response.content
    let responseText = "";
    if (typeof response === "string") {
      responseText = response;
    } else if (response && typeof response === "object") {
      if (typeof response.content === "string") {
        responseText = response.content;
      } else if (Array.isArray(response.content)) {
        responseText = response.content
          .map((part: any) => (typeof part === "string" ? part : part?.text ?? ""))
          .join(" ");
      } else if (typeof response.text === "string") {
        responseText = response.text;
      } else {
        responseText = String(response.content ?? "");
      }
    }

    const safeResponseText = enforcePolicy(responseText, "output", options);

    if (safeResponseText !== responseText) {
      if (typeof response === "string") {
        return safeResponseText;
      }
      if (response && typeof response === "object") {
        if (typeof response.content === "string") {
          response.content = safeResponseText;
        } else if (Array.isArray(response.content)) {
          const textPart = response.content.find(
            (p: any) => p && typeof p === "object" && typeof p.text === "string",
          );
          if (textPart) {
            textPart.text = safeResponseText;
          } else {
            response.content = safeResponseText;
          }
        } else if (typeof response.text === "string") {
          response.text = safeResponseText;
        }
      }
    }

    return response;
  }

  return new Proxy(model, {
    get(target, prop, receiver) {
      if (prop === "invoke") {
        return guardedInvoke;
      }
      if (prop === "call" && typeof target.call === "function") {
        return guardedInvoke;
      }
      return Reflect.get(target, prop, receiver);
    },
  });
}

function extractToolArgsString(args: any): string {
  if (typeof args === "string") return args;
  if (args === null || args === undefined) return "";
  if (typeof args === "object") {
    try {
      return JSON.stringify(args);
    } catch {
      return String(args);
    }
  }
  return String(args);
}

/**
 * Guards a LangChain tool call (function calling). Audits tool JSON arguments before execution,
 * preventing Tool Misuse, prompt injections, or unauthorized secret/PII exfiltration to external APIs.
 */
export function guardToolCall<
  TTool extends {
    name: string;
    call?: (args: any, ...rest: any[]) => Promise<any>;
    invoke?: (args: any, ...rest: any[]) => Promise<any>;
    [key: string]: any;
  },
>(tool: TTool, options: GuardOptions = {}): TTool {
  function checkAndSanitizeArgs(args: any): any {
    const rawArgsString = extractToolArgsString(args);
    const safeArgsString = enforcePolicy(
      rawArgsString,
      "prompt",
      options,
      Boolean(options.schema),
    );

    if (safeArgsString !== rawArgsString) {
      if (typeof args === "string") {
        return safeArgsString;
      }
      if (args && typeof args === "object") {
        try {
          return JSON.parse(safeArgsString);
        } catch {
          return args;
        }
      }
    }
    return args;
  }

  return new Proxy(tool, {
    get(target, prop, receiver) {
      if (prop === "invoke") {
        return async (args: any, ...rest: any[]) => {
          const safeArgs = checkAndSanitizeArgs(args);
          if (typeof target.invoke === "function") {
            return target.invoke(safeArgs, ...rest);
          }
          if (typeof target.call === "function") {
            return target.call(safeArgs, ...rest);
          }
          throw new Error(`Tool ${target.name} does not implement invoke or call`);
        };
      }
      if (prop === "call") {
        return async (args: any, ...rest: any[]) => {
          const safeArgs = checkAndSanitizeArgs(args);
          if (typeof target.call === "function") {
            return target.call(safeArgs, ...rest);
          }
          if (typeof target.invoke === "function") {
            return target.invoke(safeArgs, ...rest);
          }
          throw new Error(`Tool ${target.name} does not implement call or invoke`);
        };
      }
      return Reflect.get(target, prop, receiver);
    },
  });
}
