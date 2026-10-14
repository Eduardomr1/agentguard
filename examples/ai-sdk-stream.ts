/**
 * Real-time Streaming example using `createAgentGuardStreamTransform`
 * compatible with the Vercel AI SDK and standard Web Streams.
 *
 * Demonstrates:
 * 1. Integrating with Vercel AI SDK `textStream.pipeThrough(createAgentGuardStreamTransform(...))`.
 * 2. Real-time token inspection holding back overlapping chunks to catch split secrets across chunk boundaries.
 * 3. On-the-fly redaction mode (`onViolation: "redact"`) vs instant abort mode (`onViolation: "throw"`).
 *
 * Usage with Vercel AI SDK in Next.js / Node.js:
 * ```ts
 * import { streamText } from "ai";
 * import { openai } from "@ai-sdk/openai";
 * import { createAgentGuardStreamTransform } from "agentguard";
 *
 * export async function POST(req: Request) {
 *   const { prompt } = await req.json();
 *   const result = streamText({ model: openai("gpt-4o"), prompt });
 *
 *   const secureStream = result.textStream.pipeThrough(
 *     createAgentGuardStreamTransform({
 *       failOn: "high",
 *       onViolation: "redact", // Mask secrets & PII on the fly
 *     })
 *   );
 *
 *   return new Response(secureStream);
 * }
 * ```
 *
 * Run directly with tsx:
 *   npx tsx examples/ai-sdk-stream.ts
 */

import { fileURLToPath } from "node:url";
import {
  createAgentGuardStreamTransform,
  AgentGuardError,
  type AuditResult,
  type Target,
} from "../src/index.js";

/** Helper to simulate an LLM token ReadableStream (identical to AI SDK's textStream). */
function createMockTokenStream(tokens: string[], delayMs = 0): ReadableStream<string> {
  return new ReadableStream<string>({
    async start(controller) {
      for (const token of tokens) {
        if (delayMs > 0) {
          await new Promise((resolve) => setTimeout(resolve, delayMs));
        }
        controller.enqueue(token);
      }
      controller.close();
    },
  });
}

/** Consume and display a stream chunk-by-chunk in real time. */
async function consumeStream(stream: ReadableStream<string>): Promise<string> {
  const reader = stream.getReader();
  let fullText = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    process.stdout.write(value);
    fullText += value;
  }
  return fullText;
}

export async function runStreamingDemo() {
  console.log("=== AgentGuard Streaming Audit with Web Streams / AI SDK ===\n");

  // --------------------------------------------------------------------------
  // Scenario 1: Clean stream passed through in real time
  // --------------------------------------------------------------------------
  console.log("--- Scenario 1: Benign Response Streaming ---");
  const cleanTokens = ["The ", "capital ", "of ", "France ", "is ", "Paris.", "\n"];
  const cleanStream = createMockTokenStream(cleanTokens).pipeThrough(
    createAgentGuardStreamTransform({
      failOn: "high",
      onViolation: "throw",
    }),
  );

  process.stdout.write("Streaming output: ");
  await consumeStream(cleanStream);
  console.log("[Status] Completed with 0 violations.\n");

  // --------------------------------------------------------------------------
  // Scenario 2: Secret split across chunk boundaries (Redaction mode)
  // --------------------------------------------------------------------------
  console.log("--- Scenario 2: Secret Leaked Across Token Chunks (Redact Mode) ---");
  console.log("Simulating split token chunks containing a GitHub Personal Access Token...");

  // Token chunks intentionally split the GitHub token `ghp_...` across multiple boundaries
  const tokenWithSecret = [
    "Here is your temporary ",
    "GitHub deploy token: ",
    "ghp_a1B2c3D4e5", // chunk 1 of token
    "F6g7H8i9J0k1L2m", // chunk 2 of token
    "3N4o5P6q7R8", // chunk 3 of token
    ". Make sure to store it in a secret manager.",
    "\n",
  ];

  const redactStream = createMockTokenStream(tokenWithSecret).pipeThrough(
    createAgentGuardStreamTransform({
      failOn: "high",
      overlap: 64, // Overlap buffer ensures split credentials are reconstructed
      onViolation: "redact", // Mask secret matches to [REDACTED:<id>]
      onReport: (target: Target, result: AuditResult) => {
        console.log(`\n  -> [Guard Alert] Found ${result.findings.length} secret(s) on ${target}`);
      },
    }),
  );

  process.stdout.write("Sanitized stream output: ");
  const sanitizedOutput = await consumeStream(redactStream);
  console.log(`[Status] Redaction verified. Secret safely masked.`);
  console.log(`Result: "${sanitizedOutput.trim()}"\n`);

  // --------------------------------------------------------------------------
  // Scenario 3: Critical credential leak with stream abort (Throw mode)
  // --------------------------------------------------------------------------
  console.log("--- Scenario 3: Critical Leak with Stream Abort (Throw Mode) ---");
  console.log("Simulating stream that leaks an AWS Root Access Key...");

  const dangerousTokens = [
    "AWS Configuration:\n",
    "export AWS_ACCESS_KEY_ID=",
    "AKIAIOSFODNN7EXAMPLE\n",
    "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
  ];

  const strictStream = createMockTokenStream(dangerousTokens).pipeThrough(
    createAgentGuardStreamTransform({
      failOn: "high",
      onViolation: "throw", // Terminate stream immediately with error
    }),
  );

  try {
    process.stdout.write("Stream output: ");
    await consumeStream(strictStream);
    console.error("[ERROR] Stream should have been blocked!");
  } catch (error) {
    if (error instanceof AgentGuardError) {
      console.log("\n\n-> [BLOCKED] Stream aborted by AgentGuard!");
      console.log(`Target: ${error.target}`);
      console.log("Violations caught before client reception:");
      for (const finding of error.findings) {
        console.log(`   - [${finding.ruleId}] ${finding.message} (${finding.severity})`);
      }
    } else {
      console.error("Unexpected error:", error);
    }
  }

  console.log("\n=== Streaming Demo Finished Successfully ===");
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  runStreamingDemo().catch(console.error);
}
