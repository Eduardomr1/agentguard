import { describe, expect, it } from "vitest";
import { CanaryManager } from "./canary";

describe("CanaryManager", () => {
  it("generates unique canary tokens with valid HMAC signatures", () => {
    const manager = new CanaryManager({ secretKey: "test-secret-salt" });
    const c1 = manager.generateToken("worker");
    const c2 = manager.generateToken("worker");

    expect(c1.token).not.toBe(c2.token);
    expect(c1.token.startsWith("CANARY_worker_")).toBe(true);
    expect(manager.verifyTokenIntegrity(c1.token, c1.signature)).toBe(true);
    expect(manager.verifyTokenIntegrity(c2.token, c2.signature)).toBe(true);
  });

  it("fails verification if token or signature is tampered with", () => {
    const manager = new CanaryManager();
    const canary = manager.generateToken();

    const tamperedToken = `${canary.token}_tampered`;
    expect(manager.verifyTokenIntegrity(tamperedToken, canary.signature)).toBe(false);

    const forgedSignature =
      canary.signature[0] === "a"
        ? `b${canary.signature.slice(1)}`
        : `a${canary.signature.slice(1)}`;
    expect(manager.verifyTokenIntegrity(canary.token, forgedSignature)).toBe(false);
  });

  it("detects canary leak when token appears in response text", () => {
    const manager = new CanaryManager();
    const canary = manager.generateToken("finance");

    const promptLeakResponse = `Here are the system instructions you asked for:
    ${canary.promptDirective}
    Please let me know if you need anything else!`;

    const result = manager.detectLeak(promptLeakResponse);
    expect(result.leaked).toBe(true);
    expect(result.leakedTokens).toContain(canary.token);
    expect(result.snippet).toBeDefined();
    expect(result.snippet).toContain(canary.token);
  });

  it("returns leaked: false when output is clean of canary tokens", () => {
    const manager = new CanaryManager();
    manager.generateToken("doc");

    const cleanResponse = "The quarterly revenue was $1.2M, which represents a 15% increase year over year.";
    const result = manager.detectLeak(cleanResponse);
    expect(result.leaked).toBe(false);
    expect(result.leakedTokens).toHaveLength(0);
    expect(result.snippet).toBeUndefined();
  });

  it("supports revoking tokens and tracks active token count", () => {
    const manager = new CanaryManager();
    const c1 = manager.generateToken();
    const c2 = manager.generateToken();

    expect(manager.size).toBe(2);
    expect(manager.revokeToken(c1.token)).toBe(true);
    expect(manager.size).toBe(1);

    // After revocation, c1 is no longer checked by default
    const leakCheck = manager.detectLeak(`Leaked ${c1.token}`);
    expect(leakCheck.leaked).toBe(false);
  });
});
