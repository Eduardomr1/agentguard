import { describe, expect, it } from "vitest";
import { audit } from "./engine.js";
import { entropy } from "./rules/util.js";

const ids = (t: string) => audit(t).findings.map((f) => f.ruleId);

describe("SEC009 entropy", () => {
  it("computes entropy", () => {
    expect(entropy("aaaa")).toBe(0);
    expect(entropy("abcd")).toBeCloseTo(2);
  });
  it("flags random-looking tokens", () => {
    expect(ids("token x7Kq9ZpL2mVw8RtY4nBc6HjD1sFg")).toContain("SEC009");
  });
  it("ignores long words, paths and plain hex-less text", () => {
    expect(ids("internationalizationandlocalizationsupport")).not.toContain("SEC009");
    expect(ids("src/components/very/long/path/to/some/file")).not.toContain("SEC009");
  });
});
