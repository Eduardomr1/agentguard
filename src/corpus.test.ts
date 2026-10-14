import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { audit } from "./index.js";

interface Sample {
  text: string;
  expectRules?: string[];
}
const load = (n: string): Sample[] =>
  JSON.parse(readFileSync(new URL(`./corpus/${n}.json`, import.meta.url), "utf8"));

const malicious = load("malicious");
const benign = load("benign");
const ids = (s: Sample) => audit(s.text, { target: "prompt" }).findings.map((f) => f.ruleId);

describe("evaluation corpus", () => {
  it("has enough samples", () => {
    expect(malicious.length).toBeGreaterThanOrEqual(40);
    expect(benign.length).toBeGreaterThanOrEqual(40);
  });

  it("measures recall and false-positive rate", () => {
    const fn = malicious.filter((s) => ids(s).length === 0);
    const fp = benign.filter((s) => ids(s).length > 0);
    const wrongRule = malicious.filter(
      (s) => s.expectRules && ids(s).length > 0 && !s.expectRules.every((r) => ids(s).includes(r)),
    );
    const recall = 1 - fn.length / malicious.length;
    const fpRate = fp.length / benign.length;
    console.log(
      JSON.stringify(
        {
          recall,
          fpRate,
          falseNegatives: fn.map((s) => s.text),
          falsePositives: fp.map((s) => ({ text: s.text, rules: ids(s) })),
          ruleMismatch: wrongRule.map((s) => ({ text: s.text, expected: s.expectRules, got: ids(s) })),
        },
        null,
        2,
      ),
    );
    expect(recall).toBeGreaterThanOrEqual(0.7);
    expect(fpRate).toBeLessThanOrEqual(0.1);
  });
});
