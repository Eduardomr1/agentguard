import { Ajv } from "ajv";
import type { Finding } from "./types.js";

const ajv = new Ajv({ allErrors: true, strict: false });

/** Strip a ```json fenced block if the model wrapped its output. */
export function extractJson(text: string): string {
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  return (fence ? fence[1] : text).trim();
}

export function validateSchema(text: string, schema: object): Finding[] {
  const base = { category: "schema" as const, severity: "high" as const, start: 0, end: text.length };
  let data: unknown;
  try {
    data = JSON.parse(extractJson(text));
  } catch (e) {
    return [{ ...base, ruleId: "SCH001", message: `Output is not valid JSON: ${(e as Error).message}`, match: "" }];
  }
  let validate;
  try {
    validate = ajv.compile(schema);
  } catch (e) {
    return [{ ...base, ruleId: "SCH000", message: `Invalid schema: ${(e as Error).message}`, match: "" }];
  }
  if (validate(data)) return [];
  return (validate.errors ?? []).map((err) => ({
    ...base,
    ruleId: "SCH002",
    message: `${err.instancePath || "(root)"} ${err.message}`,
    match: "",
  }));
}
