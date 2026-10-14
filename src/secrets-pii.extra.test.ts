import { describe, expect, it } from "vitest";
import {
  audit,
  computeCurpCheckDigit,
  inspectJwtToken,
  pseudonymizeText,
  validateBrazilianCpf,
  validateMexicanCurp,
  validateSpanishId,
} from "./index.js";

const ruleIds = (text: string): string[] => audit(text).findings.map((f) => f.ruleId);

function toBase64Url(obj: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(obj), "utf8")
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

describe("expanded cloud, AI, package, and database secret rules (SEC011-SEC014)", () => {
  it("detects Anthropic and Hugging Face tokens as SEC011 without colliding with SEC003", () => {
    const anthropic = "sk-ant-api03-" + "A1b2C3d4E5f6G7h8I9j0K1l2";
    const ids = ruleIds(`ANTHROPIC_API_KEY=${anthropic}`);
    expect(ids).toContain("SEC011");
    expect(ids).not.toContain("SEC003");

    const hf = "hf_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567";
    expect(ruleIds(`HF_TOKEN=${hf}`)).toContain("SEC011");
  });

  it("detects Stripe live/test keys and npm access tokens (SEC012)", () => {
    const stripeKey = ["sk", "live", "51N9xAbCdEfGhIjKlMnOpQrSt"].join("_");
    const stripeRestricted = ["rk", "test", "99XyZaBcDeFgHiJkLmNoPqRs"].join("_");
    const npmToken = "npm_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";

    expect(ruleIds(stripeKey)).toContain("SEC012");
    expect(ruleIds(stripeRestricted)).toContain("SEC012");
    expect(ruleIds(npmToken)).toContain("SEC012");
  });

  it("detects database and message-broker connection URIs with credentials (SEC013)", () => {
    expect(ruleIds("postgres://dbadmin:S3cr3tP@ss99@db.internal.local:5432/production")).toContain(
      "SEC013",
    );
    expect(ruleIds("mongodb+srv://svc_user:MyMongoPass123@cluster0.example.mongodb.net/app")).toContain(
      "SEC013",
    );
    expect(ruleIds("rediss://default: cacheSecret987@cache.example.internal:6379")).not.toContain(
      "SEC013",
    );
    expect(ruleIds("rediss://default:cacheSecret987@cache.example.internal:6379/0")).toContain(
      "SEC013",
    );
    // Credential-free connection strings should not trigger SEC013
    expect(ruleIds("redis://localhost:6379/0")).not.toContain("SEC013");
  });

  it("detects Azure Storage AccountKey and SendGrid API keys (SEC014)", () => {
    const azureConn =
      "DefaultEndpointsProtocol=https;AccountName=prodstore;AccountKey=" +
      "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2==" +
      ";EndpointSuffix=core.windows.net";
    const sendGrid = "SG." + "a1B2c3D4e5F6g7H8i9J0" + "." + "k1L2m3N4o5P6q7R8s9T0u1V2";

    expect(ruleIds(azureConn)).toContain("SEC014");
    expect(ruleIds(sendGrid)).toContain("SEC014");
  });
});

describe("JWT structural security inspector (inspectJwtToken & SEC007)", () => {
  it("inspects claims, expiration, and algorithm without exposing claim values", () => {
    const header = toBase64Url({ alg: "HS256", typ: "JWT" });
    const payload = toBase64Url({
      sub: "user_42",
      email: "alice@corp.internal",
      role: "admin",
      iat: 1700000000,
      exp: 1700003600,
    });
    const token = `${header}.${payload}.dummysignature12345`;

    const infoExpired = inspectJwtToken(token, 1700010000);
    expect(infoExpired.validStructure).toBe(true);
    expect(infoExpired.algorithm).toBe("HS256");
    expect(infoExpired.tokenType).toBe("JWT");
    expect(infoExpired.isUnsignedNoneAlg).toBe(false);
    expect(infoExpired.isExpired).toBe(true);
    expect(infoExpired.sensitiveClaims).toEqual(["sub", "email", "role"]);

    const infoActive = inspectJwtToken(token, 1700001000);
    expect(infoActive.isExpired).toBe(false);
  });

  it("flags insecure unsigned alg=none JWTs even without a signature segment", () => {
    const header = toBase64Url({ alg: "none", typ: "JWT" });
    const payload = toBase64Url({ sub: "admin", permissions: ["*"] });
    const unsignedJwt = `${header}.${payload}.`;

    const info = inspectJwtToken(unsignedJwt);
    expect(info.validStructure).toBe(true);
    expect(info.isUnsignedNoneAlg).toBe(true);

    const res = audit(`Authorization: Bearer ${unsignedJwt}`);
    const jwtFinding = res.findings.find((f) => f.ruleId === "SEC007");
    expect(jwtFinding).toBeDefined();
    expect(jwtFinding?.message).toContain("alg=none");
  });

  it("handles malformed non-JWT strings safely", () => {
    expect(inspectJwtToken("not.a.jwt").validStructure).toBe(false);
    expect(inspectJwtToken("single-segment").validStructure).toBe(false);
  });
});

describe("international checksum-validated PII rules (PII007-PII009)", () => {
  it("validates and detects Mexican CURP identifiers (PII007)", () => {
    const base17 = "GODE561231GRRGR0"; // wait: 4+6+1+2+3+1 = 17 chars: GODE(4) 561231(6) H(1) GR(2) RGR(3) 0(1) = 17
    const prefix17 = "GODE561231HGRRGR0";
    const digit = computeCurpCheckDigit(prefix17);
    expect(digit).toBeGreaterThanOrEqual(0);
    const validCurp = `${prefix17}${digit}`;
    expect(base17.length).toBe(16);
    expect(validateMexicanCurp(validCurp, true)).toBe(true);
    expect(ruleIds(`CURP del solicitante: ${validCurp}`)).toContain("PII007");

    // Reject invalid state code "XX" and impossible February 30 date
    expect(validateMexicanCurp("GODE561231HXXRGR04")).toBe(false);
    expect(validateMexicanCurp("GODE560230HGRRGR04")).toBe(false);
    expect(ruleIds("GODE561231HXXRGR04")).not.toContain("PII007");
  });

  it("validates and detects Spanish DNI and NIE with Modulo-23 check letters (PII008)", () => {
    expect(validateSpanishId("12345678Z")).toBe(true);
    expect(validateSpanishId("X1234567L")).toBe(true);
    expect(validateSpanishId("12345678A")).toBe(false);

    expect(ruleIds("Documento DNI 12345678Z registrado")).toContain("PII008");
    expect(ruleIds("NIE extranjero: X1234567-L")).toContain("PII008");
    expect(ruleIds("Codigo producto 12345678A")).not.toContain("PII008");
  });

  it("validates and detects Brazilian CPF with two-digit Modulo-11 checksum (PII009)", () => {
    expect(validateBrazilianCpf("529.982.247-25")).toBe(true);
    expect(validateBrazilianCpf("529.982.247-26")).toBe(false);
    expect(validateBrazilianCpf("111.111.111-11")).toBe(false);

    expect(ruleIds("Cliente CPF 529.982.247-25 aprovado")).toContain("PII009");
    expect(ruleIds("CPF: 52998224725")).toContain("PII009");
    expect(ruleIds("529.982.247-26")).not.toContain("PII009");
    expect(ruleIds("111.111.111-11")).not.toContain("PII009");
  });

  it("supports hash and synthetic pseudonymization for new secret and PII rules", () => {
    const sample = "CPF 529.982.247-25 and DNI 12345678Z";
    const hashed = pseudonymizeText(sample, { mode: "hash", salt: "s1" });
    expect(hashed.text).toContain("cpf_");
    expect(hashed.text).toContain("dni_");
    expect(hashed.deanonymize(hashed.text)).toBe(sample);

    const synth = pseudonymizeText(sample, { mode: "synthetic" });
    expect(synth.text).not.toContain("529.982.247-25");
    expect(synth.deanonymize(synth.text)).toBe(sample);
  });
});
