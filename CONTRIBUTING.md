# Contributing to AgentGuard

Thanks for helping! Setup: `npm ci`, then `npm test` (vitest) and `npx tsc --noEmit`. Both must pass.

## Adding a rule

1. **Implement the `Rule` interface** from [`src/types.ts`](src/types.ts):

   ```ts
   interface Rule {
     id: string;                 // e.g. "SEC010"
     category: Category;         // "injection" | "secret" | "pii" | "schema"
     severity: Severity;         // "low" | "medium" | "high" | "critical"
     description: string;
     targets: Target[];          // "prompt" and/or "output"
     detect(text: string): RuleMatch[];  // { start, end, message? }
   }
   ```

2. **Add it in `src/rules/`**: put it in the matching file (`injection.ts`, `secrets.ts`, `pii.ts`) and append it to that file's exported array. Use helpers from `src/rules/util.ts` (`regexMatches`, `luhn`, `entropy`). Schema findings (`SCH*`) live in `src/schema.ts`.
3. **Add tests** (`src/*.test.ts`, vitest): at least one positive case, one negative case (a likely false positive), and, for new patterns, a check that the report does not contain the raw match.
4. **Document it** in the rules table in `README.md`.

## ID convention

`<PREFIX><3-digit number>`, numbered sequentially and never reused:

| Prefix | Category |
|---|---|
| `INJ` | Prompt injection |
| `SEC` | Secrets / credentials |
| `PII` | Personal data |
| `SCH` | JSON schema validation |

Choose severity conservatively: `critical` only for live credentials, `low` for noisy heuristics.

## Never leak secrets in reports

Findings must not contain the raw sensitive value. `Finding.match` is a redacted snippet (see `redact` in `src/rules/util.ts`); `message` strings must be static or describe the *kind* of issue, never echo matched text. Do not log, print or put in test names/fixtures any real credential: use obviously fake values. CI output and SARIF files are often public, so treat them as such.

## Pull requests

Keep changes focused, include tests, and make sure `npx tsc --noEmit` and `npm test` pass.
