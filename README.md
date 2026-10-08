# Home-Mandate Specification: TypeScript implementation

An independent TypeScript implementation of the [Home-Mandate Specification](https://github.com/home-mandate/spec) v0:
validation of mandates, digests, the evaluation rule, the selection of the mandate, verification of
audit logs with checkpoints, and signed mandates.

It exists for two reasons:

- **A second implementation finds what one implementation cannot.** It shares no code with the
  Go reference. It validates with the normative JSON Schemas and an ECMA-262 regular expression
  engine, computes time zones with `Intl`, digests with its own SHA-256 and signatures with
  `node:crypto`. Where the two disagree, the specification is ambiguous, and the disagreement
  becomes a conformance case.
- **Use in JavaScript and TypeScript**, for example to check a mandate in a user interface
  before it is stored, also in a web browser (see below).

Status: draft, like the specification. Not published to a registry yet.

## Use

```ts
import { evaluate, parseMandate } from "@home-mandate/spec";

const mandate = parseMandate(text); // throws MandateError if the mandate is not valid
const result = evaluate(mandate, {
  resource: { entity_id: "front-door", category: "lock" },
  action: "unlock",
  time: "2026-10-12T19:00:00+02:00",
  timezone: "Europe/Berlin",
});
// { decision: "ask", reason: "rule", rule_id: "r-locks", approval: {…}, mandate_digest: "sha256:…" }
```

The resource (category, area, critical marking), the time and the time zone are determined by
the caller from its own directory, clock and configuration, never taken from the agent
(SPEC-v0 section 4).

### In a web browser

`@home-mandate/spec/browser` (`src/browser.ts`) offers validation, digest, evaluation,
selection, succession and the vocabulary, without signatures and audit logs:

```ts
import { evaluate, isCritical, MandateError, parseMandate, vocabulary } from "@home-mandate/spec/browser";

try {
  const mandate = parseMandate(text);
} catch (e) {
  if (e instanceof MandateError) show(e.message); // e.g. "violates the schema at /rules/0: must have required property 'id'"
}
```

Its import graph contains no Node.js built-in modules and no packages, and nothing compiles
code at run time, so it runs under a Content Security Policy of `script-src 'self'` without
`'unsafe-eval'`: the files of the specification are imported as JSON modules
(`with { type: "json" }`), the JSON Schema validators are generated ahead of time with Ajv's
standalone code (`src/generated/`, `node scripts/generate-validators.ts`) and SHA-256 is
implemented in `src/sha256.ts`. The sources are TypeScript; a bundler such as Vite or esbuild
compiles them. `test/browser.test.ts` checks the import graph and runs the conformance cases of
the specification against this entry, also with code generation from strings disallowed.

## Conformance

`spec/` holds the machine-readable files of the specification, copied with
`node scripts/sync-spec.ts <path to the specification repository>`, which checks every file against the
manifest of the specification and regenerates the schema validators in `src/generated/`; a
test fails if they are not current with `spec/schema/`.

```
node --test test/*.test.ts                    # the conformance files against the library
mandate-conformance -classes evaluator,selection,signatures,audit,audit-anchored \
  -exec node src/harness.ts            # the same through the test tool of the specification
```

`src/harness.ts` implements the process binding of the test interface (SPEC-v0 section 10.2).

## Versions

This implementation has version numbers of its own (semantic versioning, `package.json`
`version`, tags `v0.1.0-alpha.1`, …), independent of the tags of the specification: a fix here
needs no new specification, and a clarification of the specification no new release here.
Which version of the specification it implements is `homeMandateSpec` in `package.json`, and every
release names it:

| This implementation | implements the Home-Mandate Specification |
|---|---|
| v0.1.0-alpha.1 | v0.1.0-alpha.1 |

Version numbers restarted with the rename from mandate-spec. Earlier releases as mandate-spec-ts
(v0.1.0-alpha.1 to v0.1.0-alpha.4, implementing mandate-spec v0.2.0-alpha.2 to v0.2.0-alpha.5)
are marked by the tag `archive/mandate-spec-ts-v0.1.0-alpha.4`.

`spec/` holds exactly the files of that tag (checked against its manifest), and CI runs the
test tool of that tag. The harness reports the version of this implementation, so a conformance
report names both.

## Contributing

Changes go through a pull request from a short-lived branch (`feature/…`, `fix/…`, `ci/…`)
against `main`, which is protected: no direct pushes, squash merge only, every required check
green and the branch up to date. A push to a branch runs the type check and the tests
(`ci.yml`); a pull request additionally runs the test tool of the specification
(`integration.yml`). Nothing runs after the merge, and every merge is tagged. Independent of
changes, `pnpm audit` runs every night (`scheduled.yml`); a failure opens an issue.

## Requirements

Node.js 24 or newer, or a current web browser for the browser entry; the sources are
TypeScript that Node runs directly. No runtime dependencies: `ajv` generates the schema
validators at development time.

## License

Apache 2.0, see `LICENSE`.
