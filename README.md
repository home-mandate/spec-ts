<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/home-mandate/.github/main/profile/assets/hm-lockup-dark.svg">
  <img src="https://raw.githubusercontent.com/home-mandate/.github/main/profile/assets/hm-lockup.svg" alt="Home-Mandate – AI is coming home. Decide what it may do." width="360">
</picture>

# Home-Mandate Specification: TypeScript implementation

An independent TypeScript implementation of the [Home-Mandate Specification](https://github.com/home-mandate/spec) v0:
validation of mandates, digests, the evaluation rule, the selection of the mandate, verification of
audit logs with checkpoints, and signed mandates. What the specification is for, explained in plain
words, and the list of implementations are on [home-mandate.org](https://home-mandate.org/).

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

The resource (category, set of `areas`, critical marking), the time and the time zone are
determined by the caller from its own directory, clock and configuration, never taken from the
agent (SPEC-v0 section 4). Parameters are integers in the units of the vocabulary or strings
(`{ mode: "heat" }`); whoever reads them from JSON text reads numbers with `exactNumber`, so
that a fraction such as `50.00000000000000000001` is never taken for an integer (section 4.5).
For a mandate in audit mode (`"enforce": false`), a `deny` by its rules for an action that is
not critical carries `enforced: false`: the caller executes the request and records it
(section 4.6).

`verifyAudit(entries, anchor?)` and `verifyAuditLines(jsonl, anchor?)` verify an audit log
(sections 9.4 and 9.5). An entry with `enforced: false` is checked against vocabulary v0: it is
invalid for a critical action. For extension categories (section 5.1), pass their
vocabularies, as JSON text in the format of `vocabulary/v0.json`:

```ts
const result = verifyAuditWith(entries, { anchor, vocabularies: [paperlessVocabulary] });
```

Without the vocabulary of an extension, the verifier cannot tell which of its actions are
critical, and such entries pass.

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

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/home-mandate/.github/main/marks/compatible-dark.svg">
  <img src="https://raw.githubusercontent.com/home-mandate/.github/main/marks/compatible-light.svg" alt="Home-Mandate compatible" width="96" align="left">
</picture>

This implementation conforms to the Home-Mandate Specification `v0.1.0-rc.3` in the classes
`evaluator`, `selection`, `signatures`, `audit` and `audit-anchored` (SPEC-v0 section 8.1),
tested with the specification's test tool `mandate-conformance` on every pull request.
Security problems: [SECURITY.md](SECURITY.md).
<br clear="left">

`spec/` holds the machine-readable files of the specification, copied with
`node scripts/sync-spec.ts <path to the specification repository>`, which checks every file against the
manifest of the specification and regenerates the schema validators in `src/generated/`; a
test fails if they are not current with `spec/schema/`.

```
node --test test/*.test.ts                    # the conformance files against the library
mandate-conformance -classes evaluator,selection,signatures,audit,audit-anchored \
  -exec node src/harness.ts            # the same through the test tool of the specification
```

`test/fuzz/` holds fuzz tests with [fast-check](https://fast-check.dev/), one per fuzz
target of the Go reference: validation of a mandate (`parse`), the evaluation rule
(`evaluate`), parameter values (`value`), audit logs (`audit`), signatures (`jws`) and the
harness (`harness`). They mutate the files of the specification and check invariants
rather than expected results.

```
pnpm fuzz                                     # every target, 10 s each
FUZZ_TIME=120 node --test test/fuzz/evaluate.fuzz.ts     # one target, 2 minutes
FUZZ_SEED=… FUZZ_PATH=… node --test test/fuzz/evaluate.fuzz.ts   # reproduce a failure
```

A failure prints the seed, the path and the counterexample, and writes them to
`fuzz-failures/<target>.txt`.

`src/harness.ts` implements the process binding of the test interface (SPEC-v0 section 10.2).
Every release carries the report of that run as `conformance-report.json`, with build provenance
(`gh attestation verify conformance-report.json --repo home-mandate/spec-ts`).

## Versions

This implementation has version numbers of its own (semantic versioning, `package.json`
`version`, tags `v0.1.0-alpha.1`, …), independent of the tags of the specification: a fix here
needs no new specification, and a clarification of the specification no new release here.
Only the major version follows the format major of the specification (SPEC-v0 section 14):
format v0 → 0.x, format v1 → 1.x. Which exact specification tag it implements is
`homeMandateSpec` in `package.json`, and every release names it:

| This implementation | implements the Home-Mandate Specification |
|---|---|
| v0.1.0-alpha.1 | v0.1.0-alpha.1 |
| v0.1.0-alpha.2 | v0.1.0-alpha.2 |
| v0.1.0-alpha.3 | v0.1.0-alpha.3 |
| v0.1.0-alpha.4 | v0.1.0-alpha.4 |
| v0.1.0-rc.1 | v0.1.0-rc.1 |
| v0.1.0-rc.3 | v0.1.0-rc.3 |

From the specification's `v0.1.0` on, the v0 formats (mandate, audit entry, audit checkpoint)
are frozen; an incompatible change then comes with a new format major. Reading v0 data as part
of v1 (older audit entries in the same log, mandates moved to v1 by succession) is only added
here once a v1 format exists.

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
(`ci.yml`); a pull request additionally runs the test tool of the specification and short
fuzzing, one minute per target (`integration.yml`). Nothing runs after the merge, and every
merge is tagged. Independent of changes, `pnpm audit` runs every night and long fuzzing,
45 minutes per target, on the 1st and 15th of every month (`scheduled.yml`); a failure opens
an issue.

## Requirements

Node.js 24 or newer, or a current web browser for the browser entry; the sources are
TypeScript that Node runs directly. No runtime dependencies: `ajv` generates the schema
validators at development time, and `fast-check` generates the inputs of the fuzz tests.

## License

Apache 2.0, see `LICENSE`. The name Home-Mandate and its logo are not covered by this license.
