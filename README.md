# mandate-spec-ts

An independent TypeScript implementation of [mandate-spec](https://github.com/mandate-spec/mandate-spec) v0:
validation of mandates, digests, the evaluation rule, the selection of the mandate, verification of
audit logs with checkpoints, and signed mandates.

It exists for two reasons:

- **A second implementation finds what one implementation cannot.** It shares no code with the
  Go reference. It validates with the normative JSON Schemas and an ECMA-262 regular expression
  engine, computes time zones with `Intl` and signatures with `node:crypto`. Where the two
  disagree, the specification is ambiguous, and the disagreement becomes a conformance case.
- **Use in JavaScript and TypeScript**, for example to check a mandate in a user interface
  before it is stored.

Status: draft, like the specification. Not published to a registry yet.

## Use

```ts
import { evaluate, parseMandate } from "@mandate-spec/mandate-spec";

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

## Conformance

`spec/` holds the machine-readable files of the specification, copied with
`node scripts/sync-spec.ts <path to mandate-spec>`, which checks every file against the
manifest of the specification.

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
Which version of the specification it implements is `mandateSpec` in `package.json`, and every
release names it:

| mandate-spec-ts | implements mandate-spec |
|---|---|
| v0.1.0-alpha.1 | v0.2.0-alpha.2 |

`spec/` holds exactly the files of that tag (checked against its manifest), and CI runs the
test tool of that tag. The harness reports the version of this implementation, so a conformance
report names both.

## Requirements

Node.js 24 or newer; the sources are TypeScript that Node runs directly. One runtime
dependency: `ajv` for JSON Schema.

## License

Apache 2.0, see `LICENSE`.
