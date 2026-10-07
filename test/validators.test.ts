// SPDX-License-Identifier: Apache-2.0

// The generated schema validators (src/generated/) are current with spec/schema/, use
// the library's own date-time check, and their run-time helpers behave like Ajv's.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { generateValidators } from "../scripts/generate-validators.ts";
import { validateMandate } from "../src/generated/mandate-validator.ts";
import { MandateError, parseMandate } from "../src/mandate.ts";
import { equal, type SchemaValidator, ucs2length } from "../src/schema-runtime.ts";
import { specFile } from "../src/spec.ts";

const ROOT = join(import.meta.dirname, "..");

test("generated validators are current with the schemas", () => {
  const generated = generateValidators();
  assert.ok(generated.size > 0);
  for (const [path, code] of generated) {
    assert.equal(readFileSync(join(ROOT, path), "utf8"), code, `${path} is out of date: run node scripts/generate-validators.ts`);
  }
});

function example(change: (m: Record<string, unknown>) => void): Record<string, unknown> {
  const mandate = JSON.parse(specFile("examples/voice-assistant.json")) as Record<string, unknown>;
  change(mandate);
  return mandate;
}

test("format date-time is asserted with the library's own timestamp check", () => {
  const validator: SchemaValidator = validateMandate;
  assert.equal(validator(example(() => {})), true);
  for (const timestamp of ["2016-12-31T23:59:60Z", "2026-02-30T00:00:00Z", "2026-01-01T24:00:00Z"]) {
    assert.equal(validator(example((m) => (m.valid_from = timestamp))), false, timestamp);
    assert.equal(validator.errors?.[0]?.keyword, "format", timestamp);
  }
});

test("a schema violation names where it is", () => {
  const text = JSON.stringify(example((m) => (m.extra = 1)));
  assert.throws(() => parseMandate(text), (e: unknown) => e instanceof MandateError && e.message === "violates the schema at /: must NOT have additional properties (extra)");
  const rules = JSON.stringify(example((m) => ((m.rules as Record<string, unknown>[])[0]!.decision = "maybe")));
  assert.throws(() => parseMandate(rules), (e: unknown) => e instanceof MandateError && e.message.startsWith("violates the schema at /rules/0/decision: "));
});

test("run-time helpers of the validators", () => {
  assert.equal(ucs2length(""), 0);
  assert.equal(ucs2length("a\u{1F600}b"), 3);
  assert.equal(ucs2length("\uD800x"), 2);
  assert.ok(equal({ a: [1, { b: "c" }] }, { a: [1, { b: "c" }] }));
  assert.ok(!equal({ a: 1 }, { a: 1, b: 2 }));
  assert.ok(!equal([1], { 0: 1 }));
  assert.ok(!equal("1", 1));
  assert.ok(!equal(null, {}));
});
