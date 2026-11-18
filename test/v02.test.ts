// SPDX-License-Identifier: Apache-2.0

// What spec v0.2 adds beyond the conformance cases: the members the model reads, the date
// format, and the test interface of SPEC-v0 section 10.2.
import assert from "node:assert/strict";
import { test } from "node:test";
import { respond } from "../src/harness.ts";

/** A request through the harness as the test tool sends it: one line, one answer line. */
const answer = (message: object): Record<string, unknown> => JSON.parse(respond(JSON.stringify(message))) as Record<string, unknown>;
import { MODEL_MEMBERS, parseMandateBytes, MandateError } from "../src/mandate.ts";
import { parseJwks, SignatureError, MAX_KEY_SET_BYTES } from "../src/jws.ts";
import { specFile } from "../src/spec.ts";
import { validDate } from "../src/time.ts";

type Schema = { properties?: Record<string, Schema>; $defs?: Record<string, Schema>; oneOf?: Schema[]; additionalProperties?: Schema };

function names(schema: Schema | undefined): string[] {
  return Object.keys(schema?.properties ?? {}).sort();
}

// A member the schema gains in a later release must be read by the model, never accepted and
// ignored: a rule's own period that is ignored allows outside it (SPEC-v0 section 4, step 2).
test("the model reads every member of the mandate schema", () => {
  const schema = JSON.parse(specFile("schema/mandate-v0.schema.json")) as Schema;
  const defs = schema.$defs!;
  const constraintForms = defs.constraints!.additionalProperties!.oneOf!.flatMap((form) => names(form));
  const expected: Record<string, string[]> = {
    mandate: names(schema),
    rule: names(defs.rule),
    resource: names(defs.resource),
    conditions: names(defs.conditions),
    dates: names((defs.conditions!.properties!.dates as { items: Schema }).items),
    constraint: [...new Set(constraintForms)].sort(),
    rule_limits: names(defs.rule_limits),
    limits: names(schema.properties!.limits),
    approval: names(defs.approval),
    agent: names(schema.properties!.agent),
  };
  for (const [object, members] of Object.entries(expected)) {
    assert.deepEqual([...MODEL_MEMBERS[object]!].sort(), members, `${object}: the schema and the model name different members`);
  }
});

test("a date is a calendar date that exists, not in the year 0000", () => {
  for (const d of ["2026-12-24", "2028-02-29", "2000-02-29", "0001-01-01", "9999-12-31"]) assert.ok(validDate(d), d);
  for (const d of ["2026-02-29", "1900-02-29", "0000-01-01", "2026-13-01", "2026-1-05", "2026-12-24T00:00:00Z", " 2026-12-24", ""]) {
    assert.ok(!validDate(d), d);
  }
});

test("a mandate given as bytes is read as UTF-8 without decoding it otherwise", () => {
  const text = specFile("examples/voice-assistant.json");
  assert.ok(parseMandateBytes(Buffer.from(text, "utf8")).digest.startsWith("sha256:"));
  assert.throws(() => parseMandateBytes(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(text)])), MandateError, "byte order mark");
  assert.throws(() => parseMandateBytes(Buffer.from([0x7b, 0xff, 0x7d])), MandateError, "not UTF-8");
});

test("a key set given as text is at most 64 KiB and strict I-JSON", () => {
  const keys = specFile("conformance/keys/test-keys.json");
  assert.ok(parseJwks(keys).size > 0);
  assert.throws(() => parseJwks(keys.replace('"keys"', '"keys": [], "keys"')), SignatureError, "a member twice");
  assert.throws(() => parseJwks(keys + " ".repeat(MAX_KEY_SET_BYTES)), SignatureError, "too large");
});

const example = specFile("examples/voice-assistant.json");
const request = { resource: { entity_id: "light.living_room_ceiling", category: "light", areas: ["living_room"] }, action: "turn_on", time: "2026-10-12T19:00:00+02:00" };

test("the base64 form of a member is canonical base64 with padding, and only one form is given", () => {
  const b64 = Buffer.from(example).toString("base64");
  assert.deepEqual(answer({ op: "validate", mandate_base64: b64 }), answer({ op: "validate", mandate: example }));
  for (const bad of ["", " " + b64, b64.slice(0, -1), "@@@@"]) {
    assert.ok("error" in answer({ op: "validate", mandate_base64: bad }), JSON.stringify(bad));
  }
  // Padding bits that are not zero: "QR==" decodes to the byte of "QQ==".
  assert.ok("error" in answer({ op: "validate", mandate_base64: "QR==" }));
  assert.ok("error" in answer({ op: "validate", mandate: example, mandate_base64: b64 }), "both forms");
  assert.ok("error" in answer({ op: "verify_audit", entries: [], jsonl: "" }), "two forms of a log");
});

test("a member of another operation is malformed, and keys travel as text", () => {
  assert.deepEqual(answer({ op: "validate", mandate: example, request }), { error: "undefined member request" });
  assert.deepEqual(answer({ op: "entry_digest", entry: "{}", keys: "{}" }), { error: "undefined member keys" });
  assert.ok("error" in answer({ op: "verify_audit", entries: [], keys: { keys: [] } }), "keys as an object");
});

test("evaluate names the limited rules of an allow", () => {
  const mandate = JSON.parse(example) as { rules: Record<string, unknown>[] };
  mandate.rules = mandate.rules.map((r) => (r.decision === "allow" ? { ...r, limits: { max_actions_per_day: 3 } } : r));
  const allowed = answer({ op: "evaluate", mandate: JSON.stringify(mandate), request })
  assert.equal(allowed.decision, "allow");
  assert.deepEqual(allowed.limited_rules, [allowed.rule_id]);
  const plain = answer({ op: "evaluate", mandate: example, request });
  assert.ok(!("limited_rules" in plain), "no member without limited rules");
});
