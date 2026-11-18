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
  // Every definition of the schema that has members is one of the objects above, so that a new
  // object of a later release fails here as well.
  const covered: Record<string, string> = { rule: "rule", resource: "resource", conditions: "conditions", rule_limits: "rule_limits", approval: "approval" };
  for (const [name, def] of Object.entries(defs)) {
    if (def.properties) assert.ok(name in covered, `$defs/${name} has members the guard does not compare`);
  }
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

// The local date of a point in time of the year 9999 can lie in the year 10000, and of the
// year 0001 before it; neither may match a range of the years 1 to 9999 (SPEC-v0 section 4.2).
test("a local date beyond the years 1 to 9999 matches no range of dates", async () => {
  const { evaluate } = await import("../src/evaluate.ts");
  const { parseMandate } = await import("../src/mandate.ts");
  const mandate = parseMandate(JSON.stringify({
    type: "https://home-mandate.org/mandate/v0", id: "m-dates", principal: "household:t",
    agent: { client_id: "hm-client:test-0001", display_name: "Test" },
    rules: [{ id: "r-1", resource: { category: "light" }, actions: ["turn_on"], decision: "allow", conditions: { dates: [{ from: "0001-01-01", to: "1999-12-31" }] } }],
    default: "deny", approval: { timeout: "PT2M", approvers: ["a-1"] }, limits: { max_actions_per_hour: 10 },
    valid_from: "0001-01-01T00:00:00Z", created_by: "a-1", created_at: "0001-01-01T00:00:00Z",
  }));
  const at = (time: string, timezone?: string) =>
    evaluate(mandate, { resource: { entity_id: "light.a", category: "light" }, action: "turn_on", time, timezone }).reason;
  assert.equal(at("9999-12-31T23:59:59Z", "Asia/Tokyo"), "no_match", "the year 10000 in Tokyo");
  assert.equal(at("9999-12-31T23:59:59+14:00"), "no_match", "the year 10000 by the offset");
  assert.equal(at("1999-12-31T12:00:00Z", "Asia/Tokyo"), "rule", "the last day of the range");
});

test("the harness splits requests at the line feed only, not at U+2028", async () => {
  const { requestLines } = await import("../src/harness.ts");
  async function* chunks() {
    yield Buffer.from('{"op":"entry_digest","entry":"{\\"a\\":\\"x y\\"}"}\n{"op":"capa', "utf8");
    yield "bilities\"}\n";
  }
  const lines: string[] = [];
  for await (const line of requestLines(chunks())) lines.push(line);
  assert.equal(lines.length, 2);
  assert.ok("digest" in JSON.parse(respond(lines[0]!)), "one answer for the request with U+2028");
});

test("verify_audit with members of the wrong type is malformed, never valid", () => {
  for (const bad of [{ entries: "" }, { entries: [1] }, { entries: [null] }, { jsonl: 5 }, { jsonl_base64: 1 }, { log_id: 1, entries: [] }]) {
    assert.deepEqual(answer({ op: "verify_audit", ...bad }), { error: "malformed request" }, JSON.stringify(bad));
  }
  const keys = specFile("conformance/keys/test-keys.json");
  const digest = "sha256:" + "a".repeat(64);
  assert.ok("error" in answer({ op: "verify_audit", entries: [], keys, last_seen: { seq: 1.5, digest } }), "seq 1.5");
  // A seq no entry can have is never found: the log breaks, it is no error (SPEC-v0 section 9.5).
  const far = JSON.parse(respond(`{"op":"verify_audit","entries":[],"keys":${JSON.stringify(keys)},"last_seen":{"seq":9007199254740993,"digest":"${digest}"}}`));
  assert.equal(far.valid, false);
  assert.ok("error" in JSON.parse(respond(`{"op":"verify_audit","entries":[],"keys":${JSON.stringify(keys)},"last_seen":{"seq":1.0,"digest":"${digest}"}}`)), "seq 1.0");
});

test("JSON nested deeper than 32 levels has no digest", () => {
  const nested = (n: number) => '{"a":'.repeat(n - 1) + "{}" + "}".repeat(n - 1);
  assert.ok("digest" in answer({ op: "entry_digest", entry: nested(32) }), "32 levels");
  assert.deepEqual(answer({ op: "entry_digest", entry: nested(33) }), { error: "entry without a digest" }, "33 levels");
});
