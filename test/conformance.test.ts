// SPDX-License-Identifier: Apache-2.0

// Runs the conformance files of the specification (spec/conformance) against the
// library directly. The test tool of the specification runs the same cases through the
// harness; see README.
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { test } from "node:test";
import * as library from "../src/index.ts";
import { entryDigest, parseJwks, verifyAudit, verifyAuditLines, verifySigned, type Json } from "../src/index.ts";
import { answer, readMessage } from "../src/harness.ts";
import { specFile } from "../src/spec.ts";
import { type Case, cases, mandateConformance } from "./cases.ts";

mandateConformance("node entry", library);

test("signed mandates", () => {
  for (const c of cases("conformance/signed-v0.json")) {
    const keys = parseJwks(JSON.parse(specFile(c.keys)) as Json);
    if (c.expected === "valid") assert.equal(verifySigned(c.jws, c.issuer, keys).digest, c.digest, c.why);
    else assert.throws(() => verifySigned(c.jws, c.issuer, keys), `${c.id}: ${c.why}`);
  }
});

test("audit logs", () => {
  // The entries are read from the file text, so that number spellings survive.
  const text = specFile("conformance/audit-v0.json");
  for (const c of cases("conformance/audit-v0.json", "logs")) {
    const anchor = c.keys ? { keys: parseJwks(JSON.parse(specFile(c.keys)) as Json), logId: c.log_id } : undefined;
    const entries: string[] = (c.entries ?? []).map((e: Json) => JSON.stringify(e));
    const result = c.jsonl !== undefined ? verifyAuditLines(c.jsonl, anchor) : verifyAudit(entries, anchor);
    assert.equal(result.valid, c.expected === "valid", `${c.id}: ${c.why}`);
    if (!result.valid) assert.equal(result.brokenAt, c.broken_at, `${c.id}: ${c.why}`);
    if (c.anchored !== undefined) assert.equal(result.anchored, c.anchored, `${c.id}: ${c.why}`);
    (c.entry_digests ?? []).forEach((d: string, i: number) => assert.equal(entryDigest(entries[i]!), d));
  }
  assert.ok(text.includes('"seq": 1.0'), "the number spelling cases are part of the file");
});

test("audit cases for template and approver changes are part of the file", () => {
  const ids = new Set(cases("conformance/audit-v0.json", "logs").map((c) => c.id as string));
  for (let n = 58; n <= 76; n++) assert.ok(ids.has(`a${n}`), `a${n} is missing`);
});

test("audit cases for removal and reconnection are part of the file", () => {
  const ids = new Set(cases("conformance/audit-v0.json", "logs").map((c) => c.id as string));
  for (let n = 77; n <= 88; n++) assert.ok(ids.has(`a${n}`), `a${n} is missing`);
});

test("audit cases for cancelled approval requests are part of the file", () => {
  const ids = new Set(cases("conformance/audit-v0.json", "logs").map((c) => c.id as string));
  for (let n = 89; n <= 105; n++) assert.ok(ids.has(`a${n}`), `a${n} is missing`);
});

test("harness answers every operation and rejects unknown ones", () => {
  const caps = answer({ op: "capabilities" }) as { ops: string[]; version: string };
  assert.equal(caps.ops.length, 7);
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string; homeMandateSpec: string };
  assert.equal(caps.version, pkg.version);
  assert.match(pkg.homeMandateSpec, /^v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/);
  assert.deepEqual(answer({ op: "dance" }), { error: "unsupported" });
  assert.deepEqual(answer({ op: "validate", mandate: "{" }), { valid: false });
  assert.deepEqual(answer({ op: "entry_digest", entry: '{"a":1,"a":2}' }), { valid: false });
  const example = specFile("examples/voice-assistant.json");
  const response = answer({
    op: "evaluate", mandate: example,
    request: { resource: { entity_id: "lock.haustuer", category: "lock", areas: ["flur"] }, action: "unlock", time: "2026-10-12T19:00:00+02:00" },
  }) as Case;
  assert.equal(response.decision, "ask");
  assert.equal(response.approval_timeout, "PT2M");
});

test("harness refuses members the test interface does not define", () => {
  const request = { resource: { entity_id: "light.desk", category: "light", area: "office" }, action: "turn_on", time: "2026-10-12T19:00:00+02:00" };
  assert.deepEqual(answer({ op: "evaluate", mandate: "{}", request }), { error: "undefined member area" });
  assert.deepEqual(answer({ op: "validate", mandate: "{}", extra: 1 } as never), { error: "undefined member extra" });
  assert.deepEqual(
    answer({ op: "select", mandates: [{ mandate: "{}", stale: true }], subject: { client_id: "c", principal: "p" }, request } as never),
    { error: "undefined member area" },
  );
});

test("harness reads parameters by their exact value and reports a deny that is not enforced", () => {
  const mandate = specFile("conformance/mandates/one-of.json");
  const line = (brightness: string) =>
    `{"op":"evaluate","mandate":${JSON.stringify(mandate)},"request":{"resource":{"entity_id":"light.desk","category":"light"},"action":"set","parameters":{"brightness":${brightness}},"time":"2026-10-12T12:00:00+02:00"}}`;
  assert.equal((answer(readMessage(line("50.00000000000000000001"))) as Case).reason, "invalid_request");
  assert.notEqual((answer(readMessage(line("5e1"))) as Case).reason, "invalid_request");
  const audit = specFile("conformance/mandates/audit-mode.json");
  const denied = answer({
    op: "evaluate", mandate: audit,
    request: { resource: { entity_id: "switch.unknown", category: "switch" }, action: "turn_on", time: "2026-10-12T12:00:00+02:00" },
  }) as Case;
  assert.equal(denied.decision, "deny");
  assert.equal(denied.enforced, false);
});

test("cases for sets of areas, parameters and audit mode are part of the files", () => {
  const ids = (path: string, key = "cases") => new Set(cases(path, key).map((c) => c.id as string));
  const expect = (set: Set<string>, prefix: string, from: number, to: number) => {
    for (let n = from; n <= to; n++) assert.ok(set.has(`${prefix}${n}`), `${prefix}${n} is missing`);
  };
  expect(ids("conformance/cases-v0.json"), "c", 140, 192);
  expect(ids("conformance/invalid-v0.json"), "i", 129, 148);
  expect(ids("conformance/digest-v0.json"), "d", 41, 44);
  expect(ids("conformance/audit-v0.json", "logs"), "a", 106, 125);
});
