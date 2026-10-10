// SPDX-License-Identifier: Apache-2.0

// Runs the conformance files of the specification (spec/conformance) against the
// library directly. The test tool of the specification runs the same cases through the
// harness; see README.
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { test } from "node:test";
import * as library from "../src/index.ts";
import { entryDigest, parseJwks, verifyAudit, verifyAuditLines, verifySigned, type Json } from "../src/index.ts";
import { answer } from "../src/harness.ts";
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
    request: { resource: { entity_id: "lock.haustuer", category: "lock", area: "flur" }, action: "unlock", time: "2026-10-12T19:00:00+02:00" },
  }) as Case;
  assert.equal(response.decision, "ask");
  assert.equal(response.approval_timeout, "PT2M");
});
