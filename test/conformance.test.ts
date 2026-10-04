// SPDX-License-Identifier: Apache-2.0

// Runs the conformance files of the specification (spec/conformance) against the
// library directly. The test tool of the specification runs the same cases through the
// harness; see README.
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  entryDigest, evaluate, isSuccessor, parseJwks, selectAndEvaluate, tryParseMandate, verifyAudit, verifyAuditLines, verifySigned,
  type Json, type Request,
} from "../src/index.ts";
import { answer } from "../src/harness.ts";
import { specFile } from "../src/spec.ts";

type Case = Record<string, any>;

function cases(path: string, key = "cases"): Case[] {
  const list = JSON.parse(specFile(path))[key] as Case[];
  assert.ok(list.length > 0, `${path} has no cases`);
  return list;
}

function mandateText(c: Case): string {
  if (c.mandate) return specFile(c.mandate);
  return c.mandate_raw ?? JSON.stringify(c.mandate_inline);
}

function request(c: Case): Request {
  return { resource: c.resource, action: c.action, parameters: c.parameters, time: c.time, timezone: c.timezone, revoked: c.revoked };
}

function assertOutcome(c: Case, result: ReturnType<typeof evaluate>): void {
  assert.equal(result.decision, c.expected, c.why);
  assert.equal(result.reason, c.reason, c.why);
  if ("rule_id" in c) assert.equal(result.rule_id ?? null, c.rule_id);
  if (c.approval_timeout) assert.equal(result.approval?.timeout, c.approval_timeout);
  assert.equal(result.approval !== undefined, result.decision === "ask");
}

test("evaluation cases", () => {
  for (const c of cases("conformance/cases-v0.json")) {
    assertOutcome(c, evaluate(tryParseMandate(mandateText(c)), request(c)));
  }
});

test("invalid mandates are rejected", () => {
  for (const c of cases("conformance/invalid-v0.json")) {
    assert.equal(tryParseMandate(mandateText(c)), null, `${c.id}: ${c.why}`);
  }
});

test("digests", () => {
  for (const c of cases("conformance/digest-v0.json")) {
    assert.equal(tryParseMandate(mandateText(c))?.digest, c.digest, `${c.id}: ${c.why}`);
  }
});

test("selection of the mandate", () => {
  for (const c of cases("conformance/selection-v0.json")) {
    const stored = c.mandates.map((m: Case) => ({ mandate: JSON.stringify(m.mandate_inline), revoked: m.revoked }));
    const { selected, result } = selectAndEvaluate(stored, c.subject.client_id, c.subject.principal, request(c));
    assertOutcome(c, result);
    assert.equal(selected?.id ?? null, c.selected, `${c.id}: ${c.why}`);
  }
});

test("succession of versions", () => {
  for (const c of cases("conformance/succession-v0.json")) {
    const stored = tryParseMandate(JSON.stringify(c.stored));
    assert.ok(stored);
    assert.equal(isSuccessor(stored, tryParseMandate(JSON.stringify(c.offered))), c.expected === "accept", `${c.id}: ${c.why}`);
  }
});

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

test("harness answers every operation and rejects unknown ones", () => {
  const caps = answer({ op: "capabilities" }) as { ops: string[] };
  assert.equal(caps.ops.length, 7);
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
