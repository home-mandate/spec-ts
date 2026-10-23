// SPDX-License-Identifier: Apache-2.0

// A deny that was not enforced (audit mode, SPEC-v0 section 4.6) is checked against the
// vocabulary of its category (section 9.1): vocabulary v0 always, an extension only when
// the verifier is given its vocabulary (section 5.1). The same cases as the Go verifier.
import assert from "node:assert/strict";
import { test } from "node:test";
import { verifyAudit, verifyAuditLines, verifyAuditLinesWith, verifyAuditWith } from "../src/index.ts";

/** A decision entry with seq 1 whose deny was not enforced, for the category and action. */
function unenforced(category: string, action: string): string {
  return JSON.stringify({
    agent: { client_id: "urn:example:agent:a" },
    evaluation: { decision: "deny", reason: "no_match", rule_id: null, enforced: false },
    event: "decision",
    id: "01a0f64c-7140-7001-9007-0000e9990001",
    mandate: { id: "m-test", digest: "sha256:" + "0".repeat(64) },
    prev: null,
    principal: "household:t",
    recorded_at: "2026-10-12T19:00:00+02:00",
    request: { time: "2026-10-12T19:00:00+02:00", resource: { entity_id: "x", category, critical: false }, action },
    result: { status: "executed" },
    seq: 1,
    type: "https://home-mandate.org/audit/v0",
  });
}

/** An extension vocabulary in the format of vocabulary/v0.json. */
const PAPERLESS = JSON.stringify({
  id: "https://example.org/vocabulary/paperless",
  version: "1",
  categories: { "paperless:document": { actions: { read: {}, tag: {}, delete: { critical: true } } } },
});

test("a deny that was not enforced is checked against vocabulary v0; an extension passes", () => {
  for (const [category, action, valid] of [
    ["switch", "turn_on", true],
    ["camera", "read", true],
    ["paperless:document", "delete", true],
    ["lock", "unlock", false],
    ["camera", "snapshot", false],
    ["other", "set", false],
    ["light", "unlock", false],
  ] as const) {
    assert.equal(verifyAudit([unenforced(category, action)]).valid, valid, `${category}.${action}`);
  }
});

test("given the vocabulary of an extension, its actions are checked as those of v0", () => {
  const options = { vocabularies: [PAPERLESS] };
  for (const [category, action, valid] of [
    ["paperless:document", "tag", true],
    ["paperless:document", "delete", false],
    ["paperless:document", "shred", false],
    ["switch", "turn_on", true],
    ["lock", "unlock", false],
    ["other:thing", "anything", true],
  ] as const) {
    const entry = unenforced(category, action);
    assert.equal(verifyAuditWith([entry], options).valid, valid, `${category}.${action}`);
    assert.equal(verifyAuditLinesWith(entry + "\n", options).valid, valid, `${category}.${action} (lines)`);
  }
});

test("the options work as the plain functions without vocabularies, and carry the anchor", () => {
  const entry = unenforced("paperless:document", "delete");
  assert.deepEqual(verifyAuditWith([entry], {}), verifyAudit([entry]));
  assert.deepEqual(verifyAuditLinesWith(entry, {}), verifyAuditLines(entry));
  assert.deepEqual(verifyAuditWith([], { anchor: { keys: new Map() } }), { valid: true, entries: 0, anchored: 0 });
});

test("an unreadable vocabulary or one that redefines a category of v0 is refused", () => {
  for (const vocabulary of [
    "not json",
    "[]",
    JSON.stringify({ categories: [] }),
    JSON.stringify({ categories: { "x:y": { actions: [] } } }),
    JSON.stringify({ categories: { "x:y": { actions: { a: { critical: "yes" } } } } }),
    JSON.stringify({ categories: { lock: { actions: { unlock: {} } } } }),
    JSON.stringify({ categories: { "x:y": { actions: {} } } }) + JSON.stringify({}),
  ]) {
    assert.throws(() => verifyAuditWith([], { vocabularies: [vocabulary] }), Error, vocabulary);
  }
});

test("a category named like a member of Object.prototype is no category", () => {
  const options = { vocabularies: [PAPERLESS] };
  assert.equal(verifyAuditWith([unenforced("constructor", "read")], options).valid, true);
  assert.equal(verifyAuditWith([unenforced("paperless:document", "toString")], options).valid, false);
});
