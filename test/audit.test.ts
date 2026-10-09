// SPDX-License-Identifier: Apache-2.0

// The semantic checks of audit entries that JSON Schema cannot express (SPEC-v0
// sections 3.1 item 8 and 9.1), for the members template and approver.
import assert from "node:assert/strict";
import { test } from "node:test";
import { verifyAudit, type Json } from "../src/index.ts";

const DIGEST_A = "sha256:4e56112f4919687e886c67e4efc6d5f28913eef6454b9f48a60cd9a8bfb49a8d";
const DIGEST_B = "sha256:15f1c3f5496649fe6ee684324810fb1f22a70b2e85f6a8ea580b92ca756783e5";

function entry(event: string, member: Record<string, Json>): string {
  return JSON.stringify({
    type: "https://home-mandate.org/audit/v0",
    id: "01a0f64c-7140-7001-9007-0000e1580001",
    seq: 1,
    prev: null,
    recorded_at: "2026-10-01T09:00:00+02:00",
    principal: "household:hm-7f3a",
    event,
    actor: { kind: "user", id: "user-1" },
    ...member,
  });
}

function template(fields: Record<string, Json>): string {
  return entry("template.changed", { template: { change: "stored", name: "household-night", digest: DIGEST_A, ...fields } });
}

function approver(fields: Record<string, Json>): string {
  return entry("approver.changed", { approver: { change: "added", id: "user-2", ...fields } });
}

test("a stored template change with a different previous digest is valid", () => {
  assert.equal(verifyAudit([template({ previous_digest: DIGEST_B })]).valid, true);
});

test("a stored template change whose previous digest equals its digest is invalid", () => {
  assert.deepEqual(verifyAudit([template({ previous_digest: DIGEST_A })]), { valid: false, brokenAt: 1, entries: 0 });
});

test("a template name that is not displayable text is invalid", () => {
  for (const name of ["night​mode", "night‮mode", " night", "night "]) {
    assert.equal(verifyAudit([template({ name })]).valid, false, JSON.stringify(name));
  }
  assert.equal(verifyAudit([template({ name: "Nachtmodus Küche" })]).valid, true);
});

test("an approver id that is not displayable text is invalid", () => {
  for (const id of ["user‮-2", "user​2", "user-2 "]) {
    assert.equal(verifyAudit([approver({ id })]).valid, false, JSON.stringify(id));
  }
  assert.equal(verifyAudit([approver({})]).valid, true);
  assert.equal(verifyAudit([approver({ change: "removed" })]).valid, true);
});

// Removal and reconnection (SPEC-v0 sections 9.1 and 11.3): who may record them.
const AGENT = { client_id: "hm-client:voice-7c21e9a4", display_name: "Voice assistant" };
const MANDATE = { id: "m-voice-assistant", digest: DIGEST_A };

function byActor(event: string, kind: string, member: Record<string, Json>): string {
  const parsed = JSON.parse(entry(event, member)) as Record<string, Json>;
  return JSON.stringify({ ...parsed, actor: { kind, id: kind === "agent" ? AGENT.client_id : `${kind}-1` } });
}

test("a revoked mandate or agent is removed by a user or the system, never by an agent", () => {
  for (const [event, member] of [["mandate.removed", { mandate: MANDATE }], ["agent.removed", { agent: AGENT }]] as const) {
    assert.equal(verifyAudit([byActor(event, "user", member)]).valid, true, `${event} by user`);
    assert.equal(verifyAudit([byActor(event, "system", member)]).valid, true, `${event} by system`);
    assert.deepEqual(verifyAudit([byActor(event, "agent", member)]), { valid: false, brokenAt: 1, entries: 0 }, `${event} by agent`);
  }
});

test("only a user reconnects an agent", () => {
  assert.equal(verifyAudit([byActor("agent.reconnected", "user", { agent: AGENT })]).valid, true);
  for (const kind of ["system", "agent"]) {
    assert.deepEqual(verifyAudit([byActor("agent.reconnected", kind, { agent: AGENT })]), { valid: false, brokenAt: 1, entries: 0 }, kind);
  }
});

test("a removed mandate names the digest of its last version", () => {
  assert.equal(verifyAudit([entry("mandate.removed", { mandate: { id: MANDATE.id } })]).valid, false);
  assert.equal(verifyAudit([entry("mandate.removed", {})]).valid, false);
});

test("an agent display name in a reconnection is displayed text", () => {
  const name = "Voice‮assistant";
  assert.equal(verifyAudit([entry("agent.reconnected", { agent: { ...AGENT, display_name: name } })]).valid, false);
});
