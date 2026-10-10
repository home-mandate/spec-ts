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

// Approval requests that end without an answer (SPEC-v0 sections 9.1 and 11.1 item 8).
function decision(approval: Record<string, Json>, result: Record<string, Json> | null): string {
  const parsed = JSON.parse(entry("decision", {})) as Record<string, Json>;
  delete parsed.actor;
  return JSON.stringify({
    ...parsed,
    agent: { client_id: AGENT.client_id },
    request: { time: "2026-10-01T09:00:00+02:00", resource: { entity_id: "lock.front_door", category: "lock" }, action: "unlock" },
    mandate: MANDATE,
    evaluation: { decision: "ask", reason: "rule", rule_id: "r-locks", approval_timeout: "PT2M" },
    approval: { at: "2026-10-01T09:00:30+02:00", ...approval },
    ...(result ? { result } : {}),
  });
}

const CAUSES = [
  ["withdrawn", "approval"],
  ["interrupted", "approval"],
  ["revoked", "authentication"],
  ["revoked", "mandate"],
  ["emergency_stop", "emergency_stop"],
] as const;

test("a cancelled request is a denial matching its cause", () => {
  for (const [cause, by] of CAUSES) {
    assert.equal(verifyAudit([decision({ outcome: "cancelled", cause }, { status: "denied", denied_by: by })]).valid, true, `${cause}/${by}`);
  }
  for (const by of ["approval", "authentication", "mandate", "emergency_stop"]) {
    for (const cause of ["withdrawn", "interrupted", "revoked", "emergency_stop"]) {
      if (CAUSES.some(([c, b]) => c === cause && b === by)) continue;
      assert.equal(verifyAudit([decision({ outcome: "cancelled", cause }, { status: "denied", denied_by: by })]).valid, false, `${cause}/${by}`);
    }
  }
});

test("a cancelled request has a cause, nobody who answered and no execution", () => {
  const denied = { status: "denied", denied_by: "approval" };
  assert.equal(verifyAudit([decision({ outcome: "cancelled" }, denied)]).valid, false, "no cause");
  assert.equal(verifyAudit([decision({ outcome: "cancelled", cause: "restarted" }, denied)]).valid, false, "unknown cause");
  assert.equal(verifyAudit([decision({ outcome: "cancelled", cause: "withdrawn", by: "user-1" }, denied)]).valid, false, "by");
  assert.equal(verifyAudit([decision({ outcome: "cancelled", cause: "withdrawn", via: "push" }, denied)]).valid, false, "via");
  assert.equal(verifyAudit([decision({ outcome: "cancelled", cause: "withdrawn" }, null)]).valid, false, "no result");
  assert.equal(verifyAudit([decision({ outcome: "cancelled", cause: "interrupted" }, { status: "failed", error: "outcome_unknown" })]).valid, false, "failed");
  assert.equal(verifyAudit([decision({ outcome: "timeout", cause: "interrupted" }, denied)]).valid, false, "cause without cancelled");
});

test("a confirmed action that was not executed is a failure with its code", () => {
  for (const error of ["outcome_unknown", "already_in_state", "state_changed"]) {
    assert.equal(verifyAudit([decision({ outcome: "approved", by: "user-1", via: "push" }, { status: "failed", error })]).valid, true, error);
  }
});
