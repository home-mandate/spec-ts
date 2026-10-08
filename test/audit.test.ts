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
