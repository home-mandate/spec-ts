// SPDX-License-Identifier: Apache-2.0

// Audit version 1 and the findings of SPEC-v0 sections 9.4 and 9.5 beyond the conformance
// files: the forms of config.changed values, the informative time going backwards, the start
// of a log for a relying party, and last_seen on the test interface.
import assert from "node:assert/strict";
import { test } from "node:test";
import { answer } from "../src/harness.ts";
import { entryDigest, parseJwks, verifyAudit, verifyAuditWith } from "../src/index.ts";
import { canonicalProxy } from "../src/ip-address.ts";
import { validPublicOrigin } from "../src/origin.ts";
import { specFile } from "../src/spec.ts";
import { cases } from "./cases.ts";

test("a public origin has one form (origin-v0.json, SPEC-v0 section 11.7 item 1)", () => {
  const origins = cases("conformance/origin-v0.json").filter((c) => c.value !== undefined);
  assert.ok(origins.length > 0);
  for (const c of origins) assert.equal(validPublicOrigin(c.value), c.expected === "valid", `${c.id}: ${c.why}`);
});

test("a trusted proxy is named in its canonical text form", () => {
  const canonical = [
    "192.0.2.1", "0.0.0.0/0", "10.0.0.0/8", "::", "::1", "1::", "::/0", "2001:db8::1", "2001:db8:0:1:1:1:1:1",
    "2001:0:0:1::1", "2001:db8::1:0:0:1", "::ffff:192.0.2.1", "::ffff:0.0.0.0/96", "fe80::/10",
  ];
  for (const value of canonical) assert.equal(canonicalProxy(value), true, value);
  const other = [
    "", "192.0.2", "192.0.2.256", "192.0.2.01", "10.0.0.0/08", "10.0.0.0/33", "10.0.0.1/8", "192.0.2.1/32", "2001:db8::1/128",
    "2001:DB8::1", "2001:db8:0:0:0:0:0:1", "2001:db8::0:1", "2001:db8:0::1", "2001::1:0:0:0:1", "::1.2.3.4", "::ffff:c000:201",
    "::ffff:0:0/96", "fe80::1%eth0", "1:2:3:4:5:6:7:8:9", "1:::2", "::1::", "0:0:0:0:0:0:0:0",
  ];
  for (const value of other) assert.equal(canonicalProxy(value), false, value);
});

const V1 = "https://home-mandate.org/audit/v1";

function emergencyStop(seq: number, prev: string | null, recordedAt: string): string {
  return JSON.stringify({
    type: V1, id: `01a0f64c-7140-7001-9007-0000e15800${String(seq).padStart(2, "0")}`, seq, prev,
    recorded_at: recordedAt, principal: "household:hm-7f3a", event: "emergency_stop.activated", actor: { kind: "user", id: "user-1" },
  });
}

function chain(times: string[]): string[] {
  const out: string[] = [];
  times.forEach((at, i) => out.push(emergencyStop(i + 1, i === 0 ? null : entryDigest(out[i - 1]!), at)));
  return out;
}

test("an entry recorded before the one before it is reported, informatively", () => {
  const log = chain(["2026-10-01T09:00:00Z", "2026-10-01T10:00:00+02:00", "2026-10-01T09:00:00.000000001Z"]);
  assert.equal(verifyAudit(log.slice(0, 1)).valid, true, "the first entry");
  const r = verifyAudit(log);
  assert.deepEqual(r, { valid: true, entries: 3, timeBackwards: 2 });
});

test("a log is valid exactly if there is no finding", () => {
  const log = chain(["2026-10-01T09:00:00Z", "2026-10-01T09:01:00Z", "2026-10-01T09:02:00Z"]);
  assert.deepEqual(verifyAudit(log), { valid: true, entries: 3 });
  const gap = [log[0]!, log[2]!];
  assert.deepEqual(verifyAudit(gap), { valid: false, brokenAt: 3, entries: 0, integrityBrokenAt: 3 });
  const late = verifyAudit([log[1]!, log[2]!]);
  assert.deepEqual(late, { valid: false, brokenAt: 2, entries: 0, integrityBrokenAt: 2 }, "a log that starts at seq 2");
});

test("a verifier with keys reports the first seq of a log", () => {
  const keys = specFile("conformance/keys/test-keys.json");
  const log = chain(["2026-10-01T09:00:00Z"]);
  const r = verifyAuditWith(log, { anchor: { keys: parseJwks(keys) } });
  assert.deepEqual(r, { valid: true, entries: 1, anchored: 0, firstSeq: 1 });
});

test("verify_audit takes last_seen only with keys and with a position an entry can have", () => {
  const keys = specFile("conformance/keys/test-keys.json");
  const entries = chain(["2026-10-01T09:00:00Z"]);
  const digest = entryDigest(entries[0]!);
  assert.deepEqual(answer({ op: "verify_audit", entries, last_seen: { seq: 1, digest } }), { error: "last_seen without keys" });
  for (const lastSeen of [{ seq: 0, digest }, { seq: 1.5, digest }, { seq: 1, digest: "sha256:00" }, { seq: 1, digest: digest.toUpperCase() }]) {
    assert.throws(() => answer({ op: "verify_audit", entries, keys, last_seen: lastSeen }), JSON.stringify(lastSeen));
  }
  assert.deepEqual(answer({ op: "verify_audit", entries, keys, last_seen: { seq: 1, digest, at: 1 } as never }), { error: "undefined member at" });
  assert.deepEqual(answer({ op: "verify_audit", entries, keys, last_seen: { seq: 1, digest } }), { valid: true, entries: 1, anchored: 0 });
  // The position is not anchored by any checkpoint, but the entry is there with that digest.
  const other = "sha256:" + "5b".repeat(32);
  assert.deepEqual(
    answer({ op: "verify_audit", entries, keys, last_seen: { seq: 1, digest: other } }),
    { valid: false, entries: 0, broken_at: 1, integrity_broken_at: 1 },
  );
  assert.deepEqual(
    answer({ op: "verify_audit", entries: [], keys, last_seen: { seq: 1, digest } }),
    { valid: false, entries: 0, broken_at: 0, integrity_broken_at: 0 },
    "every entry is gone",
  );
});
