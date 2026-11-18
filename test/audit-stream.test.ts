// SPDX-License-Identifier: Apache-2.0

// A long audit log verified as a stream, in bounded memory (issue #49): the same results as
// the text and the bytes, an over-long line held only as far as needed.
import assert from "node:assert/strict";
import { isUtf8 } from "node:buffer";
import { test } from "node:test";
import {
  entryDigest, parseJwks, verifyAuditLinesBytes, verifyAuditLinesWith, verifyAuditStream, type Anchor, type AuditResult, type Json,
} from "../src/index.ts";
import { specFile } from "../src/spec.ts";
import { cases } from "./cases.ts";

const V1 = "https://home-mandate.org/audit/v1";

function entry(seq: number, prev: string | null): string {
  return JSON.stringify({
    type: V1, id: `01a0f64c-7140-7001-9007-${String(seq).padStart(12, "0")}`, seq, prev, recorded_at: "2026-11-18T10:00:00Z",
    principal: "household:hm-7f3a", event: "emergency_stop.activated", actor: { kind: "user", id: "user-1" },
  });
}

/** A valid log of n entries, generated as it is read, in pieces of about a hundred lines. */
async function* generated(n: number): AsyncGenerator<Uint8Array> {
  let prev: string | null = null;
  let piece = "";
  for (let seq = 1; seq <= n; seq++) {
    const e = entry(seq, prev);
    prev = entryDigest(e);
    piece += e + "\n";
    if (seq % 100 === 0 || seq === n) {
      yield Buffer.from(piece, "utf8");
      piece = "";
    }
  }
}

/** The text of a case's log in the exchange format, and the anchor it gives. */
function logOf(c: Record<string, any>): { bytes: Buffer; anchor?: Anchor } | undefined {
  let bytes: Buffer;
  if (c.jsonl_base64 !== undefined) bytes = Buffer.from(c.jsonl_base64, "base64");
  else if (c.jsonl !== undefined) bytes = Buffer.from(c.jsonl, "utf8");
  else if (c.entries !== undefined) bytes = Buffer.from((c.entries as Json[]).map((e) => JSON.stringify(e) + "\n").join(""), "utf8");
  else return undefined;
  if (!c.keys) return { bytes };
  const anchor: Anchor = { keys: parseJwks(specFile(c.keys)), logId: c.log_id };
  if (c.last_seen) anchor.lastSeen = c.last_seen;
  return { bytes, anchor };
}

/** The bytes in pieces of every size from 1, so that a line feed or a character falls between two pieces. */
async function* pieces(bytes: Uint8Array, size: number): AsyncGenerator<Uint8Array> {
  for (let i = 0; i < bytes.length; i += size) yield bytes.subarray(i, i + size);
}

test("a stream gives the result of the bytes and of the text, for every log of the case files", async () => {
  let compared = 0;
  for (const file of ["conformance/audit-v0.json", "conformance/audit-v1.json"]) {
    for (const c of cases(file, "logs")) {
      const log = logOf(c);
      if (!log) continue;
      const options = log.anchor ? { anchor: log.anchor } : {};
      let expected: AuditResult;
      try {
        expected = verifyAuditLinesBytes(log.bytes, log.anchor);
      } catch {
        await assert.rejects(verifyAuditStream(pieces(log.bytes, 7), options), `${c.id}: the stream does not refuse it as well`);
        continue;
      }
      for (const size of [1, 3, 7, 4096]) {
        assert.deepEqual(await verifyAuditStream(pieces(log.bytes, size), options), expected, `${c.id}, pieces of ${size}`);
      }
      if (isUtf8(log.bytes)) assert.deepEqual(verifyAuditLinesWith(log.bytes.toString("utf8"), options), expected, `${c.id}: text`);
      compared++;
    }
  }
  assert.ok(compared >= 379, `only ${compared} logs compared`);
});

test("text pieces are read as their UTF-8 bytes", async () => {
  async function* text(): AsyncGenerator<string> {
    yield entry(1, null).slice(0, 10);
    yield entry(1, null).slice(10) + "\n";
  }
  assert.deepEqual(await verifyAuditStream(text()), { valid: true, entries: 1 });
});

test("a log of 100 000 entries is verified in bounded memory", async () => {
  globalThis.gc?.();
  const before = process.memoryUsage().heapUsed;
  let peak = before;
  async function* watched(): AsyncGenerator<Uint8Array> {
    for await (const piece of generated(100_000)) {
      peak = Math.max(peak, process.memoryUsage().heapUsed);
      yield piece;
    }
  }
  const result = await verifyAuditStream(watched());
  assert.equal(result.valid, true);
  assert.equal(result.entries, 100_000);
  // The whole log is about 30 MB of text and far more as strings and objects; the stream
  // holds a few lines at a time. The bound leaves room for the garbage collector's pace.
  assert.ok(peak - before < 64 * 1024 * 1024, `heap grew by ${Math.round((peak - before) / 1e6)} MB`);
});

test("an over-long line does not end the reading, and is held only as far as needed", async () => {
  const first = entry(1, null);
  let fed = 0;
  async function* endless(): AsyncGenerator<Uint8Array> {
    yield Buffer.from(first + "\n");
    const block = Buffer.alloc(1 << 20, 0x61);
    for (let i = 0; i < 64; i++) {
      fed += block.length;
      yield block; // one line of 64 MiB
    }
    yield Buffer.from("\n" + entry(3, null) + "\n");
  }
  const before = process.memoryUsage().heapUsed;
  const result = await verifyAuditStream(endless());
  assert.equal(fed, 64 << 20);
  assert.equal(result.valid, false);
  assert.equal(result.entries, 0);
  assert.equal(result.integrityBrokenAt, 0, "the over-long line has no readable seq");
  assert.ok(process.memoryUsage().heapUsed - before < 32 * 1024 * 1024, "the over-long line was kept");
});
