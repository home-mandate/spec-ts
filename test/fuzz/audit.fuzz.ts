// SPDX-License-Identifier: Apache-2.0

// Mirrors FuzzVerify of the Go audit package: verification of arbitrary entries never
// throws, a single entry is valid only as the first entry of a log (seq 1, prev null,
// SPEC-v0 section 9.4), and a log in the exchange format is valid only with all its lines.
import assert from "node:assert/strict";
import fc from "fast-check";
import { entryDigest, verifyAudit, verifyAuditLines } from "../../src/audit.ts";
import { cases } from "../cases.ts";
import { anyText, editedText, fuzz, jsonInput } from "./fuzz.ts";

const logs = cases("conformance/audit-v0.json", "logs");
const entries: string[] = logs.flatMap((c) => (c.entries ?? []).map((e: unknown) => JSON.stringify(e)));
const jsonl: string[] = [
  ...logs.filter((c) => c.jsonl !== undefined).map((c) => c.jsonl as string),
  ...logs.filter((c) => c.entries !== undefined).map((c) => c.entries.map((e: unknown) => JSON.stringify(e)).join("\n") + "\n"),
];
if (entries.length === 0 || jsonl.length === 0) throw new Error("no audit seeds in conformance/audit-v0.json");

const seeds = ['{"type":"https://home-mandate.org/audit/v0","seq":1,"prev":null}', "{}", "[1,2]", ...entries];

const input = fc.record({
  entry: jsonInput(seeds),
  log: fc.oneof(editedText(jsonl), fc.array(jsonInput(seeds), { maxLength: 4 }).map((lines) => lines.join("\n")), anyText(64)),
});

fuzz("audit", input, ({ entry, log }) => {
  const single = verifyAudit([entry]);
  if (single.valid) {
    assert.equal(single.brokenAt, undefined);
    assert.equal(single.entries, 1);
    const value = JSON.parse(entry) as { seq?: unknown; prev?: unknown };
    assert.ok(value.seq === 1 && value.prev === null, `valid single entry that is no first entry: ${entry}`);
  } else {
    assert.ok(Number.isInteger(single.brokenAt), `invalid without broken_at: ${JSON.stringify(single)}`);
    assert.equal(single.entries, 0);
  }
  try {
    assert.match(entryDigest(entry), /^sha256:[0-9a-f]{64}$/);
  } catch (e) {
    if (e instanceof assert.AssertionError) throw e; // a digest that is none; any other error rejects the entry
  }
  const lines = log.split("\n");
  if (lines.at(-1) === "") lines.pop();
  const r = verifyAuditLines(log);
  if (r.valid) assert.equal(r.entries, lines.length, `valid log with ${r.entries} of ${lines.length} lines`);
  else assert.ok(Number.isInteger(r.brokenAt) && r.entries === 0, `invalid log: ${JSON.stringify(r)}`);
}, seeds.slice(0, 3).map((entry, i) => ({ entry, log: jsonl[i]! })));
