// SPDX-License-Identifier: Apache-2.0

// Verification of audit logs (SPEC-v0 sections 9.4 and 9.5).
import { displayable } from "./displaytext.ts";
import { isObject, type Json, parseJson } from "./ijson.ts";
import { canonicalize, digest } from "./jcs.ts";
import { type Keys, verifyDetached } from "./jws.ts";
import { validateAudit } from "./generated/audit-validator.ts";
import type { SchemaValidator } from "./schema-runtime.ts";

const auditSchema: SchemaValidator = validateAudit;

const MAX_ENTRY_BYTES = 64 * 1024;

export interface Anchor {
  keys: Keys;
  logId?: string;
}

export interface AuditResult {
  valid: boolean;
  /** seq of the first violating entry; 0 if it has no readable seq. */
  brokenAt?: number;
  entries: number;
  /** seq up to which a verified checkpoint covers the log; only with an anchor. */
  anchored?: number;
}

interface Link {
  seq: number;
  prev: string | null;
  digest: string;
  event: string;
  truncated?: { up_to_seq: number; last_digest: string };
  checkpoint?: { log_id: string; signature: string };
}

function readableSeq(value: Json | undefined): number {
  return typeof value === "number" && Number.isInteger(value) && Math.abs(value) <= 2 ** 53 ? value : 0;
}

/** Digest of one entry; throws if the entry is not I-JSON or cannot be canonicalized. */
export function entryDigest(text: string): string {
  if (Buffer.byteLength(text, "utf8") > MAX_ENTRY_BYTES) throw new Error("entry too large");
  return digest(parseJson(text));
}

/** Members that user interfaces show to humans: member, field (SPEC-v0 section 3.1 item 8). */
const DISPLAYED_FIELDS = [
  ["actor", "id"], ["agent", "display_name"], ["approval", "by"], ["template", "name"], ["approver", "id"],
] as const;

/** Members of a change that name the former value next to the current one: member, current, former (SPEC-v0 section 9.1). */
const FORMER_VALUES = [
  ["directory", "entity_id", "previous_entity_id"],
  ["template", "digest", "previous_digest"],
] as const;

function member(entry: { [key: string]: Json }, name: string): { [key: string]: Json } | undefined {
  const value = entry[name];
  return isObject(value) ? value : undefined;
}

/** Whether every displayed member follows the rule for displayed text. */
function displayedTextValid(entry: { [key: string]: Json }): boolean {
  return DISPLAYED_FIELDS.every(([name, field]) => {
    const text = member(entry, name)?.[field];
    return typeof text !== "string" || displayable(text);
  });
}

/** Whether every change that names a former value names one other than the current one; JSON Schema cannot compare two members. */
function formerValuesDistinct(entry: { [key: string]: Json }): boolean {
  return FORMER_VALUES.every(([name, current, former]) => {
    const change = member(entry, name);
    return change?.[former] === undefined || change[former] !== change[current];
  });
}

function check(text: string): { link?: Link; seq: number } {
  let value: Json;
  try {
    if (Buffer.byteLength(text, "utf8") > MAX_ENTRY_BYTES || !text.isWellFormed()) return { seq: 0 };
    value = parseJson(text);
  } catch {
    return { seq: 0 };
  }
  const seq = isObject(value) ? readableSeq(value.seq) : 0;
  if (!isObject(value) || !auditSchema(value)) return { seq };
  if (!displayedTextValid(value) || !formerValuesDistinct(value)) return { seq };
  let entryDigest: string;
  try {
    entryDigest = digest(value);
  } catch {
    return { seq };
  }
  return {
    seq,
    link: {
      seq, prev: value.prev as string | null, digest: entryDigest, event: value.event as string,
      truncated: value.truncated as Link["truncated"], checkpoint: value.checkpoint as Link["checkpoint"],
    },
  };
}

/** Verifies entries in file order: schema of all entries, start, chain, checkpoints. */
export function verifyAudit(entries: string[], anchor?: Anchor): AuditResult {
  const links: Link[] = [];
  for (const text of entries) {
    const { link, seq } = check(text);
    if (!link) return { valid: false, brokenAt: seq, entries: 0 };
    links.push(link);
  }
  if (links.length === 0) return anchor ? { valid: true, entries: 0, anchored: 0 } : { valid: true, entries: 0 };
  const first = links[0]!;
  const covered = links.slice(1).some(
    (l) => l.event === "log.truncated" && l.truncated!.up_to_seq === first.seq - 1 && l.truncated!.last_digest === first.prev,
  );
  if (first.seq !== 1 && !covered) return { valid: false, brokenAt: first.seq, entries: 0 };
  for (let i = 1; i < links.length; i++) {
    const [previous, l] = [links[i - 1]!, links[i]!];
    if (l.seq !== previous.seq + 1 || l.prev !== previous.digest) return { valid: false, brokenAt: l.seq, entries: 0 };
  }
  let logId = anchor?.logId ?? "";
  let anchored = 0;
  for (const l of links) {
    if (l.event !== "log.checkpoint") continue;
    const cp = l.checkpoint!;
    if (logId === "") logId = cp.log_id;
    let ok = cp.log_id === logId;
    if (ok && anchor) {
      const payload = canonicalize({ type: "https://home-mandate.org/audit-checkpoint/v0", log_id: cp.log_id, seq: l.seq - 1, digest: l.prev });
      try {
        verifyDetached(cp.signature, payload, anchor.keys);
        anchored = l.seq - 1;
      } catch {
        ok = false;
      }
    }
    if (!ok) return { valid: false, brokenAt: l.seq, entries: 0 };
  }
  return anchor ? { valid: true, entries: links.length, anchored } : { valid: true, entries: links.length };
}

/** Verifies a log in the exchange format: lines are separated by line feed only. */
export function verifyAuditLines(jsonl: string, anchor?: Anchor): AuditResult {
  const lines = jsonl.split("\n");
  if (lines[lines.length - 1] === "") lines.pop(); // the final line feed is optional
  return verifyAudit(lines, anchor);
}
