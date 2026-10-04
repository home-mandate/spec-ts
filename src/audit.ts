// SPDX-License-Identifier: Apache-2.0

// Verification of audit logs (SPEC-v0 sections 9.4 and 9.5).
import { displayable } from "./displaytext.ts";
import { isObject, type Json, parseJson } from "./ijson.ts";
import { canonicalize, digest } from "./jcs.ts";
import { type Keys, verifyDetached } from "./jws.ts";
import { auditSchema } from "./spec.ts";

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
  const displayed = [
    isObject(value.actor) ? value.actor.id : undefined,
    isObject(value.agent) ? value.agent.display_name : undefined,
    isObject(value.approval) ? value.approval.by : undefined,
  ];
  if (displayed.some((text) => typeof text === "string" && !displayable(text))) return { seq };
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
      const payload = canonicalize({ type: "https://mandate-spec.org/audit-checkpoint/v0", log_id: cp.log_id, seq: l.seq - 1, digest: l.prev });
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
