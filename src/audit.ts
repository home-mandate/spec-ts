// SPDX-License-Identifier: Apache-2.0

// Verification of audit logs (SPEC-v0 sections 9.4 and 9.5).
import { displayable } from "./displaytext.ts";
import { isObject, type Json, parseJson } from "./ijson.ts";
import { canonicalize, digest } from "./jcs.ts";
import { type Keys, verifyDetached } from "./jws.ts";
import { validateAudit } from "./generated/audit-validator.ts";
import type { SchemaValidator } from "./schema-runtime.ts";
import { vocabulary } from "./spec-data.ts";

const auditSchema: SchemaValidator = validateAudit;

const MAX_ENTRY_BYTES = 64 * 1024;

export interface Anchor {
  keys: Keys;
  logId?: string;
}

/** Options of a verification (verifyAuditWith). */
export interface AuditOptions {
  /** Verifies the signatures of checkpoints (SPEC-v0 section 9.5). */
  anchor?: Anchor;
  /**
   * Extension vocabularies (SPEC-v0 section 5.1) as JSON text in the format of
   * vocabulary/v0.json. With them, a deny that was not enforced for an extension category is
   * checked as for the categories of v0; without the vocabulary of an extension, the
   * verifier cannot tell which of its actions are critical.
   */
  vocabularies?: readonly string[];
}

/** Actions by category, true for a critical one; no prototype, so no inherited names. */
type KnownActions = ReadonlyMap<string, ReadonlyMap<string, boolean>>;

const V0_ACTIONS: KnownActions = new Map(
  Object.entries(vocabulary).map(([name, c]) => [name, new Map(Object.entries(c.actions).map(([a, info]) => [a, info.critical === true]))]),
);

/** Reads the categories of an extension vocabulary; throws if it is no such file. */
function readVocabulary(text: string, index: number): KnownActions {
  const fail = (why: string): never => {
    throw new Error(`audit: vocabulary ${index + 1}: ${why}`);
  };
  let value: Json;
  try {
    value = parseJson(text);
  } catch (err) {
    return fail(err instanceof Error ? err.message : "no JSON");
  }
  if (!isObject(value) || !isObject(value.categories)) return fail("no categories");
  const out = new Map<string, ReadonlyMap<string, boolean>>();
  for (const [name, category] of Object.entries(value.categories)) {
    if (!isObject(category) || !isObject(category.actions)) return fail(`category ${name} has no actions`);
    const actions = new Map<string, boolean>();
    for (const [action, info] of Object.entries(category.actions)) {
      if (!isObject(info) || (info.critical !== undefined && typeof info.critical !== "boolean")) return fail(`action ${name}.${action}`);
      actions.set(action, info.critical === true);
    }
    out.set(name, actions);
  }
  return out;
}

/** Vocabulary v0 together with the extensions; an extension cannot redefine a category of v0. */
function knownActions(extensions: readonly string[] | undefined): KnownActions {
  if (!extensions || extensions.length === 0) return V0_ACTIONS;
  const known = new Map(V0_ACTIONS);
  extensions.forEach((text, i) => {
    for (const [name, actions] of readVocabulary(text, i)) {
      if (V0_ACTIONS.has(name)) throw new Error(`audit: vocabulary ${i + 1} redefines category ${name} of v0`);
      known.set(name, actions);
    }
  });
  return known;
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

/**
 * Whether an entry with evaluation.enforced names an action that may be left unenforced
 * (SPEC-v0 sections 9.1 and 9.4): in the vocabulary of its category and not critical
 * there. The schema cannot see the vocabulary. A category the verifier knows no
 * vocabulary for passes: its critical actions are unknown; the schema already requires the
 * category and rejects a resource marked critical.
 */
function enforcedConsistent(entry: { [key: string]: Json }, known: KnownActions): boolean {
  if (member(entry, "evaluation")?.enforced === undefined) return true;
  const request = member(entry, "request");
  const category = isObject(request?.resource) ? request.resource.category : undefined;
  const actions = typeof category === "string" ? known.get(category) : undefined;
  if (!actions) return true;
  const critical = typeof request?.action === "string" ? actions.get(request.action) : undefined;
  return critical === false;
}

function check(text: string, known: KnownActions): { link?: Link; seq: number } {
  let value: Json;
  try {
    if (Buffer.byteLength(text, "utf8") > MAX_ENTRY_BYTES || !text.isWellFormed()) return { seq: 0 };
    value = parseJson(text);
  } catch {
    return { seq: 0 };
  }
  const seq = isObject(value) ? readableSeq(value.seq) : 0;
  if (!isObject(value) || !auditSchema(value)) return { seq };
  if (!displayedTextValid(value) || !formerValuesDistinct(value) || !enforcedConsistent(value, known)) return { seq };
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
  return verifyAuditWith(entries, anchor ? { anchor } : {});
}

/**
 * verifyAudit with options: an anchor and extension vocabularies. Throws if a vocabulary is
 * unreadable or redefines a category of v0.
 */
export function verifyAuditWith(entries: readonly string[], options: AuditOptions): AuditResult {
  const known = knownActions(options.vocabularies);
  const anchor = options.anchor;
  const links: Link[] = [];
  for (const text of entries) {
    const { link, seq } = check(text, known);
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
  return verifyAuditLinesWith(jsonl, anchor ? { anchor } : {});
}

/** verifyAuditLines with options (verifyAuditWith). */
export function verifyAuditLinesWith(jsonl: string, options: AuditOptions): AuditResult {
  const lines = jsonl.split("\n");
  if (lines[lines.length - 1] === "") lines.pop(); // the final line feed is optional
  return verifyAuditWith(lines, options);
}
