// SPDX-License-Identifier: Apache-2.0

// Verification of audit logs (SPEC-v0 sections 9.4 and 9.5).
import { displayable } from "./displaytext.ts";
import { isObject, type Json, parseJson } from "./ijson.ts";
import { canonicalize, digest } from "./jcs.ts";
import { type Keys, verifyDetached } from "./jws.ts";
import { validateAudit } from "./generated/audit-validator.ts";
import type { SchemaValidator } from "./schema-runtime.ts";
import { vocabulary, vocabularyId } from "./spec-data.ts";

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
   * vocabulary/v0.json, each with its id. With them, a deny that was not enforced for an
   * extension category is checked as for the categories of v0, and the vocabulary a
   * decision names for such a category must be theirs; without the vocabulary of an
   * extension, the verifier cannot tell which of its actions are critical.
   */
  vocabularies?: readonly string[];
}

/** What the verifier knows about one category: the id of the vocabulary that defines it, and whether each action is critical. */
interface CategoryVocabulary {
  id: string;
  actions: ReadonlyMap<string, boolean>;
}

/** Categories by name; no prototype, so no inherited names. */
type KnownActions = ReadonlyMap<string, CategoryVocabulary>;

const V0_ACTIONS: KnownActions = new Map(
  Object.entries(vocabulary).map(([name, c]) => [
    name, { id: vocabularyId, actions: new Map(Object.entries(c.actions).map(([a, info]) => [a, info.critical === true])) },
  ]),
);

/** Reads the id and the categories of an extension vocabulary; throws if it is no such file. */
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
  if (typeof value.id !== "string" || value.id === "") return fail("no id");
  const out = new Map<string, CategoryVocabulary>();
  for (const [name, category] of Object.entries(value.categories)) {
    if (!isObject(category) || !isObject(category.actions)) return fail(`category ${name} has no actions`);
    const actions = new Map<string, boolean>();
    for (const [action, info] of Object.entries(category.actions)) {
      if (!isObject(info) || (info.critical !== undefined && typeof info.critical !== "boolean")) return fail(`action ${name}.${action}`);
      actions.set(action, info.critical === true);
    }
    out.set(name, { id: value.id, actions });
  }
  return out;
}

/** Vocabulary v0 together with the extensions; an extension cannot redefine a category of v0. */
function knownActions(extensions: readonly string[] | undefined): KnownActions {
  if (!extensions || extensions.length === 0) return V0_ACTIONS;
  const known = new Map(V0_ACTIONS);
  extensions.forEach((text, i) => {
    for (const [name, category] of readVocabulary(text, i)) {
      if (V0_ACTIONS.has(name)) throw new Error(`audit: vocabulary ${i + 1} redefines category ${name} of v0`);
      known.set(name, category);
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
  /** recorded_at as written: the signature of a checkpoint covers it (SPEC-v0 section 9.5). */
  recordedAt: string;
  truncated?: { up_to_seq: number; last_digest: string };
  checkpoint?: { log_id: string; signature: string };
}

type Entry = { [key: string]: Json };

/** An integer member by its value; 0 if it is missing, is no integer or lies outside the exact range (RFC 7493). */
function readableSeq(value: Json | undefined): number {
  return typeof value === "number" && Number.isInteger(value) && Math.abs(value) < 2 ** 53 ? value : 0;
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
  ["directory", "category", "previous_category"],
  ["mandate", "digest", "previous_digest"],
  ["template", "digest", "previous_digest"],
  ["config", "value", "previous_value"],
] as const;

function member(entry: Entry, name: string): Entry | undefined {
  const value = entry[name];
  return isObject(value) ? value : undefined;
}

/** Whether every displayed member follows the rule for displayed text. */
function displayedTextValid(entry: Entry): boolean {
  return DISPLAYED_FIELDS.every(([name, field]) => {
    const text = member(entry, name)?.[field];
    return typeof text !== "string" || displayable(text);
  });
}

/** Whether every change that names a former value names one other than the current one; JSON Schema cannot compare two members. */
function formerValuesDistinct(entry: Entry): boolean {
  return FORMER_VALUES.every(([name, current, former]) => {
    const change = member(entry, name);
    return typeof change?.[former] !== "string" || change[former] !== change[current];
  });
}

/** Whether an areas_changed entry names two different sets of areas (SPEC-v0 sections 3.4 and 9.1): the order does not count. */
function areasDistinct(entry: Entry): boolean {
  const directory = member(entry, "directory");
  const current = directory?.areas;
  const former = directory?.previous_areas;
  if (!Array.isArray(current) || !Array.isArray(former)) return true;
  return current.length !== former.length || !current.every((area) => former.includes(area));
}

/** Whether a log.truncated entry accounts only for entries before itself: up_to_seq is smaller than its own seq (SPEC-v0 section 9.4). */
function truncatesEarlier(entry: Entry): boolean {
  const truncated = member(entry, "truncated");
  return truncated === undefined || readableSeq(truncated.up_to_seq) < readableSeq(entry.seq);
}

/** Whether a log.exported entry names a range of entries before itself: from_seq ≤ to_seq < seq (SPEC-v0 section 9.1). */
function exportsEarlier(entry: Entry): boolean {
  const exported = member(entry, "exported");
  if (exported === undefined) return true;
  const [from, to] = [readableSeq(exported.from_seq), readableSeq(exported.to_seq)];
  return from <= to && to < readableSeq(entry.seq);
}

function categoryOf(entry: Entry): string | undefined {
  const request = member(entry, "request");
  const category = isObject(request?.resource) ? request.resource.category : undefined;
  return typeof category === "string" ? category : undefined;
}

/**
 * Whether an entry with evaluation.enforced names an action that may be left unenforced
 * (SPEC-v0 sections 9.1 and 9.4): in the vocabulary of its category and not critical
 * there. The schema cannot see the vocabulary. A category the verifier knows no
 * vocabulary for passes: its critical actions are unknown; the schema already requires the
 * category and rejects a resource marked critical.
 */
function enforcedConsistent(entry: Entry, known: KnownActions): boolean {
  if (member(entry, "evaluation")?.enforced === undefined) return true;
  const category = categoryOf(entry);
  const actions = category === undefined ? undefined : known.get(category)?.actions;
  if (!actions) return true;
  const action = member(entry, "request")?.action;
  return typeof action === "string" && actions.get(action) === false;
}

/**
 * Whether the vocabulary a decision entry names fits the category of its resource (SPEC-v0
 * section 9.1): the id of v0 for a category of v0, the id of the extension for a category
 * of an extension the verifier knows, and any id but that of v0 for another extension
 * category. The schema cannot see the vocabulary.
 */
function vocabularyConsistent(entry: Entry, known: KnownActions): boolean {
  const named = member(entry, "vocabulary");
  if (named === undefined) return true;
  const category = categoryOf(entry);
  if (category === undefined || category === "") return true;
  const defined = known.get(category);
  return defined ? named.id === defined.id : named.id !== vocabularyId;
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
  if (!displayedTextValid(value) || !formerValuesDistinct(value) || !areasDistinct(value) || !truncatesEarlier(value) ||
    !exportsEarlier(value) || !enforcedConsistent(value, known) || !vocabularyConsistent(value, known)) {
    return { seq };
  }
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
      recordedAt: typeof value.recorded_at === "string" ? value.recorded_at : "",
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
      // The signed statement: the log, the entry the checkpoint covers, and when it was made (SPEC-v0 section 9.5).
      const payload = canonicalize({ type: "https://home-mandate.org/audit-checkpoint/v0", log_id: cp.log_id, seq: l.seq - 1, digest: l.prev, at: l.recordedAt });
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

/**
 * verifyAuditLines with options (verifyAuditWith). A carriage return before the line feed
 * is white space around the value and not part of the entry's size (SPEC-v0 section 9.4).
 */
export function verifyAuditLinesWith(jsonl: string, options: AuditOptions): AuditResult {
  const lines = jsonl.split("\n");
  if (lines[lines.length - 1] === "") lines.pop(); // the final line feed is optional
  return verifyAuditWith(lines.map((line) => (line.endsWith("\r") ? line.slice(0, -1) : line)), options);
}
