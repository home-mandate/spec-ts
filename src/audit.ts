// SPDX-License-Identifier: Apache-2.0

// Verification of audit logs (SPEC-v0 sections 9.4 and 9.5) of the audit versions 0 and 1
// (section 14): the verdict, the findings and the cadence of checkpoints.
import {
  type Anchor, Cadence, checkPosition, EVENT_CHECKPOINT, EVENT_TRUNCATED, type Position, signatureVerifies,
} from "./audit-checkpoint.ts";
import { type Entry, keepsRules, type KnownActions, knownActions, member, readableSeq, text } from "./audit-rules.ts";
import { validateAudit } from "./generated/audit-validator.ts";
import { validateAuditV1 } from "./generated/audit-v1-validator.ts";
import { isObject, type Json, parseAuditEntry, parseRecorded } from "./ijson.ts";
import { digest } from "./jcs.ts";
import type { SchemaValidator } from "./schema-runtime.ts";
import { parseTimestamp } from "./time.ts";

export type { Anchor, Position } from "./audit-checkpoint.ts";

/** The schemas of the audit versions this verifier knows, by version (SPEC-v0 section 14). */
const SCHEMAS: readonly SchemaValidator[] = [validateAudit, validateAuditV1];
/** The first version to which no correction applies (SPEC-v0 section 14, Correction). */
const FIRST_STRICT_VERSION = 1;
/** The type of an entry names a version exactly if it is this prefix and the number (SPEC-v0 section 14). */
const TYPE_PREFIX = "https://home-mandate.org/audit/v";
const VERSION_NUMBER = /^(0|[1-9][0-9]{0,8})$/;

const MAX_ENTRY_BYTES = 64 * 1024;

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

/**
 * The outcome of a verification (SPEC-v0 sections 9.4 and 9.5). Each finding is the seq of the
 * first entry of its kind in file order (0 if it has no readable seq), absent if there is none;
 * a log is valid exactly if it has no finding.
 */
export interface AuditResult {
  valid: boolean;
  /** seq of the first violating entry; 0 if it has no readable seq. */
  brokenAt?: number;
  /** The number of entries of a valid log; 0 for an invalid one. */
  entries: number;
  /** seq up to which a verified checkpoint covers a valid log; only with an anchor. */
  anchored?: number;
  /** The log is not complete and unaltered from this entry on (conditions 2, 3 and 4, an entry outside the chain). */
  integrityBrokenAt?: number;
  /** An entry of a known version that breaks condition 1: a fault of the software that wrote it, not damage. */
  conformanceBrokenAt?: number;
  /** An entry of an audit version this verifier does not know; the content from there on is not checked, the chain is. */
  unknownVersionAt?: number;
  /** For a valid log with a checkpoint: the first entry at which the writer did not keep the cadence (section 9.5); no finding. */
  checkpointGapAt?: number;
  /** For a valid log, informative: the first entry recorded before the entry before it; no finding. */
  timeBackwards?: number;
  /** For a valid log with entries and an anchor: the seq of its first entry, greater than 1 if the beginning was deleted. */
  firstSeq?: number;
  /** For a valid log with an anchor whose beginning was deleted: whether the log.truncated entry for it is anchored. */
  truncationAnchored?: boolean;
}

/** The first entry of a kind: its position in file order and its seq. */
interface Finding {
  index: number;
  at: number;
}

/** What the chain, the start, the checkpoints and the cadence need from an entry. */
interface Link {
  index: number;
  seq: number;
  /** "" for null. */
  prev: string;
  digest: string;
  event: string;
  upToSeq: number;
  lastDigest: string;
  logId: string;
  signature: string;
  /** recorded_at as written: the signature of a checkpoint covers it. */
  recordedAt: string;
  at: bigint | null;
  /** The audit version its type names; -1 if none. */
  version: number;
}

function emptyLink(index: number, seq: number): Link {
  return {
    index, seq, prev: "", digest: "", event: "", upToSeq: 0, lastDigest: "", logId: "", signature: "", recordedAt: "", at: null, version: -1,
  };
}

/** The version an entry names in its type; -1 if it names none. */
function versionOf(entry: Entry): number {
  const type = text(entry, "type");
  if (!type.startsWith(TYPE_PREFIX)) return -1;
  const digits = type.slice(TYPE_PREFIX.length);
  return VERSION_NUMBER.test(digits) ? Number(digits) : -1;
}

/** Digest of one entry; throws if the entry is not I-JSON or cannot be canonicalized. */
export function entryDigest(text: string): string {
  if (Buffer.byteLength(text, "utf8") > MAX_ENTRY_BYTES) throw new Error("entry too large");
  return digest(parseRecorded(text));
}

/**
 * Checks a log entry by entry in file order and keeps only what the rest of the log can still
 * depend on. Every entry is read: each finding needs the whole log.
 */
class Verifier {
  private count = 0;
  /** The previous entry takes no part in the chain; the integrity finding names it already. */
  private lost = false;
  /** The newest known version so far; an older one after it breaks condition 1. */
  private newest = 0;
  private integrity: Finding | undefined;
  private conformance: Finding | undefined;
  private unknown: Finding | undefined;
  private backwards: Finding | undefined;
  private first = emptyLink(0, 0);
  private previous = emptyLink(0, 0);
  /** A log.truncated entry accounts for everything before the first entry, at coveredAt. */
  private startCovered = false;
  private coveredAt = 0;
  /** The first violation of condition 3; reported only if nothing comes before it. */
  private chainBreak: Finding | undefined;
  /** The first violation of condition 4; it comes last. */
  private checkpointBreak: Finding | undefined;
  private logId = "";
  private anchoredSeq = 0;
  private readonly cadence = new Cadence();
  /** An entry or a log.truncated entry stands for Anchor.lastSeen. */
  private lastFound = false;
  /** The log.truncated entry that stands for Anchor.lastSeen; it counts only if anchored. */
  private lastTruncation: Finding | undefined;

  private readonly known: KnownActions;
  private readonly anchor: Anchor | undefined;

  constructor(known: KnownActions, anchor: Anchor | undefined) {
    checkPosition(anchor?.lastSeen);
    [this.known, this.anchor] = [known, anchor];
  }

  add(entryText: string): void {
    const index = this.count++;
    const l = this.check(index, entryText);
    if (l.digest === "" || l.seq < 1) {
      this.integrity ??= { index, at: l.seq };
      this.lost = true;
      return;
    }
    if (index === 0) {
      this.first = l;
    } else if (l.event === EVENT_TRUNCATED && l.upToSeq === this.first.seq - 1 && l.lastDigest === this.first.prev && !this.startCovered) {
      [this.startCovered, this.coveredAt] = [true, l.seq];
    }
    if (index > 0 && !this.lost && (l.seq !== this.previous.seq + 1 || l.prev !== this.previous.digest)) {
      this.integrity ??= { index, at: l.seq };
      this.chainBreak ??= { index, at: l.seq };
    }
    // A checkpoint is checked whatever its version and whether or not it keeps the rules: it
    // anchors the log, and an entry made unreadable on purpose must not escape it.
    if (l.event === EVENT_CHECKPOINT && this.checkpointViolates(l)) {
      this.integrity ??= { index, at: l.seq };
      this.checkpointBreak ??= { index, at: l.seq };
    }
    if (this.anchor?.lastSeen && this.contradictsLastSeen(this.anchor.lastSeen, l)) this.breakCheckpoint(index, l.seq);
    this.cadence.next(l);
    if (index > 0 && l.at !== null && this.previous.at !== null && l.at < this.previous.at) this.backwards ??= { index, at: l.seq };
    [this.previous, this.lost] = [l, false];
  }

  /**
   * Reads one entry. It takes no part in the chain (no digest) if it cannot be read or
   * canonicalized. It is checked against the schema of its version and the rules of section 9.1
   * if this verifier knows the version: a violation is a conformance finding, an unknown
   * version a finding of its own. What the chain, the start and the checkpoints need is read
   * from every entry: the integrity of a log does not depend on whether its writer kept the rules.
   */
  private check(index: number, entryText: string): Link {
    let value: Json;
    let corrected: boolean;
    try {
      if (Buffer.byteLength(entryText, "utf8") > MAX_ENTRY_BYTES || !entryText.isWellFormed()) throw new Error("unreadable");
      ({ value, corrected } = parseAuditEntry(entryText));
    } catch {
      this.conformance ??= { index, at: 0 };
      return emptyLink(index, 0);
    }
    const entry = isObject(value) ? value : undefined;
    const l = emptyLink(index, readableSeq(entry?.seq));
    let entryDigest = "";
    try {
      if (entry) entryDigest = digest(entry);
    } catch {
      // An entry without a digest breaks condition 1 and takes no part in the chain.
    }
    if (entry === undefined || entryDigest === "") {
      this.conformance ??= { index, at: l.seq };
      return l;
    }
    l.digest = entryDigest;
    l.prev = text(entry, "prev");
    l.version = versionOf(entry);
    if (l.version < 0 || l.version < this.newest) {
      // No audit version, or an older version after a newer one, known or not.
      this.conformance ??= { index, at: l.seq };
    } else if (l.version >= SCHEMAS.length) {
      this.unknown ??= { index, at: l.seq };
    } else if (!SCHEMAS[l.version]!(entry) || !keepsRules(entry, this.known) || (l.version >= FIRST_STRICT_VERSION && corrected)) {
      this.conformance ??= { index, at: l.seq };
    }
    this.newest = Math.max(this.newest, l.version);
    l.event = text(entry, "event");
    l.at = parseTimestamp(text(entry, "recorded_at"))?.ns ?? null;
    const checkpoint = member(entry, "checkpoint");
    if (checkpoint) [l.logId, l.signature, l.recordedAt] = [text(checkpoint, "log_id"), text(checkpoint, "signature"), text(entry, "recorded_at")];
    const truncated = member(entry, "truncated");
    if (truncated) [l.upToSeq, l.lastDigest] = [readableSeq(truncated.up_to_seq), text(truncated, "last_digest")];
    return l;
  }

  /**
   * Whether a checkpoint violates condition 4. One without a log_id or a signature cannot be
   * checked, with keys or without, and breaks it like one whose signature does not verify.
   */
  private checkpointViolates(l: Link): boolean {
    if (l.logId === "" || l.signature === "") return true;
    if (this.logId === "") {
      if (this.anchor?.logId && l.logId !== this.anchor.logId) return true;
      this.logId = l.logId;
    } else if (l.logId !== this.logId) {
      return true;
    }
    if (!this.anchor) return false;
    if (!signatureVerifies(l.logId, l.seq, l.prev, l.recordedAt, l.signature, this.anchor.keys)) return true;
    this.anchoredSeq = l.seq - 1;
    return false;
  }

  /**
   * Whether an entry contradicts the position the relying party saw last: the entry at that
   * seq has another digest, or a log.truncated entry for it binds another digest. A
   * log.truncated entry that accounts for it counts only if a verified checkpoint anchors it,
   * which finish checks: anyone who can write the log can write one.
   */
  private contradictsLastSeen(last: Position, l: Link): boolean {
    if (l.seq === last.seq) {
      [this.lastFound, this.lastTruncation] = [true, undefined];
      return l.digest !== last.digest;
    }
    if (l.event === EVENT_TRUNCATED && l.upToSeq >= last.seq && !this.lastFound) {
      if (l.upToSeq === last.seq && l.lastDigest !== last.digest) return true;
      [this.lastFound, this.lastTruncation] = [true, { index: l.index, at: l.seq }];
    }
    return false;
  }

  /** Records a violation of condition 4, keeping the first in file order. */
  private breakCheckpoint(index: number, at: number): void {
    if (!this.integrity || index < this.integrity.index) this.integrity = { index, at };
    if (!this.checkpointBreak || index < this.checkpointBreak.index) this.checkpointBreak = { index, at };
  }

  finish(): AuditResult {
    if (this.anchor?.lastSeen && !this.lastFound) {
      // The log ends before the position the relying party saw: it was cut or rolled back.
      if (this.count === 0) return { valid: false, brokenAt: 0, entries: 0, integrityBrokenAt: 0 };
      this.breakCheckpoint(this.count - 1, this.previous.seq);
    }
    if (this.lastTruncation && this.lastTruncation.at > this.anchoredSeq) this.breakCheckpoint(this.lastTruncation.index, this.lastTruncation.at);
    const lostFirst = this.integrity?.index === 0;
    if (this.count > 0 && this.first.seq !== 1 && !this.startCovered && !lostFirst) {
      // Condition 2 is about the first entry: it comes before every other break of integrity.
      this.integrity = { index: 0, at: this.first.seq };
    }
    const findings = {
      ...(this.integrity && { integrityBrokenAt: this.integrity.at }),
      ...(this.conformance && { conformanceBrokenAt: this.conformance.at }),
      ...(this.unknown && { unknownVersionAt: this.unknown.at }),
    };
    const broken = (f: Finding): AuditResult => ({ valid: false, brokenAt: f.at, entries: 0, ...findings });
    // Condition 1 first: an entry of an unknown version matches the schema of no version this verifier knows.
    const condition1 = [this.conformance, this.unknown].filter((f) => f !== undefined).sort((a, b) => a.index - b.index)[0];
    if (condition1) return broken(condition1);
    if (this.count > 0 && this.first.seq !== 1 && !this.startCovered) return broken({ index: 0, at: this.first.seq });
    if (this.chainBreak) return broken(this.chainBreak);
    if (this.checkpointBreak) return broken(this.checkpointBreak);
    // Fail closed: a log is valid exactly if there is no finding.
    if (this.integrity) return broken(this.integrity);
    if (this.count === 0) return this.anchor ? { valid: true, entries: 0, anchored: 0 } : { valid: true, entries: 0 };
    const result: AuditResult = { valid: true, entries: this.count };
    if (this.anchor) {
      result.anchored = this.anchoredSeq;
      result.firstSeq = this.first.seq;
      if (this.first.seq !== 1) result.truncationAnchored = this.coveredAt <= this.anchoredSeq;
    }
    if (this.cadence.gap) result.checkpointGapAt = this.cadence.gap.at;
    if (this.backwards) result.timeBackwards = this.backwards.at;
    return result;
  }
}

/** Verifies entries in file order: schema of all entries, start, chain, checkpoints. */
export function verifyAudit(entries: readonly string[], anchor?: Anchor): AuditResult {
  return verifyAuditWith(entries, anchor ? { anchor } : {});
}

/**
 * verifyAudit with options: an anchor and extension vocabularies. Throws if a vocabulary is
 * unreadable or redefines a category of v0, or if the anchor names a position no entry can have.
 */
export function verifyAuditWith(entries: readonly string[], options: AuditOptions): AuditResult {
  const verifier = new Verifier(knownActions(options.vocabularies), options.anchor);
  for (const entry of entries) verifier.add(entry);
  return verifier.finish();
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

const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * The text of an entry given as bytes. Bytes that are not UTF-8 become a text that is not
 * well formed, which no entry is (SPEC-v0 sections 3.1 item 1 and 9.4); a byte order mark is
 * kept and makes the entry unreadable.
 */
function entryText(bytes: Uint8Array): string {
  try {
    return UTF8.decode(bytes);
  } catch {
    return "\uD800";
  }
}

/** verifyAudit for entries given as the bytes they were stored as. */
export function verifyAuditBytes(entries: readonly Uint8Array[], anchor?: Anchor): AuditResult {
  return verifyAuditWith(entries.map(entryText), anchor ? { anchor } : {});
}

/**
 * verifyAuditLines for the exchange format given as bytes: the lines are split at the byte of
 * the line feed first, so that bytes that are not UTF-8 make only their own line unreadable.
 */
export function verifyAuditLinesBytes(jsonl: Uint8Array, anchor?: Anchor): AuditResult {
  const lines: string[] = [];
  let start = 0;
  for (let i = 0; i <= jsonl.length; i++) {
    if (i === jsonl.length || jsonl[i] === 0x0a) {
      lines.push(entryText(jsonl.subarray(start, i)));
      start = i + 1;
    }
  }
  return verifyAuditLinesWith(lines.join("\n"), anchor ? { anchor } : {});
}
