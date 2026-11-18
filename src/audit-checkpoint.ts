// SPDX-License-Identifier: Apache-2.0

// Checkpoints of an audit log (SPEC-v0 section 9.5): the signed statement, the anchor a
// verifier knows from outside the log, and the cadence a writer keeps.
import { canonicalize } from "./jcs.ts";
import { type Keys, verifyDetached } from "./jws.ts";

export const EVENT_CHECKPOINT = "log.checkpoint";
export const EVENT_TRUNCATED = "log.truncated";

/** The type of the signed statement of a checkpoint, in a log of every audit version. */
const CHECKPOINT_TYPE = "https://home-mandate.org/audit-checkpoint/v0";

const DIGEST = /^sha256:[0-9a-f]{64}$/;

/** An entry of a log, by its seq and its digest. */
export interface Position {
  seq: number;
  digest: string;
}

/** What a verifier knows from outside the log (SPEC-v0 section 9.5). */
export interface Anchor {
  /** The public keys that may sign checkpoints of the log, by key ID. */
  keys: Keys;
  /** The expected identifier of the log; absent or empty accepts the one of the first checkpoint. */
  logId?: string;
  /**
   * The entry the relying party saw covered by the last checkpoint it verified (the
   * checkpoint's seq − 1 and its prev). The log must still hold an entry with that seq and
   * digest, or an anchored log.truncated entry that accounts for it (condition 4). A seq below
   * 1 or a digest that is not "sha256:" and 64 hexadecimal digits in lower case makes the
   * verification throw.
   */
  lastSeen?: Position;
}

/** Throws if the position of an anchor is not one an entry can have. */
export function checkPosition(position: Position | undefined): void {
  if (position === undefined) return;
  const { seq, digest } = position;
  if (!Number.isSafeInteger(seq) || seq < 1 || typeof digest !== "string" || !DIGEST.test(digest)) {
    throw new Error(`audit: the last entry seen needs a seq of at least 1 and a digest, got ${String(seq)} and ${JSON.stringify(digest)}`);
  }
}

/**
 * Whether the signature of a checkpoint verifies: the statement is the log, the entry the
 * checkpoint covers, and when it was made (its recorded_at as written).
 */
export function signatureVerifies(logId: string, seq: number, prev: string, recordedAt: string, signature: string, keys: Keys): boolean {
  try {
    const payload = canonicalize({ type: CHECKPOINT_TYPE, log_id: logId, seq: seq - 1, digest: prev, at: recordedAt });
    verifyDetached(signature, payload, keys);
    return true;
  } catch {
    return false;
  }
}

/** The first audit version whose writer had to keep the cadence. */
const FIRST_CADENCE_VERSION = 1;
const MAX_ENTRIES_BETWEEN_CHECKPOINTS = 1000;
const MAX_NS_BETWEEN_CHECKPOINTS = 24n * 60n * 60n * 1_000_000_000n;

/** What the cadence needs from an entry. */
export interface CadenceEntry {
  index: number;
  seq: number;
  event: string;
  /** recorded_at in nanoseconds since the epoch; null if it cannot be read. */
  at: bigint | null;
  /** The audit version its type names; -1 if none. */
  version: number;
}

/**
 * Follows the checkpoints of a log for checkpoint_gap_at (SPEC-v0 section 9.5, "The signer",
 * item 3), entry by entry in file order, as the table of section 9.5 states it.
 */
export class Cadence {
  /** The first entry at which the writer did not keep the cadence. */
  gap: { index: number; at: number } | undefined;
  private seen = false;
  /** recorded_at of the last checkpoint. */
  private at: bigint | null = null;
  /** Entries after it that are no checkpoint. */
  private since = 0;
  /** The first of them was recorded more than 24 hours after the checkpoint ("late start"). */
  private firstLate = false;

  private late(t: bigint | null): boolean {
    return this.at !== null && t !== null && t - this.at > MAX_NS_BETWEEN_CHECKPOINTS;
  }

  next(e: CadenceEntry): void {
    const checkpoint = e.event === EVENT_CHECKPOINT;
    if (this.seen) {
      let gap = false;
      if (checkpoint) gap = this.since > 0 && !this.firstLate && this.late(e.at);
      else if (this.since === 0) this.firstLate = this.late(e.at);
      else gap = this.firstLate || this.late(e.at) || this.since >= MAX_ENTRIES_BETWEEN_CHECKPOINTS;
      // Only an entry of version 1 or later is reported: the cadence became a MUST with it.
      if (gap && e.version >= FIRST_CADENCE_VERSION) this.gap ??= { index: e.index, at: e.seq };
    }
    if (checkpoint) {
      [this.seen, this.at, this.since, this.firstLate] = [true, e.at, 0, false];
    } else if (this.seen) {
      this.since++;
    }
  }
}
