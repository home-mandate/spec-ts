#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

// Harness for the process binding of the test interface (SPEC-v0 section 10.2): one
// JSON request per line on standard input, one JSON response per line on standard output.
import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import {
  entryDigest, verifyAudit, verifyAuditBytes, verifyAuditLines, verifyAuditLinesBytes, type Anchor, type AuditResult, type Position,
} from "./audit.ts";
import { evaluate, isSuccessor, needsConfirmation, selectAndEvaluate, type Request, type Result } from "./evaluate.ts";
import { isObject, type Json } from "./ijson.ts";
import { parseJwks, verifySigned } from "./jws.ts";
import { tryParseMandate, tryParseMandateBytes, type Mandate } from "./mandate.ts";
import { exactNumber } from "./number.ts";

// The version of this implementation, from package.json, so that it is stated once.
const VERSION = (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string }).version;

interface Message {
  op: string;
  id?: string;
  mandate?: string;
  mandate_base64?: string;
  mandates?: { mandate: string; revoked?: boolean }[];
  subject?: { client_id: string; principal: string };
  request?: Request;
  stored?: string;
  stored_revoked?: boolean;
  offered?: string;
  jws?: string;
  issuer?: string;
  keys?: string;
  jsonl?: string;
  entries?: string[];
  jsonl_base64?: string;
  entries_base64?: string[];
  log_id?: string;
  last_seen?: Json;
  entry?: string;
}

// Members of a request (SPEC-v0 section 10.2). A request with another member is malformed,
// so that a former member name (such as "area") is never evaluated as if it were absent.
const MEMBERS: Readonly<Record<string, readonly string[]>> = {
  message: [
    "op", "id", "mandate", "mandate_base64", "mandates", "subject", "request", "stored", "stored_revoked", "offered", "jws", "issuer",
    "keys", "jsonl", "entries", "jsonl_base64", "entries_base64", "log_id", "last_seen", "entry",
  ],
  stored: ["mandate", "revoked"],
  subject: ["client_id", "principal"],
  request: ["resource", "action", "parameters", "time", "timezone", "revoked"],
  resource: ["entity_id", "category", "areas", "critical"],
  last_seen: ["seq", "digest"],
};

// The members each operation defines besides op and id (SPEC-v0 section 10.2): a member of
// another operation is as malformed as an unknown one.
const OP_MEMBERS: Readonly<Record<string, readonly string[]>> = {
  capabilities: [],
  validate: ["mandate", "mandate_base64"],
  evaluate: ["mandate", "mandate_base64", "request"],
  select: ["mandates", "subject", "request"],
  succession: ["stored", "offered", "stored_revoked"],
  verify_signed: ["jws", "issuer", "keys"],
  verify_audit: ["entries", "jsonl", "entries_base64", "jsonl_base64", "keys", "log_id", "last_seen"],
  entry_digest: ["entry"],
};

function unknownMember(value: unknown, kind: string): string | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  return Object.keys(value).find((key) => !MEMBERS[kind]!.includes(key));
}

/** The first member of the message that the test interface does not define, if any. */
export function undefinedMember(m: Message): string | undefined {
  const ofOp = OP_MEMBERS[m.op];
  const foreign = ofOp && Object.keys(m).find((k) => k !== "op" && k !== "id" && !ofOp.includes(k));
  return (foreign || undefined) ?? unknownMember(m, "message") ??
    unknownMember(m.subject, "subject") ??
    unknownMember(m.request, "request") ??
    unknownMember(m.request?.resource, "resource") ??
    unknownMember(m.last_seen, "last_seen") ??
    (Array.isArray(m.mandates) ? m.mandates.map((s) => unknownMember(s, "stored")).find((k) => k !== undefined) : undefined);
}

/**
 * Reads one request line. Numbers are read by their exact value, so that a parameter
 * such as 50.00000000000000000001 is no integer (SPEC-v0 section 4.5).
 */
export function readMessage(line: string): Message {
  const exact = (_key: string, value: unknown, context?: { source?: string }): unknown =>
    typeof value === "number" && context?.source !== undefined ? exactNumber(context.source) : value;
  return JSON.parse(line, exact as never) as Message;
}

const OPS = ["validate", "evaluate", "select", "succession", "verify_signed", "verify_audit", "entry_digest"];

const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * The bytes of a base64 member (SPEC-v0 section 10.2): canonical base64 with padding, no
 * white space, padding bits zero, at least one byte; anything else is malformed.
 */
function base64Bytes(value: unknown, name: string): Buffer {
  if (typeof value !== "string" || value === "" || !BASE64.test(value)) throw new Error(`${name} is not base64`);
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) throw new Error(`${name} is not canonical base64`);
  return bytes;
}

/** The mandate of a request, from its text or its bytes; exactly one form is given. */
function requestMandate(m: Message): Mandate | null {
  if (m.mandate !== undefined && m.mandate_base64 !== undefined) throw new Error("both mandate and mandate_base64");
  if (m.mandate_base64 !== undefined) return tryParseMandateBytes(base64Bytes(m.mandate_base64, "mandate_base64"));
  if (typeof m.mandate !== "string") throw new Error("missing mandate");
  return tryParseMandate(m.mandate);
}

function keysText(keys: unknown): string {
  if (typeof keys !== "string") throw new Error("keys is not JSON text in a string");
  return keys;
}

function outcome(r: Result): object {
  const out: Record<string, unknown> = { decision: r.decision, reason: r.reason };
  if (r.rule_id !== undefined) out.rule_id = r.rule_id;
  if (r.approval) Object.assign(out, { approval_timeout: r.approval.timeout, approvers: r.approval.approvers });
  if (r.mandate_digest !== undefined) out.mandate_digest = r.mandate_digest;
  if (r.enforced === false) out.enforced = false;
  if (r.confirm === true) out.confirm = true;
  if (r.limited_rules !== undefined && r.limited_rules.length > 0) out.limited_rules = r.limited_rules;
  return out;
}

/** The position of last_seen (SPEC-v0 section 10.2): seq and digest; verifyAudit checks their values. */
function position(value: Json): Position {
  if (!isObject(value) || typeof value.seq !== "number" || typeof value.digest !== "string") throw new Error("last_seen is not a position");
  return { seq: value.seq, digest: value.digest };
}

/** The response to verify_audit (SPEC-v0 section 10.2): the verdict and the findings of section 9.4. */
function auditResponse(r: AuditResult): object {
  const out: Record<string, unknown> = { valid: r.valid, entries: r.entries };
  if (!r.valid) out.broken_at = r.brokenAt;
  else if (r.anchored !== undefined) out.anchored = r.anchored;
  if (r.integrityBrokenAt !== undefined) out.integrity_broken_at = r.integrityBrokenAt;
  if (r.conformanceBrokenAt !== undefined) out.conformance_broken_at = r.conformanceBrokenAt;
  if (r.unknownVersionAt !== undefined) out.unknown_version_at = r.unknownVersionAt;
  if (r.valid && r.checkpointGapAt !== undefined) out.checkpoint_gap_at = r.checkpointGapAt;
  return out;
}

export function answer(m: Message): object {
  const member = undefinedMember(m);
  if (member !== undefined) return { error: `undefined member ${member}` };
  switch (m.op) {
    case "capabilities":
      return { name: "home-mandate-spec-ts", version: VERSION, ops: OPS };
    case "validate": {
      const mandate = requestMandate(m);
      return mandate ? { valid: true, digest: mandate.digest } : { valid: false };
    }
    case "evaluate": {
      if (!m.request) return { error: "missing request" };
      return outcome(evaluate(requestMandate(m), m.request));
    }
    case "select": {
      if (!m.subject || !m.request) return { error: "missing subject and request" };
      const { selected, result } = selectAndEvaluate(m.mandates ?? [], m.subject.client_id, m.subject.principal, m.request);
      return selected ? { ...outcome(result), selected: selected.id } : outcome(result);
    }
    case "succession": {
      const stored = tryParseMandate(m.stored ?? "");
      if (!stored) return { error: "stored mandate is invalid" };
      const offered = tryParseMandate(m.offered ?? "");
      if (!isSuccessor(stored, offered)) return { accept: false };
      // Accepted is not in effect (SPEC-v0 section 3.5): a weakening, a revoked predecessor
      // or audit mode switched on need a human's confirmation first.
      return needsConfirmation(stored, m.stored_revoked === true, offered) ? { accept: true, confirm: true } : { accept: true };
    }
    case "verify_signed":
      try {
        return { valid: true, digest: verifySigned(m.jws ?? "", m.issuer ?? "", parseJwks(keysText(m.keys))).digest };
      } catch {
        return { valid: false };
      }
    case "verify_audit": {
      let anchor: Anchor | undefined;
      if (m.keys !== undefined) {
        anchor = { keys: parseJwks(keysText(m.keys)), logId: m.log_id || undefined };
        if (m.last_seen !== undefined) anchor.lastSeen = position(m.last_seen);
      } else if (m.last_seen !== undefined) {
        return { error: "last_seen without keys" };
      }
      const forms = [m.jsonl, m.entries, m.jsonl_base64, m.entries_base64].filter((f) => f !== undefined).length;
      if (forms > 1) return { error: "more than one of jsonl, entries, jsonl_base64 and entries_base64" };
      let r;
      if (m.jsonl_base64 !== undefined) r = verifyAuditLinesBytes(base64Bytes(m.jsonl_base64, "jsonl_base64"), anchor);
      else if (m.entries_base64 !== undefined) {
        if (!Array.isArray(m.entries_base64)) return { error: "entries_base64 is not an array" };
        r = verifyAuditBytes(m.entries_base64.map((e) => base64Bytes(e, "entries_base64")), anchor);
      } else r = m.jsonl !== undefined ? verifyAuditLines(m.jsonl, anchor) : verifyAudit(m.entries ?? [], anchor);
      return auditResponse(r);
    }
    case "entry_digest":
      if (typeof m.entry !== "string") return { error: "missing entry" };
      try {
        return { digest: entryDigest(m.entry) };
      } catch {
        return { error: "entry without a digest" };
      }
  }
  return { error: "unsupported" };
}

/** The response line to one request line, without the line feed; never throws. */
export function respond(line: string): string {
  let response: object;
  try {
    response = answer(readMessage(line));
  } catch (e) {
    response = { error: e instanceof Error ? e.message : "malformed request" };
  }
  return JSON.stringify(response);
}

if ((import.meta as { main?: boolean }).main) {
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of lines) {
    if (line === "") continue;
    process.stdout.write(respond(line) + "\n");
  }
}
