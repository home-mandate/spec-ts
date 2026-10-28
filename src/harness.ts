#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

// Harness for the process binding of the test interface (SPEC-v0 section 10.2): one
// JSON request per line on standard input, one JSON response per line on standard output.
import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { entryDigest, verifyAudit, verifyAuditLines, type Anchor } from "./audit.ts";
import { evaluate, isSuccessor, selectAndEvaluate, type Request, type Result } from "./evaluate.ts";
import { type Json } from "./ijson.ts";
import { parseJwks, verifySigned } from "./jws.ts";
import { tryParseMandate } from "./mandate.ts";
import { exactNumber } from "./number.ts";

// The version of this implementation, from package.json, so that it is stated once.
const VERSION = (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string }).version;

interface Message {
  op: string;
  id?: string;
  mandate?: string;
  mandates?: { mandate: string; revoked?: boolean }[];
  subject?: { client_id: string; principal: string };
  request?: Request;
  stored?: string;
  offered?: string;
  jws?: string;
  issuer?: string;
  keys?: Json;
  jsonl?: string;
  entries?: string[];
  log_id?: string;
  entry?: string;
}

// Members of a request (SPEC-v0 section 10.2). A request with another member is malformed,
// so that a former member name (such as "area") is never evaluated as if it were absent.
// keys is a JWK Set and not checked here.
const MEMBERS: Readonly<Record<string, readonly string[]>> = {
  message: ["op", "id", "mandate", "mandates", "subject", "request", "stored", "offered", "jws", "issuer", "keys", "jsonl", "entries", "log_id", "entry"],
  stored: ["mandate", "revoked"],
  subject: ["client_id", "principal"],
  request: ["resource", "action", "parameters", "time", "timezone", "revoked"],
  resource: ["entity_id", "category", "areas", "critical"],
};

function unknownMember(value: unknown, kind: string): string | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  return Object.keys(value).find((key) => !MEMBERS[kind]!.includes(key));
}

/** The first member of the message that the test interface does not define, if any. */
export function undefinedMember(m: Message): string | undefined {
  return unknownMember(m, "message") ??
    unknownMember(m.subject, "subject") ??
    unknownMember(m.request, "request") ??
    unknownMember(m.request?.resource, "resource") ??
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

function outcome(r: Result): object {
  const out: Record<string, unknown> = { decision: r.decision, reason: r.reason };
  if (r.rule_id !== undefined) out.rule_id = r.rule_id;
  if (r.approval) Object.assign(out, { approval_timeout: r.approval.timeout, approvers: r.approval.approvers });
  if (r.mandate_digest !== undefined) out.mandate_digest = r.mandate_digest;
  if (r.enforced === false) out.enforced = false;
  return out;
}

export function answer(m: Message): object {
  const member = undefinedMember(m);
  if (member !== undefined) return { error: `undefined member ${member}` };
  switch (m.op) {
    case "capabilities":
      return { name: "home-mandate-spec-ts", version: VERSION, ops: OPS };
    case "validate": {
      const mandate = tryParseMandate(m.mandate ?? "");
      return mandate ? { valid: true, digest: mandate.digest } : { valid: false };
    }
    case "evaluate":
      if (m.mandate === undefined || !m.request) return { error: "missing mandate and request" };
      return outcome(evaluate(tryParseMandate(m.mandate), m.request));
    case "select": {
      if (!m.subject || !m.request) return { error: "missing subject and request" };
      const { selected, result } = selectAndEvaluate(m.mandates ?? [], m.subject.client_id, m.subject.principal, m.request);
      return selected ? { ...outcome(result), selected: selected.id } : outcome(result);
    }
    case "succession": {
      const stored = tryParseMandate(m.stored ?? "");
      if (!stored) return { error: "stored mandate is invalid" };
      return { accept: isSuccessor(stored, tryParseMandate(m.offered ?? "")) };
    }
    case "verify_signed":
      try {
        return { valid: true, digest: verifySigned(m.jws ?? "", m.issuer ?? "", parseJwks(m.keys ?? null)).digest };
      } catch {
        return { valid: false };
      }
    case "verify_audit": {
      let anchor: Anchor | undefined;
      if (m.keys !== undefined) anchor = { keys: parseJwks(m.keys), logId: m.log_id || undefined };
      const r = m.jsonl !== undefined ? verifyAuditLines(m.jsonl, anchor) : verifyAudit(m.entries ?? [], anchor);
      const out: Record<string, unknown> = { valid: r.valid, entries: r.entries };
      if (!r.valid) out.broken_at = r.brokenAt;
      else if (r.anchored !== undefined) out.anchored = r.anchored;
      return out;
    }
    case "entry_digest":
      try {
        return { valid: true, digest: entryDigest(m.entry ?? "") };
      } catch {
        return { valid: false };
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
