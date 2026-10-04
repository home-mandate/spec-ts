#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

// Harness for the process binding of the test interface (SPEC-v0 section 10.2): one
// JSON request per line on standard input, one JSON response per line on standard output.
import { createInterface } from "node:readline";
import { entryDigest, verifyAudit, verifyAuditLines, type Anchor } from "./audit.ts";
import { evaluate, isSuccessor, selectAndEvaluate, type Request, type Result } from "./evaluate.ts";
import { type Json } from "./ijson.ts";
import { parseJwks, verifySigned } from "./jws.ts";
import { tryParseMandate } from "./mandate.ts";

interface Message {
  op: string;
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

const OPS = ["validate", "evaluate", "select", "succession", "verify_signed", "verify_audit", "entry_digest"];

function outcome(r: Result): object {
  const out: Record<string, unknown> = { decision: r.decision, reason: r.reason };
  if (r.rule_id !== undefined) out.rule_id = r.rule_id;
  if (r.approval) Object.assign(out, { approval_timeout: r.approval.timeout, approvers: r.approval.approvers });
  if (r.mandate_digest !== undefined) out.mandate_digest = r.mandate_digest;
  return out;
}

export function answer(m: Message): object {
  switch (m.op) {
    case "capabilities":
      return { name: "mandate-spec-ts", version: "0.2.0-alpha.1", ops: OPS };
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

if ((import.meta as { main?: boolean }).main) {
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of lines) {
    if (line === "") continue;
    let response: object;
    try {
      response = answer(JSON.parse(line) as Message);
    } catch (e) {
      response = { error: e instanceof Error ? e.message : "malformed request" };
    }
    process.stdout.write(JSON.stringify(response) + "\n");
  }
}
