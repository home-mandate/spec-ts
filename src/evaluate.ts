// SPDX-License-Identifier: Apache-2.0

// The evaluation rule (SPEC-v0 section 4) and the selection of the mandate (4.3).
import type { Approval, Decision, Mandate, Rule } from "./mandate.ts";
import { tryParseMandate } from "./mandate.ts";
import { parseJson, isObject } from "./ijson.ts";
import { vocabulary } from "./spec.ts";
import { type Instant, type LocalTime, localTime, parseTimestamp } from "./time.ts";

export interface Resource {
  entity_id: string;
  category?: string;
  area?: string;
  critical?: boolean;
}

/** The input of the evaluation as the PEP determined it. */
export interface Request {
  resource: Resource;
  action: string;
  parameters?: Record<string, number>;
  time: string;
  timezone?: string;
  revoked?: boolean;
}

export interface Result {
  decision: Decision;
  reason: string;
  rule_id?: string;
  approval?: Approval;
  mandate_digest?: string;
}

function opaque(s: string | undefined, limit: number): boolean {
  return typeof s === "string" && s.length >= 1 && s.length <= limit && /^[!-~]+$/.test(s);
}

function integer(n: number): boolean {
  return Number.isInteger(n) && Math.abs(n) <= Number.MAX_SAFE_INTEGER;
}

const STRICTNESS: Record<Decision, number> = { allow: 0, ask: 1, deny: 2 };

function matches(rule: Rule, req: Request, local: LocalTime): boolean {
  const s = rule.resource;
  const resource = s.any === true ||
    ((s.entity_id === undefined || s.entity_id === req.resource.entity_id) &&
      (s.category === undefined || s.category === req.resource.category) &&
      (s.area === undefined || s.area === req.resource.area));
  if (!resource) return false;
  if (!rule.actions.includes("*") && !rule.actions.includes(req.action)) return false;
  if (rule.window) {
    const { start, end } = rule.window;
    const inside = start < end ? local.minute >= start && local.minute < end : local.minute >= start || local.minute < end;
    if (!inside) return false;
  }
  if (rule.weekdays && !rule.weekdays.includes(local.weekday)) return false;
  return rule.constraints.every((c) => {
    const value = req.parameters?.[c.parameter];
    return value !== undefined && value >= c.min && value <= c.max;
  });
}

function deny(reason: string, mandate?: Mandate): Result {
  return mandate ? { decision: "deny", reason, mandate_digest: mandate.digest } : { decision: "deny", reason };
}

/** Evaluates a request against a mandate; null stands for an invalid mandate. */
export function evaluate(mandate: Mandate | null, req: Request): Result {
  if (!mandate) return deny("invalid_mandate");
  const at: Instant | null = typeof req.time === "string" ? parseTimestamp(req.time) : null;
  const local = at ? localTime(at, req.timezone) : null;
  const parameters = Object.values(req.parameters ?? {});
  if (!at || !local || !opaque(req.resource.entity_id, 255) ||
    (req.resource.area !== undefined && !opaque(req.resource.area, 64)) || !parameters.every(integer)) {
    return deny("invalid_request", mandate);
  }
  const category = req.resource.category;
  if (category === undefined || category === "") return deny("unknown_resource", mandate);
  const actions = vocabulary[category]?.actions;
  if (!actions) return deny("unknown_category", mandate);
  const action = actions[req.action];
  if (!action) return deny("unknown_action", mandate);
  if (req.revoked) return deny("revoked", mandate);
  if (at.ns < mandate.validFrom.ns) return deny("not_yet_valid", mandate);
  if (mandate.expires && at.ns >= mandate.expires.ns) return deny("expired", mandate);

  const matched = mandate.rules.filter((r) => matches(r, req, local));
  if (matched.length === 0) return deny("no_match", mandate);
  const final = matched.reduce<Decision>((d, r) => (STRICTNESS[r.decision] > STRICTNESS[d] ? r.decision : d), "allow");
  const first = matched.find((r) => r.decision === final)!;
  const result: Result = { decision: final, reason: "rule", rule_id: first.id, mandate_digest: mandate.digest };
  if (final === "ask") {
    result.approval = matched.find((r) => r.decision === "ask" && r.approval)?.approval ?? mandate.approval;
  }
  const critical = action.critical === true || (req.resource.critical === true && req.action !== "read");
  if (final === "allow" && critical) {
    const unprotected = matched.find((r) => !r.allowCritical);
    if (unprotected) {
      return { decision: "ask", reason: "critical_demotion", rule_id: unprotected.id, approval: mandate.approval, mandate_digest: mandate.digest };
    }
  }
  return result;
}

export interface Stored {
  mandate: string;
  revoked?: boolean;
}

/** Selects the mandate of an agent and a principal among the stored ones and evaluates. */
export function selectAndEvaluate(stored: Stored[], clientId: string, principal: string, req: Request): { selected: Mandate | null; result: Result } {
  const at = typeof req.time === "string" ? parseTimestamp(req.time) : null;
  const candidates: (Mandate | null)[] = [];
  for (const s of stored) {
    if (s.revoked) continue;
    const mandate = tryParseMandate(s.mandate);
    if (mandate) {
      if (mandate.clientId === clientId && mandate.principal === principal) candidates.push(mandate);
      continue;
    }
    // An invalid document stays a candidate if it names the agent and the principal, or
    // if not even that can be read.
    const named = looseSubject(s.mandate);
    if (!named || (named.clientId === clientId && named.principal === principal)) candidates.push(null);
  }
  const current = candidates.filter(
    (m) => m === null || (at !== null && at.ns >= m.validFrom.ns && (!m.expires || at.ns < m.expires.ns)),
  );
  let selected: Mandate | null;
  if (current.length === 1) selected = current[0]!;
  else if (current.length > 1) return { selected: null, result: deny("ambiguous_mandate") };
  else if (candidates.length === 1) selected = candidates[0]!;
  else return { selected: null, result: deny("no_mandate") };
  return { selected, result: evaluate(selected, { ...req, revoked: false }) };
}

function looseSubject(text: string): { clientId: string; principal: string } | null {
  try {
    const value = parseJson(text);
    if (isObject(value) && isObject(value.agent) && typeof value.agent.client_id === "string" && typeof value.principal === "string") {
      return { clientId: value.agent.client_id, principal: value.principal };
    }
  } catch {
    // not readable
  }
  return null;
}

/** Succession (SPEC-v0 section 3.5): may offered replace stored? */
export function isSuccessor(stored: Mandate, offered: Mandate | null): boolean {
  if (!offered || offered.id !== stored.id) return false;
  if (offered.clientId !== stored.clientId || offered.principal !== stored.principal) return false;
  if (stored.version === 0) return true;
  return offered.issuer === stored.issuer && offered.version > stored.version;
}
