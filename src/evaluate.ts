// SPDX-License-Identifier: Apache-2.0

// The evaluation rule (SPEC-v0 section 4), the selection of the mandate (4.3) and the
// succession of versions (3.5).
import type { Approval, Decision, Mandate, Rule } from "./mandate.ts";
import { tryParseMandate } from "./mandate.ts";
import { parseJson, isObject } from "./ijson.ts";
import { MAX_AREAS, MAX_PARAMETERS, opaque, type ParameterValue, parametersAdmitted, validParameterName, validValue } from "./parameters.ts";
import { vocabulary } from "./spec-data.ts";
import { type Instant, type LocalTime, localTime, parseTimestamp } from "./time.ts";

export interface Resource {
  entity_id: string;
  category?: string;
  /**
   * The set of areas of the resource (SPEC-v0 section 3.4): its room and every location
   * above it, or several rooms side by side; at most 16, no duplicates, order irrelevant.
   * Absent or empty: the resource has no area.
   */
  areas?: readonly string[];
  critical?: boolean;
}

/** The input of the evaluation as the PEP determined it. */
export interface Request {
  resource: Resource;
  action: string;
  /**
   * Parameters of the action (SPEC-v0 section 4.5): integers in the units of the
   * vocabulary, or strings. Whoever reads them from JSON text reads numbers by their exact
   * value (exactNumber), so that a fraction is never rounded to an integer. A request
   * carries exactly the parameters its action declares: one the action does not declare,
   * a missing required one, and none or more than one of the alternatives the action
   * requires one of make it invalid (section 4, step 0).
   */
  parameters?: Readonly<Record<string, ParameterValue>>;
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
  /**
   * false only for a deny that the PEP does not enforce: the mandate is in audit mode, the
   * deny results from its rules (no_match or a deny rule) and the action is not critical
   * (SPEC-v0 section 4.6). The decision stays deny. Absent: the result is enforced.
   */
  enforced?: false;
  /**
   * true only for a deny that is not enforced while a matching rule decides ask (SPEC-v0
   * sections 4.1 and 4.6): the PEP executes it only after a confirmation, as an ask, with
   * the approval settings in approval. Absent: no confirmation beyond the decision.
   */
  confirm?: true;
}

/** Whether the areas are a set of at most 16 area identifiers without duplicates. */
function validAreas(areas: unknown): boolean {
  if (areas === undefined) return true;
  if (!Array.isArray(areas) || areas.length > MAX_AREAS) return false;
  return areas.every((area, i) => opaque(area, 64) && areas.indexOf(area) === i);
}

/**
 * Whether the parameters are ones a request may carry (SPEC-v0 section 4, step 0): at
 * most 16, names of the form the log can record, values of the permitted types, and
 * fitting the action of the vocabulary: declared, of the declared type, range and values,
 * the required ones present.
 */
function validParameters(req: Request): boolean {
  const parameters = req.parameters ?? {};
  if (typeof parameters !== "object" || parameters === null || Array.isArray(parameters)) return false;
  const entries = Object.entries(parameters);
  if (entries.length > MAX_PARAMETERS) return false;
  if (!entries.every(([name, value]) => validParameterName(name) && validValue(value))) return false;
  return parametersAdmitted(req.resource.category, req.action, parameters);
}

const STRICTNESS: Record<Decision, number> = { allow: 0, ask: 1, deny: 2 };

function matches(rule: Rule, req: Request, local: LocalTime): boolean {
  const s = rule.resource;
  const resource = s.any === true ||
    ((s.entity_id === undefined || s.entity_id === req.resource.entity_id) &&
      (s.category === undefined || s.category === req.resource.category) &&
      (s.area === undefined || (req.resource.areas ?? []).includes(s.area)));
  if (!resource) return false;
  if (!rule.actions.includes("*") && !rule.actions.includes(req.action)) return false;
  if (rule.window) {
    const { start, end } = rule.window;
    const inside = start < end ? local.minute >= start && local.minute < end : local.minute >= start || local.minute < end;
    if (!inside) return false;
  }
  if (rule.weekdays && !rule.weekdays.includes(local.weekday)) return false;
  return rule.constraints.every((c) => {
    const value = req.parameters !== undefined && Object.hasOwn(req.parameters, c.parameter) ? req.parameters[c.parameter] : undefined;
    if (value === undefined) return false;
    if (c.oneOf !== null) return c.oneOf.includes(value);
    return typeof value === "number" && value >= c.min && value <= c.max;
  });
}

/**
 * Whether the action is critical (SPEC-v0 section 4, step 5): the vocabulary marks it
 * critical, or the directory marks the resource critical and the action is not read.
 * False for a category or an action the vocabulary does not contain.
 */
export function isCritical(resource: Pick<Resource, "category" | "critical">, action: string): boolean {
  const known = resource.category === undefined ? undefined : vocabulary[resource.category]?.actions[action];
  if (!known) return false;
  return known.critical === true || (resource.critical === true && action !== "read");
}

function deny(reason: string, mandate?: Mandate): Result {
  return mandate ? { decision: "deny", reason, mandate_digest: mandate.digest } : { decision: "deny", reason };
}

/** Evaluates a request against a mandate; null stands for an invalid mandate. */
export function evaluate(mandate: Mandate | null, req: Request): Result {
  if (!mandate) return deny("invalid_mandate");
  const at: Instant | null = typeof req.time === "string" ? parseTimestamp(req.time) : null;
  const local = at ? localTime(at, req.timezone) : null;
  if (!at || !local || !opaque(req.resource.entity_id, 255) || !validAreas(req.resource.areas) || !validParameters(req)) {
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
  const result = decide(mandate, matched, req);
  // Audit mode (section 4.6): only a deny by the rules, never one of a critical action.
  const notEnforced = !mandate.enforce && result.decision === "deny" && !isCritical(req.resource, req.action);
  if (!notEnforced) return result;
  // A deny that is not enforced keeps the confirmation a matching ask rule asks for.
  if (matched.some((r) => r.decision === "ask")) {
    return { ...result, enforced: false, confirm: true, approval: askApproval(mandate, matched) };
  }
  return { ...result, enforced: false };
}

/** The approval settings of the first matching ask rule that has its own, otherwise those of the mandate. */
function askApproval(mandate: Mandate, matched: Rule[]): Approval {
  return matched.find((r) => r.decision === "ask" && r.approval)?.approval ?? mandate.approval;
}

/** Steps 3 to 5 of the evaluation rule: the decision of the matching rules. */
function decide(mandate: Mandate, matched: Rule[], req: Request): Result {
  if (matched.length === 0) return deny("no_match", mandate);
  const final = matched.reduce<Decision>((d, r) => (STRICTNESS[r.decision] > STRICTNESS[d] ? r.decision : d), "allow");
  const first = matched.find((r) => r.decision === final)!;
  const result: Result = { decision: final, reason: "rule", rule_id: first.id, mandate_digest: mandate.digest };
  if (final === "ask") {
    result.approval = askApproval(mandate, matched);
  }
  if (final === "allow" && isCritical(req.resource, req.action)) {
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

/** The pattern of principal in the mandate schema. */
const PRINCIPAL = /^(household|person):[A-Za-z0-9_-]{1,64}$/;

/**
 * Whether a request names its subject in a form a mandate could name: a non-empty client
 * ID and a principal that matches the pattern of the schema. A request that does not is
 * deny with invalid_request before any mandate is selected (SPEC-v0 sections 4.3 and 6).
 */
export function validSubject(clientId: string, principal: string): boolean {
  return typeof clientId === "string" && clientId !== "" && typeof principal === "string" && PRINCIPAL.test(principal);
}

/** A stored document as the selection sees it: the mandate, or null if the document is not a valid one. */
interface Document {
  mandate: Mandate | null;
  revoked: boolean;
}

/**
 * Whether the stored document concerns the agent and principal (SPEC-v0 section 4.3 step
 * 1): a valid mandate by its members; an invalid document by what can be read of them,
 * or every agent and principal if not even that can be read, so that it is never ignored.
 */
function concerns(s: Stored, mandate: Mandate | null, clientId: string, principal: string): boolean {
  if (mandate) return mandate.clientId === clientId && mandate.principal === principal;
  const named = looseSubject(s.mandate);
  return !named || (named.clientId === clientId && named.principal === principal);
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

/**
 * The answer of a selection without candidates (SPEC-v0 section 4.3 step 2): no_mandate,
 * unless revoked documents are stored for the agent and principal, which are not evaluated
 * but shown: revoked, naming the mandate if it is exactly one valid one.
 */
function revokedOnly(revoked: Document[]): { selected: Mandate | null; result: Result } {
  if (revoked.length === 0) return { selected: null, result: deny("no_mandate") };
  const only = revoked.length === 1 ? revoked[0]!.mandate : null;
  return only ? { selected: only, result: deny("revoked", only) } : { selected: null, result: deny("revoked") };
}

/**
 * Selects the mandate of an agent and a principal among the stored ones and evaluates
 * (SPEC-v0 section 4.3). Revoked mandates are never evaluated: without any other
 * candidate they yield revoked instead of no_mandate, with the mandate if it is exactly one.
 */
export function selectAndEvaluate(stored: Stored[], clientId: string, principal: string, req: Request): { selected: Mandate | null; result: Result } {
  if (!validSubject(clientId, principal)) return { selected: null, result: deny("invalid_request") };
  const at = typeof req.time === "string" ? parseTimestamp(req.time) : null;
  const documents: Document[] = [];
  for (const s of stored) {
    const mandate = tryParseMandate(s.mandate);
    if (concerns(s, mandate, clientId, principal)) documents.push({ mandate, revoked: s.revoked === true });
  }
  const candidates = documents.filter((d) => !d.revoked).map((d) => d.mandate);
  const current = candidates.filter(
    (m) => m === null || (at !== null && at.ns >= m.validFrom.ns && (!m.expires || at.ns < m.expires.ns)),
  );
  let selected: Mandate | null;
  if (current.length === 1) selected = current[0]!;
  else if (current.length > 1) return { selected: null, result: deny("ambiguous_mandate") };
  else if (candidates.length === 1) selected = candidates[0]!;
  else if (candidates.length === 0) return revokedOnly(documents.filter((d) => d.revoked));
  else return { selected: null, result: deny("no_mandate") };
  return { selected, result: evaluate(selected, { ...req, revoked: false }) };
}

/** Succession (SPEC-v0 section 3.5): may offered replace stored? */
export function isSuccessor(stored: Mandate, offered: Mandate | null): boolean {
  if (!offered || offered.id !== stored.id) return false;
  if (offered.clientId !== stored.clientId || offered.principal !== stored.principal) return false;
  if (stored.version === 0) return true;
  return offered.issuer === stored.issuer && offered.version > stored.version;
}

/**
 * Whether offered differs from stored only in ways that take nothing away from the
 * household's protection (SPEC-v0 section 3.5): removed allow rules, added deny rules,
 * added ask rules without their own approval, an earlier or added expiry, a later start, a
 * lower rate limit, audit mode switched off, and the issuer's version. Everything else, a
 * changed rule or displayed text included, is a weakening. Rules are compared as wholes.
 */
export function narrows(stored: Mandate, offered: Mandate): boolean {
  if (stored.id !== offered.id || stored.clientId !== offered.clientId || stored.principal !== offered.principal) return false;
  if ((!offered.enforce && stored.enforce) || offered.name !== stored.name || offered.displayName !== stored.displayName ||
    offered.audience !== stored.audience || offered.approvalText !== stored.approvalText ||
    offered.maxActions > stored.maxActions || offered.validFrom.ns < stored.validFrom.ns) {
    return false;
  }
  if (stored.expires && (!offered.expires || offered.expires.ns > stored.expires.ns)) return false;
  const kept = new Map(stored.ruleTexts.map((r) => [r.text, false]));
  for (const r of offered.ruleTexts) {
    if (kept.has(r.text)) {
      kept.set(r.text, true);
      continue;
    }
    if (r.decision !== "deny" && !(r.decision === "ask" && !r.ownApproval)) return false; // an added or changed allow rule, or an ask rule that names approvers
  }
  return stored.ruleTexts.every((r) => kept.get(r.text) || r.decision === "allow"); // a removed or changed deny or ask rule weakens
}

/**
 * Whether the stored mandate is in force: not revoked, and valid at the point in time if
 * one is given (SPEC-v0 section 4, step 1); without one, only valid and active.
 */
function inForce(stored: Mandate | null, storedRevoked: boolean, at: Instant | undefined): stored is Mandate {
  if (stored === null || storedRevoked) return false;
  return at === undefined || (at.ns >= stored.validFrom.ns && (!stored.expires || at.ns < stored.expires.ns));
}

/**
 * Whether adopting offered switches audit mode on (SPEC-v0 sections 3.5 and 11.6): it is in
 * audit mode and no mandate in audit mode is in force for it. stored is the mandate held
 * under the same id, null if none; a predecessor that is revoked, expired or not yet valid
 * at the point in time counts as none, so offered arrives as if from outside.
 */
export function entersAuditMode(stored: Mandate | null, storedRevoked: boolean, offered: Mandate, at?: Instant): boolean {
  if (offered.enforce) return false;
  return !inForce(stored, storedRevoked, at) || stored.enforce;
}

/**
 * Whether an accepted successor takes effect only after a human confirmed exactly this
 * version (SPEC-v0 sections 3.5 and 11.6): it switches audit mode on, its predecessor is
 * revoked (the issuer cannot undo a revocation of the household), or it does not merely
 * narrow the stored mandate. Whether the approvers of a signed mandate are known to the
 * implementation is the caller's check.
 */
export function needsConfirmation(stored: Mandate | null, storedRevoked: boolean, offered: Mandate | null, at?: Instant): boolean {
  if (!offered) return false;
  if (entersAuditMode(stored, storedRevoked, offered, at)) return true;
  if (!stored) return false;
  return storedRevoked || !narrows(stored, offered);
}
