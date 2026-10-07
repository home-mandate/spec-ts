// SPDX-License-Identifier: Apache-2.0

// Validity of a mandate (SPEC-v0 section 3.1) and its digest (section 3.2).
import { displayable } from "./displaytext.ts";
import { isObject, type Json, JsonError, parseJson, utf8Length } from "./ijson.ts";
import { digest } from "./jcs.ts";
import { validateMandate } from "./generated/mandate-validator.ts";
import { describeViolation, type SchemaValidator } from "./schema-runtime.ts";
import { vocabulary } from "./spec-data.ts";
import { type Instant, parseTimestamp } from "./time.ts";

export class MandateError extends Error {}

const MAX_BYTES = 256 * 1024;

const mandateSchema: SchemaValidator = validateMandate;

export type Decision = "allow" | "ask" | "deny";

export interface Approval {
  timeout: string;
  approvers: string[];
}

export interface Rule {
  id: string;
  resource: { any?: boolean; entity_id?: string; category?: string; area?: string };
  actions: string[];
  decision: Decision;
  window: { start: number; end: number } | null;
  weekdays: number[] | null;
  constraints: { parameter: string; min: number; max: number }[];
  approval: Approval | null;
  allowCritical: boolean;
}

export interface Mandate {
  id: string;
  digest: string;
  clientId: string;
  principal: string;
  issuer: string;
  /** 0 if the mandate has no version. */
  version: number;
  validFrom: Instant;
  expires: Instant | null;
  rules: Rule[];
  approval: Approval;
}

const WEEKDAY_INDEX: Record<string, number> = { sun: 0, mon: 1, tue: 2, wed: 3, thu: 4, fri: 5, sat: 6 };

function fail(message: string): never {
  throw new MandateError(message);
}

/** Seconds of a timeout PT[nH][nM][nS]; the schema has checked the form. */
export function timeoutSeconds(timeout: string): number {
  const m = /^PT(?:([0-9]{1,5})H)?(?:([0-9]{1,5})M)?(?:([0-9]{1,5})S)?$/.exec(timeout);
  if (!m) return NaN;
  return Number(m[1] ?? 0) * 3600 + Number(m[2] ?? 0) * 60 + Number(m[3] ?? 0);
}

function approval(raw: Json, where: string): Approval {
  const a = raw as { timeout: string; approvers: string[] };
  const seconds = timeoutSeconds(a.timeout);
  if (!(seconds >= 10 && seconds <= 3600)) fail(`${where}: timeout outside 10 s to 1 h`);
  for (const approver of a.approvers) if (!displayable(approver)) fail(`${where}: approver not displayable`);
  return { timeout: a.timeout, approvers: [...a.approvers] };
}

function knownAction(category: string | undefined, action: string): boolean {
  if (category !== undefined) return action in (vocabulary[category]?.actions ?? {});
  return Object.values(vocabulary).some((c) => action in c.actions);
}

function hasParameter(category: string | undefined, action: string, parameter: string): boolean {
  return Object.entries(vocabulary).some(
    ([name, c]) => (category === undefined || name === category) && parameter in (c.actions[action]?.parameters ?? {}),
  );
}

function clock(text: string): number {
  return Number(text.slice(0, 2)) * 60 + Number(text.slice(3, 5));
}

function rule(raw: { [key: string]: Json }): Rule {
  const id = raw.id as string;
  const resource = raw.resource as Rule["resource"];
  const actions = raw.actions as string[];
  const category = resource.category;
  const checked = category === undefined || category in vocabulary; // extensions are not checked
  if (checked) {
    for (const action of actions) {
      if (action !== "*" && !knownAction(category, action)) fail(`rule ${id}: action ${action} not in the vocabulary`);
    }
  }
  let window: Rule["window"] = null;
  let weekdays: Rule["weekdays"] = null;
  if (isObject(raw.conditions)) {
    const tw = raw.conditions.time_window;
    if (typeof tw === "string") {
      window = { start: clock(tw.slice(0, 5)), end: clock(tw.slice(6, 11)) };
      if (window.start === window.end) fail(`rule ${id}: time window with equal start and end`);
    }
    if (Array.isArray(raw.conditions.weekdays)) weekdays = raw.conditions.weekdays.map((d) => WEEKDAY_INDEX[d as string]!);
  }
  const constraints: Rule["constraints"] = [];
  if (isObject(raw.constraints)) {
    for (const [parameter, limits] of Object.entries(raw.constraints)) {
      const { min = -Infinity, max = Infinity } = limits as { min?: number; max?: number };
      if (min > max) fail(`rule ${id}: constraint ${parameter} has min greater than max`);
      for (const action of actions) {
        if (checked && !hasParameter(category, action, parameter)) fail(`rule ${id}: ${action} has no parameter ${parameter}`);
      }
      constraints.push({ parameter, min, max });
    }
  }
  return {
    id, resource, actions, decision: raw.decision as Decision, window, weekdays, constraints,
    approval: raw.approval === undefined ? null : approval(raw.approval, `rule ${id}`),
    allowCritical: raw.allow_critical === true,
  };
}

/** Parses and validates a mandate; throws MandateError if it is not valid. */
export function parseMandate(text: string): Mandate {
  if (utf8Length(text) > MAX_BYTES) fail("larger than 256 KiB");
  if (!text.isWellFormed()) fail("not UTF-8");
  let value: Json;
  try {
    value = parseJson(text);
  } catch (e) {
    if (e instanceof JsonError) fail(`not I-JSON: ${e.message}`);
    throw e;
  }
  if (!mandateSchema(value) || !isObject(value)) fail(`violates the schema at ${describeViolation(mandateSchema)}`);
  const validFrom = parseTimestamp(value.valid_from as string)!;
  const expires = typeof value.expires === "string" ? parseTimestamp(value.expires)! : null;
  if (expires && expires.ns <= validFrom.ns) fail("expires must be after valid_from");
  const agent = value.agent as { client_id: string; display_name: string };
  if (!displayable(agent.display_name) || !displayable(value.created_by as string)) fail("text not displayable");
  const rules = (value.rules as { [key: string]: Json }[]).map(rule);
  if (new Set(rules.map((r) => r.id)).size !== rules.length) fail("duplicate rule id");
  let mandateDigest: string;
  try {
    mandateDigest = digest(value);
  } catch {
    fail("cannot be canonicalized");
  }
  return {
    id: value.id as string,
    digest: mandateDigest,
    clientId: agent.client_id,
    principal: value.principal as string,
    issuer: (value.issuer as string | undefined) ?? "",
    version: (value.version as number | undefined) ?? 0,
    validFrom, expires, rules,
    approval: approval(value.approval!, "approval"),
  };
}

/** The mandate, or null if the text is not a valid mandate. */
export function tryParseMandate(text: string): Mandate | null {
  try {
    return parseMandate(text);
  } catch (e) {
    if (e instanceof MandateError) return null;
    throw e;
  }
}
