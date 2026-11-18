// SPDX-License-Identifier: Apache-2.0

// Validity of a mandate (SPEC-v0 section 3.1) and its digest (section 3.2).
import { displayable } from "./displaytext.ts";
import { isObject, type Json, JsonError, parseJson, utf8Length } from "./ijson.ts";
import { canonicalize, digest } from "./jcs.ts";
import { declares, MAX_ONE_OF, type ParameterValue, validValue } from "./parameters.ts";
import { validateMandate } from "./generated/mandate-validator.ts";
import { describeViolation, type SchemaValidator } from "./schema-runtime.ts";
import { vocabulary } from "./spec-data.ts";
import { type Instant, parseTimestamp, validDate } from "./time.ts";

export class MandateError extends Error {}

const MAX_BYTES = 256 * 1024;

const mandateSchema: SchemaValidator = validateMandate;

export type Decision = "allow" | "ask" | "deny";

export interface Approval {
  timeout: string;
  approvers: string[];
}

/**
 * What a rule permits for one parameter (SPEC-v0 section 4.5): the inclusive range of an
 * integer (a limit the rule does not give is infinite); if oneOf is not null, exactly the
 * listed values; if noneOf is not null, every value of the type of the list except the
 * listed ones.
 */
export interface Constraint {
  parameter: string;
  min: number;
  max: number;
  oneOf: readonly ParameterValue[] | null;
  noneOf: readonly ParameterValue[] | null;
}

/** A rule's own period (SPEC-v0 section 4, step 2); null bounds do not restrict. */
export interface Period {
  from: Instant | null;
  until: Instant | null;
}

/** A range of calendar dates, both inclusive, as YYYY-MM-DD (SPEC-v0 section 4.2). */
export interface DateRange {
  from: string;
  to: string;
}

/** The limits a rule sets of its own (SPEC-v0 section 11.2); 0 does not limit. */
export interface RuleLimits {
  perHour: number;
  perDay: number;
  /** Seconds. */
  minInterval: number;
}

export interface Rule {
  id: string;
  resource: { any?: boolean; entity_id?: string; category?: string; area?: string };
  actions: string[];
  decision: Decision;
  window: { start: number; end: number } | null;
  weekdays: number[] | null;
  /** conditions.dates; null: no condition. */
  dates: DateRange[] | null;
  period: Period;
  /** The rule's own limits; null if it has none. */
  limits: RuleLimits | null;
  constraints: Constraint[];
  approval: Approval | null;
  allowCritical: boolean;
}

/** What a rule is for the comparison of two versions (SPEC-v0 section 3.5): its canonical text, as a whole. */
export interface RuleText {
  text: string;
  decision: Decision;
  /** The rule names its own approval settings. */
  ownApproval: boolean;
}

export interface Mandate {
  id: string;
  digest: string;
  clientId: string;
  principal: string;
  issuer: string;
  /** 0 if the mandate has no version. */
  version: number;
  /** The verifier the mandate is for (SPEC-v0 section 3.5); "" if it names none. */
  audience: string;
  /** Displayed name of the mandate (SPEC-v0 section 3.1); "" if it has none. */
  name: string;
  /** agent.display_name, the name every confirmation shows. */
  displayName: string;
  /** limits.max_actions_per_hour; 0 if the mandate names none. */
  maxActions: number;
  /** Canonical text of approval, for the comparison of two versions (SPEC-v0 section 3.5). */
  approvalText: string;
  /** The rules as wholes, in document order (SPEC-v0 section 3.5). */
  ruleTexts: readonly RuleText[];
  /** false for a mandate in audit mode ("enforce": false, SPEC-v0 section 4.6). */
  enforce: boolean;
  validFrom: Instant;
  expires: Instant | null;
  rules: Rule[];
  approval: Approval;
}

/**
 * The members of the mandate schema this model reads, by object. test/members.test.ts
 * compares them with spec/schema/mandate-v0.schema.json: a member the schema gains in a
 * later release would otherwise be accepted by the schema and ignored by the evaluation,
 * which fails open. Members that are only displayed or compared as text count as read.
 */
export const MODEL_MEMBERS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  mandate: [
    "type", "id", "name", "principal", "agent", "enforce", "rules", "default", "approval", "limits", "valid_from", "expires",
    "issuer", "audience", "version", "created_by", "created_at",
  ],
  rule: ["id", "resource", "actions", "decision", "note", "valid_from", "expires", "conditions", "constraints", "approval", "limits", "allow_critical"],
  resource: ["entity_id", "category", "area", "any"],
  conditions: ["time_window", "weekdays", "dates"],
  dates: ["from", "to"],
  constraint: ["min", "max", "one_of", "none_of"],
  rule_limits: ["max_actions_per_hour", "max_actions_per_day", "min_interval"],
  limits: ["max_actions_per_hour"],
  approval: ["timeout", "approvers"],
  agent: ["client_id", "display_name"],
});

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

/**
 * Whether the constraint fits a parameter of the action (SPEC-v0 section 3.1 item 10): a
 * range only an integer parameter, a list only values the parameter declares; in the
 * given category, or without one in any category of the vocabulary.
 */
function parameterFits(category: string | undefined, action: string, c: Constraint): boolean {
  return Object.entries(vocabulary).some(([name, vocabularyCategory]) => {
    if (category !== undefined && name !== category) return false;
    const p = vocabularyCategory.actions[action]?.parameters?.[c.parameter];
    if (!p) return false;
    const list = c.oneOf ?? c.noneOf;
    return list === null ? p.type === "integer" : list.every((v) => declares(p, v));
  });
}

/**
 * Reads one constraint: a list of permitted or of excluded values, or limits (SPEC-v0
 * section 4.5).
 */
function constraint(id: string, parameter: string, raw: Json): Constraint {
  const given = raw as { min?: number; max?: number; one_of?: Json[]; none_of?: Json[] };
  const list = given.one_of ?? given.none_of;
  if (list === undefined) {
    const { min = -Infinity, max = Infinity } = given;
    if (min > max) fail(`rule ${id}: constraint ${parameter} has min greater than max`);
    return { parameter, min, max, oneOf: null, noneOf: null };
  }
  // The schema checks the list already; checked again so that no list contradicts section 4.5.
  if (given.min !== undefined || given.max !== undefined || (given.one_of !== undefined && given.none_of !== undefined)) {
    fail(`rule ${id}: constraint ${parameter} has a list together with another form`);
  }
  if (list.length < 1 || list.length > MAX_ONE_OF) fail(`rule ${id}: constraint ${parameter} needs 1 to ${MAX_ONE_OF} values`);
  const values: ParameterValue[] = [];
  for (const v of list) {
    if (!validValue(v)) fail(`rule ${id}: constraint ${parameter} has a value that is no parameter value`);
    if (typeof v !== typeof list[0]) fail(`rule ${id}: constraint ${parameter} mixes integers and strings`);
    if (values.includes(v)) fail(`rule ${id}: constraint ${parameter} has a value twice`);
    values.push(v);
  }
  const frozen = Object.freeze(values);
  return given.one_of !== undefined
    ? { parameter, min: -Infinity, max: Infinity, oneOf: frozen, noneOf: null }
    : { parameter, min: -Infinity, max: Infinity, oneOf: null, noneOf: frozen };
}

/** A rule's own period (SPEC-v0 section 3.1 items 0 and 6). */
function period(id: string, raw: { [key: string]: Json }): Period {
  const read = (member: string): Instant | null => {
    if (raw[member] === undefined) return null;
    return parseTimestamp(raw[member] as string) ?? fail(`rule ${id}: ${member} is no timestamp`);
  };
  const from = read("valid_from");
  const until = read("expires");
  if (from && until && until.ns <= from.ns) fail(`rule ${id}: expires must be after valid_from`);
  return { from, until };
}

/** conditions.dates (SPEC-v0 section 3.1 items 0 and 3); the schema has checked the form. */
function dates(id: string, raw: Json): DateRange[] {
  return (raw as { from: string; to: string }[]).map(({ from, to }) => {
    if (!validDate(from) || !validDate(to)) fail(`rule ${id}: a date that does not exist`);
    if (from > to) fail(`rule ${id}: dates from ${from} is after to ${to}`);
    return { from, to };
  });
}

/** A rule's own limits (SPEC-v0 section 3.1 item 12); the schema has checked the counts. */
function ruleLimits(id: string, decision: Decision, raw: Json): RuleLimits {
  if (decision !== "allow") fail(`rule ${id}: limits only on an allow rule`);
  const given = raw as { max_actions_per_hour?: number; max_actions_per_day?: number; min_interval?: string };
  const limits: RuleLimits = { perHour: given.max_actions_per_hour ?? 0, perDay: given.max_actions_per_day ?? 0, minInterval: 0 };
  if (given.min_interval !== undefined) {
    limits.minInterval = timeoutSeconds(given.min_interval);
    if (!(limits.minInterval >= 1 && limits.minInterval <= 86400)) fail(`rule ${id}: min_interval outside 1 s to 24 h`);
  }
  if (limits.perHour === 0 && limits.perDay === 0 && limits.minInterval === 0) fail(`rule ${id}: limits without a member`);
  return limits;
}

function clock(text: string): number {
  return Number(text.slice(0, 2)) * 60 + Number(text.slice(3, 5));
}

function rule(raw: { [key: string]: Json }): Rule {
  const id = raw.id as string;
  if (typeof raw.note === "string" && !displayable(raw.note)) fail(`rule ${id}: note not displayable`);
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
  let dateRanges: Rule["dates"] = null;
  if (isObject(raw.conditions)) {
    if (raw.conditions.dates !== undefined) dateRanges = dates(id, raw.conditions.dates);
    const tw = raw.conditions.time_window;
    if (typeof tw === "string") {
      window = { start: clock(tw.slice(0, 5)), end: clock(tw.slice(6, 11)) };
      if (window.start === window.end) fail(`rule ${id}: time window with equal start and end`);
    }
    if (Array.isArray(raw.conditions.weekdays)) weekdays = raw.conditions.weekdays.map((d) => WEEKDAY_INDEX[d as string]!);
  }
  const constraints: Rule["constraints"] = [];
  if (isObject(raw.constraints)) {
    for (const [parameter, given] of Object.entries(raw.constraints)) {
      const c = constraint(id, parameter, given);
      for (const action of actions) {
        if (checked && !parameterFits(category, action, c)) fail(`rule ${id}: ${action} has no parameter ${parameter} that the constraint fits`);
      }
      constraints.push(c);
    }
  }
  const decision = raw.decision as Decision;
  return {
    id, resource, actions, decision, window, weekdays, dates: dateRanges, period: period(id, raw),
    limits: raw.limits === undefined ? null : ruleLimits(id, decision, raw.limits), constraints,
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
  if (typeof value.name === "string" && !displayable(value.name)) fail("name not displayable");
  const rules = (value.rules as { [key: string]: Json }[]).map(rule);
  if (new Set(rules.map((r) => r.id)).size !== rules.length) fail("duplicate rule id");
  let mandateDigest: string;
  let approvalText: string;
  let ruleTexts: RuleText[];
  try {
    mandateDigest = digest(value);
    approvalText = canonicalize(value.approval!);
    ruleTexts = (value.rules as { [key: string]: Json }[]).map((r) => ({
      text: canonicalize(r), decision: r.decision as Decision, ownApproval: r.approval !== undefined,
    }));
  } catch {
    fail("cannot be canonicalized");
  }
  const limits = isObject(value.limits) ? value.limits : undefined;
  return {
    id: value.id as string,
    digest: mandateDigest,
    clientId: agent.client_id,
    principal: value.principal as string,
    issuer: (value.issuer as string | undefined) ?? "",
    version: (value.version as number | undefined) ?? 0,
    audience: (value.audience as string | undefined) ?? "",
    name: (value.name as string | undefined) ?? "",
    displayName: agent.display_name,
    maxActions: typeof limits?.max_actions_per_hour === "number" ? limits.max_actions_per_hour : 0,
    approvalText,
    ruleTexts,
    enforce: value.enforce !== false,
    validFrom, expires, rules,
    approval: approval(value.approval!, "approval"),
  };
}

const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * Parses and validates a mandate given as the bytes it was received or stored as; throws
 * MandateError if they are not UTF-8 or not a valid mandate (SPEC-v0 section 3.1 items 1
 * and 5). A byte order mark is kept and makes the document invalid.
 */
export function parseMandateBytes(bytes: Uint8Array): Mandate {
  if (bytes.length > MAX_BYTES) fail("larger than 256 KiB");
  let text: string;
  try {
    text = UTF8.decode(bytes);
  } catch {
    fail("not UTF-8");
  }
  return parseMandate(text);
}

/** The mandate, or null if the bytes are not a valid mandate. */
export function tryParseMandateBytes(bytes: Uint8Array): Mandate | null {
  try {
    return parseMandateBytes(bytes);
  } catch (e) {
    if (e instanceof MandateError) return null;
    throw e;
  }
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
