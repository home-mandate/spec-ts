// SPDX-License-Identifier: Apache-2.0

// The rules of SPEC-v0 section 9.1 that a schema cannot express, for condition 1 of section
// 9.4, and the vocabularies they are checked against.
import { displayable } from "./displaytext.ts";
import { isObject, type Json, parseRecorded } from "./ijson.ts";
import { canonicalProxy } from "./ip-address.ts";
import { validPublicOrigin } from "./origin.ts";
import { vocabulary, vocabularyId } from "./spec-data.ts";

export type Entry = { [key: string]: Json };

/** What the verifier knows about one category: the id of the vocabulary that defines it, and whether each action is critical. */
interface CategoryVocabulary {
  id: string;
  actions: ReadonlyMap<string, boolean>;
}

/** Categories by name; no prototype, so no inherited names. */
export type KnownActions = ReadonlyMap<string, CategoryVocabulary>;

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
    value = parseRecorded(text);
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
export function knownActions(extensions: readonly string[] | undefined): KnownActions {
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

/** An integer member by its value; 0 if it is missing, is no integer or lies outside the exact range (RFC 7493). */
export function readableSeq(value: Json | undefined): number {
  return typeof value === "number" && Number.isInteger(value) && Math.abs(value) < 2 ** 53 ? value : 0;
}

/** A member that is an object; undefined otherwise. */
export function member(entry: Entry | undefined, name: string): Entry | undefined {
  const value = entry?.[name];
  return isObject(value) ? value : undefined;
}

/** A member that is a string; "" otherwise. */
export function text(entry: Entry | undefined, name: string): string {
  const value = entry?.[name];
  return typeof value === "string" ? value : "";
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
  ["ct", "status", "previous_status"],
  ["relay", "status", "previous_status"],
  ["relay", "level", "previous_level"],
] as const;

/** Whether every displayed member follows the rule for displayed text. */
function displayedTextValid(entry: Entry): boolean {
  return DISPLAYED_FIELDS.every(([name, field]) => {
    const value = member(entry, name)?.[field];
    return typeof value !== "string" || displayable(value);
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
  const category = member(member(entry, "request"), "resource")?.category;
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

/** Whether the values of a change of the given setting all pass the check; a pattern cannot fully express either form. */
function settingValuesValid(entry: Entry, setting: string, valid: (value: string) => boolean): boolean {
  const config = member(entry, "config");
  if (text(config, "setting") !== setting) return true;
  return ["value", "previous_value"].every((key) => typeof config?.[key] !== "string" || valid(config[key]));
}

/** Whether an entry that conforms to the schema of its version keeps the rules of section 9.1 the schema cannot express. */
export function keepsRules(entry: Entry, known: KnownActions): boolean {
  return displayedTextValid(entry) && formerValuesDistinct(entry) && areasDistinct(entry) && truncatesEarlier(entry) &&
    exportsEarlier(entry) && enforcedConsistent(entry, known) && vocabularyConsistent(entry, known) &&
    // The one form of a public origin (section 11.7 item 1, without IDNA) and of a trusted proxy.
    settingValuesValid(entry, "public_origin", validPublicOrigin) && settingValuesValid(entry, "trusted_proxy", canonicalProxy);
}
