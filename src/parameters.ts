// SPDX-License-Identifier: Apache-2.0

// Parameter values and how they relate to the vocabulary (SPEC-v0 sections 4.5 and 5).
import { vocabulary, type VocabularyParameter } from "./spec-data.ts";

/** The value of a parameter: an integer in the unit of the vocabulary, or a string. */
export type ParameterValue = number | string;

/** Largest number of areas of a resource, of values of a one_of and of parameters of a request (SPEC-v0 sections 3.4, 4 step 0 and 4.5). */
export const MAX_AREAS = 16;
export const MAX_ONE_OF = 32;
export const MAX_PARAMETERS = 16;

const MAX_TEXT = 64;

/** The form of a parameter name (SPEC-v0 section 4, step 0). */
const PARAMETER_NAME = /^[a-z][a-z0-9_]{0,63}$/;

/** An identifier of 1 to limit printable ASCII characters without space (SPEC-v0 section 3.4). */
export function opaque(s: unknown, limit: number): s is string {
  return typeof s === "string" && s.length >= 1 && s.length <= limit && /^[!-~]+$/.test(s);
}

export function integer(n: unknown): n is number {
  return typeof n === "number" && Number.isInteger(n) && Math.abs(n) <= Number.MAX_SAFE_INTEGER;
}

/** Whether a request may carry the value: an integer of magnitude at most 2^53 − 1 or a string like an area. */
export function validValue(v: unknown): v is ParameterValue {
  return integer(v) || opaque(v, MAX_TEXT);
}

/** Whether the name is one a parameter may have, and the log can record (SPEC-v0 sections 4 step 0 and 9.1). */
export function validParameterName(name: string): boolean {
  return PARAMETER_NAME.test(name);
}

/**
 * Whether the value has the type of the parameter and, for a string with permitted values,
 * is one of them, compared exactly. The range of an integer is not part of it: a mandate
 * may name a value outside the range, which no valid request carries.
 */
export function declares(p: VocabularyParameter, v: ParameterValue): boolean {
  if (p.type === "integer") return typeof v === "number";
  return typeof v === "string" && (p.values === undefined || p.values.includes(v));
}

/** Whether a request may carry the value for the parameter (SPEC-v0 section 4, step 0). */
function admits(p: VocabularyParameter, v: ParameterValue): boolean {
  if (!declares(p, v)) return false;
  if (typeof v === "string") return true;
  return (p.minimum === undefined || v >= p.minimum) && (p.maximum === undefined || v <= p.maximum);
}

/**
 * Whether the parameters of a request fit the action (SPEC-v0 section 4, step 0): every
 * parameter is one the action declares and has its type, lies within its range or is one
 * of its permitted values; every required parameter is present; and of the alternatives
 * the action requires one of, exactly one is present whole and no part of another.
 * Parameters of a category or action outside the vocabulary are not checked here; such a
 * request is denied anyway (unknown_category, unknown_action).
 */
export function parametersAdmitted(category: string | undefined, action: string, parameters: Readonly<Record<string, ParameterValue>>): boolean {
  const info = category === undefined ? undefined : vocabulary[category]?.actions[action];
  if (!info) return true;
  // The vocabulary is a copy without prototype (spec-data.ts); a name such as "toString"
  // must not find an inherited member, so only own members count as declared.
  const declared = info.parameters ?? {};
  for (const [name, value] of Object.entries(parameters)) {
    const p = Object.hasOwn(declared, name) ? declared[name] : undefined;
    if (p === undefined || !admits(p, value)) return false;
  }
  for (const [name, p] of Object.entries(declared)) {
    if (p.required === true && !Object.hasOwn(parameters, name)) return false;
  }
  const alternatives = info.required_one_of;
  if (alternatives === undefined || alternatives.length === 0) return true;
  let satisfied = 0;
  for (const alternative of alternatives) {
    const present = alternative.filter((name) => Object.hasOwn(parameters, name)).length;
    if (present === alternative.length) satisfied++;
    else if (present !== 0) return false; // a part of an alternative
  }
  return satisfied === 1;
}
