// SPDX-License-Identifier: Apache-2.0

// Parameter values and how they relate to the vocabulary (SPEC-v0 sections 4.5 and 5).
import { vocabulary, type VocabularyParameter } from "./spec-data.ts";

/** The value of a parameter: an integer in the unit of the vocabulary, or a string. */
export type ParameterValue = number | string;

/** Largest number of areas of a resource and of values of a one_of (SPEC-v0 sections 3.4 and 4.5). */
export const MAX_AREAS = 16;
export const MAX_ONE_OF = 32;

const MAX_TEXT = 64;

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
 * Whether every parameter of a request that the action declares in the vocabulary has its
 * type and lies within its range or is one of its permitted values. Parameters the action
 * does not declare, and those of a category or action outside the vocabulary, are not
 * checked here.
 */
export function parametersAdmitted(category: string | undefined, action: string, parameters: Readonly<Record<string, ParameterValue>>): boolean {
  const declared = category === undefined ? undefined : vocabulary[category]?.actions[action]?.parameters;
  if (!declared) return true;
  return Object.entries(parameters).every(([name, value]) => {
    const p = declared[name];
    return p === undefined || admits(p, value);
  });
}
