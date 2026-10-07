// SPDX-License-Identifier: Apache-2.0

// The run-time helpers the generated validators (src/generated/) call. Ajv's standalone
// code refers to them as CommonJS modules of the ajv package; scripts/generate-validators.ts
// replaces those references with these, so that the validators need no package at run time
// and no code is compiled at run time (a Content Security Policy without 'unsafe-eval').
import { validTimestamp } from "./time.ts";

/** Length in Unicode code points, as JSON Schema counts minLength and maxLength. */
export function ucs2length(text: string): number {
  let length = 0;
  for (const _ of text) length++;
  return length;
}

/** Structural equality of JSON values, for const and enum. */
export function equal(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((item, i) => equal(item, b[i]));
  }
  const x = a as Record<string, unknown>;
  const y = b as Record<string, unknown>;
  const keys = Object.keys(x);
  return keys.length === Object.keys(y).length && keys.every((k) => Object.hasOwn(y, k) && equal(x[k], y[k]));
}

// format date-time is asserted with our own check (SPEC-v0 section 3.1 item 0): the
// common format libraries accept leap seconds.
export const formats: Readonly<Record<string, (text: string) => boolean>> = Object.freeze({ "date-time": validTimestamp });

/** An error of a generated validator, as Ajv reports it. */
export interface SchemaError {
  instancePath: string;
  keyword: string;
  message?: string;
  params: Record<string, unknown>;
}

/** A generated validator; errors holds the first violation after a failed call. */
export interface SchemaValidator {
  (value: unknown): boolean;
  errors?: SchemaError[] | null;
}

/** The first violation of the last failed call, for example "/rules/0: must have required property 'id'". */
export function describeViolation(validator: SchemaValidator): string {
  const error = validator.errors?.[0];
  if (!error) return "unknown violation";
  const extra = typeof error.params.additionalProperty === "string" ? ` (${error.params.additionalProperty})` : "";
  return `${error.instancePath || "/"}: ${error.message ?? error.keyword}${extra}`;
}
