// SPDX-License-Identifier: Apache-2.0

// The normative files of the specification, copied into spec/ by scripts/sync-spec.ts.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Ajv2020, type ValidateFunction } from "ajv/dist/2020.js";
import { validTimestamp } from "./time.ts";

const root = join(import.meta.dirname, "..", "spec");

export function specFile(path: string): string {
  return readFileSync(join(root, path), "utf8");
}

function readJson<T>(path: string): T {
  return JSON.parse(specFile(path)) as T;
}

// JSON Schema patterns are ECMA-262 regular expressions; Ajv compiles them as such.
// format date-time is asserted with our own check (SPEC-v0 section 3.1 item 0): the
// common format libraries accept leap seconds.
const ajv = new Ajv2020({ strict: false, allErrors: false, formats: { "date-time": validTimestamp } });

function compile(path: string): ValidateFunction {
  return ajv.compile(readJson<object>(path));
}

export const mandateSchema = compile("schema/mandate-v0.schema.json");
export const auditSchema = compile("schema/audit-v0.schema.json");

interface VocabularyFile {
  categories: Record<string, { actions: Record<string, { critical?: boolean; parameters?: Record<string, unknown> }> }>;
}

export const vocabulary = readJson<VocabularyFile>("vocabulary/v0.json").categories;

interface CodepointFile {
  forbidden: [number, number][];
  joiners: number[];
  not_first: [number, number][];
}

export const codepoints = readJson<CodepointFile>("data/forbidden-codepoints-v0.json");
