// SPDX-License-Identifier: Apache-2.0

// Shared by the fuzz targets (test/fuzz/*.fuzz.ts, pnpm fuzz): the time budget, how a
// failure is reported and reproduced, and inputs derived from seeds. fast-check generates
// inputs rather than following coverage like Go's fuzzer, so besides random text every
// target mutates seeds from the files of the specification: edits of their text and
// changes of single members of their JSON values.
//
// FUZZ_TIME: seconds per target (default 10). The run stops when the time is up and
//   passes if no input failed.
// FUZZ_SEED, FUZZ_PATH: reproduce a failure with the seed and path that it printed.
// A failure is also written to fuzz-failures/<target>.txt.
import { mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import fc from "fast-check";
import { specFile } from "../../src/spec.ts";

const DEFAULT_SECONDS = 10;
const ROOT = join(import.meta.dirname, "..", "..");
const SPEC = join(ROOT, "spec");
const FAILURES = join(ROOT, "fuzz-failures");

function seconds(): number {
  const text = process.env.FUZZ_TIME ?? "";
  if (text === "") return DEFAULT_SECONDS;
  const n = Number(text);
  if (!(n > 0) || !Number.isFinite(n)) throw new Error(`FUZZ_TIME must be a positive number of seconds, not ${JSON.stringify(text)}`);
  return n;
}

function reproduction(): { seed?: number; path?: string } {
  const seed = process.env.FUZZ_SEED;
  if (seed === undefined || seed === "") return {};
  if (!Number.isSafeInteger(Number(seed))) throw new Error(`FUZZ_SEED must be an integer, not ${JSON.stringify(seed)}`);
  return { seed: Number(seed), path: process.env.FUZZ_PATH || undefined };
}

/**
 * Registers a fuzz target: check runs on the examples first, then on generated inputs
 * until the time budget is used up, and fails by throwing.
 */
export function fuzz<T>(name: string, input: fc.Arbitrary<T>, check: (value: T) => void, examples: readonly T[] = []): void {
  test(name, (t) => {
    const budget = seconds();
    const start = performance.now();
    const details = fc.check(fc.property(input, check), {
      numRuns: Number.MAX_SAFE_INTEGER,
      interruptAfterTimeLimit: budget * 1000,
      markInterruptAsFailure: false,
      examples: examples.map((e) => [e] as [T]),
      ...reproduction(),
    });
    const elapsed = ((performance.now() - start) / 1000).toFixed(1);
    t.diagnostic(`${details.numRuns} inputs in ${elapsed} s (budget ${budget} s), seed ${details.seed}`);
    if (!details.failed) return;
    const report = `${fc.defaultReportMessage(details)}\n\nReproduce: FUZZ_SEED=${details.seed} FUZZ_PATH=${details.counterexamplePath ?? ""} ` +
      `node --test test/fuzz/${name}.fuzz.ts\n`;
    mkdirSync(FAILURES, { recursive: true });
    writeFileSync(join(FAILURES, `${name}.txt`), report);
    throw new Error(report);
  });
}

/** Text of the JSON files in a directory of the specification, e.g. "examples". */
export function specJsonFiles(dir: string): string[] {
  const names = readdirSync(join(SPEC, dir)).filter((n) => n.endsWith(".json")).sort();
  if (names.length === 0) throw new Error(`no seeds in spec/${dir}`);
  return names.map((n) => specFile(`${dir}/${n}`));
}

/** A UTF-16 code unit, lone surrogates included, so that text need not be well formed. */
const codeUnit = fc.oneof(
  fc.integer({ min: 0x20, max: 0x7e }).map((c) => String.fromCharCode(c)),
  fc.integer({ min: 0, max: 0xffff }).map((c) => String.fromCharCode(c)),
);

/** Any text, also text that is no well-formed Unicode. */
export const anyText = (maxLength = 64): fc.Arbitrary<string> => fc.string({ unit: codeUnit, maxLength });

/** Fragments that change the meaning of JSON text or of the names in it. */
const TOKENS = [
  "{", "}", "[", "]", ",", ":", '"', "\\", "\\u0000", "\\ud800", "\ud800", "\udc00", "\u0000", "‍", "‮",
  "null", "true", "false", "0", "-0", "1.0", "1e400", "1e-400", "9007199254740992", "50.00000000000000000001",
  "__proto__", "constructor", "toString", "*", " ", "\n", "\r", "\t", ".", "=", "A",
];

const fragment = fc.oneof(fc.constantFrom(...TOKENS), anyText(8));

const edit = fc.record({
  kind: fc.constantFrom("insert", "delete", "replace", "repeat"),
  at: fc.nat(),
  length: fc.nat({ max: 32 }),
  text: fragment,
});

type Edit = typeof edit extends fc.Arbitrary<infer E> ? E : never;

function applyEdit(text: string, e: Edit): string {
  const at = e.at % (text.length + 1);
  const end = Math.min(text.length, at + e.length);
  switch (e.kind) {
    case "insert":
      return text.slice(0, at) + e.text + text.slice(at);
    case "delete":
      return text.slice(0, at) + text.slice(end);
    case "replace":
      return text.slice(0, at) + e.text + text.slice(end);
    default:
      return text.slice(0, end) + text.slice(at, end) + text.slice(end);
  }
}

/** A seed with a few edits of its text. */
export function editedText(seeds: readonly string[]): fc.Arbitrary<string> {
  return fc.tuple(fc.constantFrom(...seeds), fc.array(edit, { minLength: 1, maxLength: 8 }))
    .map(([seed, edits]) => edits.reduce(applyEdit, seed));
}

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/** Values that sit on the edges of what the specification permits. */
const edgeValue: fc.Arbitrary<Json> = fc.oneof(
  fc.constantFrom<Json>(
    null, true, false, 0, -1, 1, 100, 101, 9007199254740991, -9007199254740991, 9007199254740992, 0.5, "", "*", "read",
    "unlock", "light", "lock", "other", "paperless:document", "Europe/Berlin", "00:00-00:00", "22:00-06:00", "PT9S", "PT1H",
    "PT1H1S", "2026-10-12T19:00:00+02:00", "2026-10-12T19:00:00-00:00", "0000-01-01T00:00:00Z", "a b", "x".repeat(65),
    "‮", "\ud800", [], {},
  ),
  fc.jsonValue({ maxDepth: 2 }) as fc.Arbitrary<Json>,
);

/** The places in a JSON value: the containers with a key or index each. */
function places(value: Json, out: { parent: Json[] | { [key: string]: Json }; key: string | number }[] = []) {
  if (Array.isArray(value)) {
    value.forEach((child, i) => {
      out.push({ parent: value, key: i });
      places(child, out);
    });
  } else if (value !== null && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      out.push({ parent: value, key });
      places(child, out);
    }
  }
  return out;
}

const change = fc.record({ place: fc.nat(), kind: fc.constantFrom("set", "delete", "add"), value: edgeValue, key: fc.oneof(fc.constantFrom(...TOKENS), anyText(8)) });

function parsed(text: string): Json[] {
  try {
    return [JSON.parse(text) as Json];
  } catch {
    return [];
  }
}

/** A seed JSON value with a few of its members changed, removed or added, as text; seeds that are no JSON are left out. */
export function editedJson(seeds: readonly string[]): fc.Arbitrary<string> {
  const values = seeds.flatMap(parsed);
  return fc.tuple(fc.constantFrom(...values), fc.array(change, { minLength: 1, maxLength: 4 })).map(([seed, changes]) => {
    const copy = structuredClone(seed);
    for (const c of changes) {
      const all = places(copy);
      if (all.length === 0) break;
      const { parent, key } = all[c.place % all.length]!;
      if (Array.isArray(parent)) {
        const i = key as number;
        if (c.kind === "set") parent[i] = c.value;
        else if (c.kind === "delete") parent.splice(i, 1);
        else parent.splice(i, 0, c.value);
      } else if (c.kind === "set") {
        parent[key as string] = c.value;
      } else if (c.kind === "delete") {
        delete parent[key as string];
      } else {
        Object.defineProperty(parent, c.key, { value: c.value, enumerable: true, writable: true, configurable: true });
      }
    }
    return JSON.stringify(copy);
  });
}

/** Text from the seeds, edited, with members changed, or arbitrary. */
export function jsonInput(seeds: readonly string[]): fc.Arbitrary<string> {
  return fc.oneof(
    { arbitrary: editedJson(seeds), weight: 4 },
    { arbitrary: editedText(seeds), weight: 4 },
    { arbitrary: fc.json({ maxDepth: 4 }), weight: 1 },
    { arbitrary: anyText(256), weight: 1 },
  );
}
