// SPDX-License-Identifier: Apache-2.0

// Mirrors FuzzEvaluate of the Go reference: requests against the shipped mandates (and an
// invalid one) always give a result that keeps the invariants of the evaluation rule
// (SPEC-v0 section 4), and the same result again.
import assert from "node:assert/strict";
import fc from "fast-check";
import { evaluate, type Request, type Result } from "../../src/evaluate.ts";
import type { Mandate } from "../../src/mandate.ts";
import { anyText, fuzz } from "./fuzz.ts";
import { parsedMandates } from "./seeds.ts";

// Vocabulary v0 as the table in SPEC-v0 section 5 lists it, independently of the
// implementation: the actions of each category, and the critical ones.
const VOCABULARY: Readonly<Record<string, { actions: readonly string[]; critical: readonly string[] }>> = {
  light: { actions: ["read", "turn_on", "turn_off", "set"], critical: [] },
  switch: { actions: ["read", "turn_on", "turn_off"], critical: [] },
  climate: { actions: ["read", "set_temperature", "set_mode"], critical: [] },
  cover: { actions: ["read", "open", "close", "stop", "set_position"], critical: [] },
  gate: { actions: ["read", "open", "close"], critical: ["open"] },
  lock: { actions: ["read", "lock", "unlock", "open"], critical: ["unlock", "open"] },
  alarm: { actions: ["read", "arm", "disarm"], critical: ["disarm"] },
  camera: { actions: ["read", "snapshot"], critical: ["snapshot"] },
  media: { actions: ["read", "turn_on", "turn_off", "play", "pause", "set_volume"], critical: [] },
  sensor: { actions: ["read"], critical: [] },
  scene: { actions: ["read", "activate"], critical: ["activate"] },
  script: { actions: ["read", "run"], critical: ["run"] },
  other: { actions: ["read", "set"], critical: ["set"] },
};

function inVocabulary(category: string | undefined, action: string): { known: boolean; critical: boolean } {
  const entry = category !== undefined && Object.hasOwn(VOCABULARY, category) ? VOCABULARY[category]! : undefined;
  return { known: entry?.actions.includes(action) ?? false, critical: entry?.critical.includes(action) ?? false };
}

/** 1 to 64 printable ASCII characters without space (SPEC-v0 section 3.4). */
function identifier(s: string): boolean {
  return /^[!-~]{1,64}$/.test(s);
}

const mandates: readonly (Mandate | null)[] = [...parsedMandates, null];

const ACTIONS = [...new Set(Object.values(VOCABULARY).flatMap((c) => c.actions))];
const CATEGORIES = Object.keys(VOCABULARY);
const ODD_NAMES = ["", "*", "Light", "paperless:document", "__proto__", "constructor", "toString", "hasOwnProperty"];
// Entities and areas the rules of the shipped mandates name, so that requests match rules.
const named = (key: "entity_id" | "area") => parsedMandates.flatMap((m) => m.rules.flatMap((r) => (r.resource[key] === undefined ? [] : [r.resource[key]])));
const ENTITIES = [...new Set(["lock.haustuer", "light.flur", "cover.terrasse", "thermostat-1", ...named("entity_id")])];
const AREAS = [...new Set(["flur", "erdgeschoss", "home", "terrasse", ...named("area")])];
const ODD_IDENTIFIERS = ["", "a b", "x".repeat(65), "x".repeat(256), "\u00e4"];

/** Mostly one of the known values, sometimes an odd or arbitrary one. */
const mostly = <T>(known: fc.Arbitrary<T>, odd: fc.Arbitrary<T>) => fc.oneof({ arbitrary: known, weight: 12 }, { arbitrary: odd, weight: 1 });
const identifierFrom = (known: readonly string[]) => mostly(fc.constantFrom(...known), fc.oneof(fc.constantFrom(...ODD_IDENTIFIERS), anyText(16)));
const ZONES = ["Europe/Berlin", "America/New_York", "UTC", "Etc/GMT+5", "europe/berlin", "Local", "", "Europe/Nowhere"];

const name = (known: readonly string[]) => mostly(fc.constantFrom(...known), fc.oneof(fc.constantFrom(...ODD_NAMES), anyText(16)));

/** Seconds from 0001-01-01 to 9999-12-31, the years a timestamp can have. */
const MIN_UNIX = -62135596800;
const MAX_UNIX = 253402300799;
const NEAR = { min: 1767225600, max: 1830297600 }; // 2026 to 2027, where the shipped mandates are valid

function timestamp(unix: number, offsetMinutes: number, fraction: string): string {
  const local = new Date((unix + offsetMinutes * 60) * 1000).toISOString().slice(0, 19);
  if (offsetMinutes === 0) return `${local}${fraction}Z`;
  const abs = Math.abs(offsetMinutes);
  const offset = `${offsetMinutes < 0 ? "-" : "+"}${String(Math.floor(abs / 60)).padStart(2, "0")}:${String(abs % 60).padStart(2, "0")}`;
  return `${local}${fraction}${offset}`;
}

const time = mostly(
  fc.tuple(
    fc.oneof({ weight: 4, arbitrary: fc.integer(NEAR) }, fc.integer({ min: MIN_UNIX + 86400, max: MAX_UNIX - 86400 })),
    fc.integer({ min: -720, max: 840 }),
    fc.constantFrom("", ".5", ".000000001", ".123456789"),
  ).map(([unix, offset, fraction]) => timestamp(unix, offset, fraction)),
  fc.oneof(fc.constantFrom("2026-10-12T19:00:00-00:00", "2026-02-30T12:00:00Z", "2026-10-12T24:00:00Z", "2026-10-12 19:00:00Z"), anyText(32)),
);

/** Parameter values as a caller may pass them: also NaN or a fraction, as exactNumber reads them. */
const parameterValue = mostly<number | string>(
  fc.oneof(
    fc.integer({ min: -10, max: 110 }),
    fc.integer({ min: 1500, max: 2500 }),
    fc.constantFrom("off", "auto", "cool", "heat", "emergency_heat", "precooling", "fan_only", "dry", "sleep"),
  ),
  fc.oneof(fc.constantFrom<number | string>(NaN, Infinity, 1.5, 9007199254740992, "fan only", "", "Heat"), fc.integer(), anyText(16)),
);

// Mostly an action of the category, sometimes any action or none of the vocabulary.
const PAIRS = Object.entries(VOCABULARY).flatMap(([category, c]) => c.actions.map((action) => [category, action] as const));
const categoryAndAction = mostly<readonly [string | undefined, string]>(
  fc.constantFrom(...PAIRS),
  fc.tuple(fc.option(name(CATEGORIES), { nil: undefined }), name(ACTIONS)),
);

const fields = fc.record({
  resource: fc.record({
    entity_id: identifierFrom(ENTITIES),
    areas: fc.option(mostly(fc.uniqueArray(fc.constantFrom(...AREAS), { maxLength: 4 }), fc.array(identifierFrom(AREAS), { maxLength: 18 })), { nil: undefined }),
    critical: fc.option(fc.boolean(), { nil: undefined }),
  }, { requiredKeys: ["entity_id"] }),
  parameters: fc.option(fc.oneof(
    parameterValue.map((v) => ({ mode: v, brightness: v })),
    fc.dictionary(fc.constantFrom("mode", "brightness", "temperature", "position", "volume", "x"), parameterValue, { maxKeys: 3 }),
  ), { nil: undefined }),
  time,
  timezone: fc.option(mostly(fc.constantFrom("Europe/Berlin", "America/New_York", "UTC"), fc.oneof(fc.constantFrom(...ZONES), anyText(16))), { nil: undefined }),
  revoked: fc.option(mostly(fc.constant(false), fc.constant(true)), { nil: undefined }),
}, { requiredKeys: ["resource", "time"] });

const request: fc.Arbitrary<Request> = fc.tuple(fields, categoryAndAction).map(([f, [category, action]]) => ({
  ...f,
  resource: category === undefined ? f.resource : { ...f.resource, category },
  action,
}));

fuzz("evaluate", fc.tuple(fc.nat({ max: mandates.length - 1 }), request), ([index, req]) => {
  const mandate = mandates[index]!;
  const got = evaluate(mandate, req);
  checkInvariants(mandate, req, got);
  assert.deepEqual(evaluate(mandate, req), got, "evaluate is not deterministic");
}, [
  [0, { resource: { entity_id: "lock.haustuer", category: "lock", areas: ["flur", "erdgeschoss", "home"] }, action: "unlock", time: "2026-10-04T08:20:00+02:00", timezone: "Europe/Berlin" }],
  [mandates.length - 1, { resource: { entity_id: "light.flur", category: "light", areas: ["flur"] }, action: "turn_on", time: "2026-10-04T08:20:00+02:00", revoked: true, parameters: { mode: 50, brightness: 50 } }],
  [0, { resource: { entity_id: "x", category: "paperless:document" }, action: "*", time: "1970-01-01T00:00:00-12:00", timezone: "Local", parameters: { mode: "fan only", brightness: "fan only" } }],
  [0, { resource: { entity_id: "lock.haustuer", category: "lock", areas: "abcdefghijklmnopq".split("") }, action: "unlock", time: "2026-10-04T08:20:00+01:00" }],
  [0, { resource: { entity_id: "thermostat-1", category: "climate" }, action: "set_mode", time: "2026-10-04T08:20:00+02:00", timezone: "Europe/Berlin", parameters: { mode: "auto", brightness: "auto" } }],
]);

function checkInvariants(mandate: Mandate | null, req: Request, got: Result): void {
  const where = `${JSON.stringify(req)} -> ${JSON.stringify(got)}`;
  assert.ok(["allow", "ask", "deny"].includes(got.decision), `unknown decision: ${where}`);
  const byRule = got.reason === "rule" || got.reason === "critical_demotion";
  assert.ok(byRule || got.decision === "deny", `reason ${got.reason} with decision ${got.decision}: ${where}`);
  assert.ok(got.reason !== "critical_demotion" || got.decision === "ask", `critical demotion without ask: ${where}`);
  assert.equal(byRule, got.rule_id !== undefined && got.rule_id !== "", `rule id with reason ${got.reason}: ${where}`);
  assert.equal(got.decision === "ask", got.approval !== undefined, `approval with decision ${got.decision}: ${where}`);
  const { known, critical } = inVocabulary(req.resource.category, req.action);
  if (mandate === null || req.revoked === true || !known) assert.equal(got.decision, "deny", `unknown or revoked input was not denied: ${where}`);
  for (const value of Object.values(req.parameters ?? {})) {
    if (typeof value === "string" && !identifier(value)) {
      assert.ok(got.reason === "invalid_mandate" || got.reason === "invalid_request", `string parameter that is no identifier: ${where}`);
    }
  }
  if (got.enforced === false) {
    const byTheRules = got.reason === "no_match" || got.reason === "rule";
    const criticalAction = critical || (req.resource.critical === true && req.action !== "read");
    assert.ok(got.decision === "deny" && byTheRules && mandate !== null && !mandate.enforce && !criticalAction, `not enforced: ${where}`);
  }
  if (mandate === null) assert.equal(got.reason, "invalid_mandate", where);
  else assert.equal(got.mandate_digest, mandate.digest, where);
}
