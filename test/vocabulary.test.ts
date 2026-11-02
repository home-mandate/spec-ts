// SPDX-License-Identifier: Apache-2.0

// The vocabulary is looked up by names that come from mandates and requests: names of
// Object.prototype must not be found in it.
import assert from "node:assert/strict";
import { test } from "node:test";
import { evaluate, needsConfirmation, parseMandate } from "../src/index.ts";
import { parseTimestamp } from "../src/time.ts";
import { specFile } from "../src/spec.ts";

const TIME = "2026-10-12T19:00:00+02:00";

test("names of Object.prototype are neither categories nor actions", () => {
  const mandate = JSON.parse(specFile("examples/voice-assistant.json")) as { rules: object[] };
  const valid = parseMandate(JSON.stringify(mandate));
  for (const action of ["constructor", "toString", "hasOwnProperty", "__proto__"]) {
    const result = evaluate(valid, { resource: { entity_id: "lock.front", category: "lock" }, action, time: TIME });
    assert.equal(result.reason, "unknown_action", action);
  }
  for (const category of ["constructor", "__proto__", "toString"]) {
    const result = evaluate(valid, { resource: { entity_id: "x", category }, action: "read", time: TIME });
    assert.equal(result.reason, "unknown_category", category);
  }
  mandate.rules.push({ id: "r-proto", resource: { category: "lock" }, actions: ["constructor"], decision: "allow" });
  assert.throws(() => parseMandate(JSON.stringify(mandate)), /action constructor not in the vocabulary/);
});

// A parameter name that matches the pattern but is a member of Object.prototype is not
// declared by an action without parameters, and never throws (SPEC-v0 section 4, step 0).
test("names of Object.prototype are no parameters", () => {
  const valid = parseMandate(specFile("examples/voice-assistant.json"));
  for (const name of ["constructor", "toString", "valueOf", "hasownproperty"]) {
    for (const value of ["x", 1]) {
      const request = { resource: { entity_id: "lock.front", category: "lock" }, action: "lock", time: TIME, parameters: { [name]: value } };
      assert.equal(evaluate(valid, request).reason, "invalid_request", `${name}: ${value}`);
    }
  }
});

// A predecessor in audit mode that is expired or not yet valid at the point in time is not
// in force: a successor in audit mode then enters audit mode and needs a confirmation
// (SPEC-v0 sections 3.5 and 11.6), as with the Go reference.
test("an expired predecessor in audit mode does not carry audit mode over", () => {
  const base = JSON.parse(specFile("examples/voice-assistant.json")) as Record<string, unknown>;
  const stored = parseMandate(JSON.stringify({ ...base, issuer: "https://issuer.example/m", version: 1, enforce: false, valid_from: "2026-01-01T00:00:00Z", expires: "2026-06-01T00:00:00Z" }));
  const offered = parseMandate(JSON.stringify({ ...base, issuer: "https://issuer.example/m", version: 2, enforce: false, valid_from: "2026-01-01T00:00:00Z", expires: "2026-06-01T00:00:00Z" }));
  assert.equal(needsConfirmation(stored, false, offered), false, "without a point in time the stored mandate counts as in force");
  assert.equal(needsConfirmation(stored, false, offered, parseTimestamp("2026-03-01T00:00:00Z")!), false, "in force at the time");
  assert.equal(needsConfirmation(stored, false, offered, parseTimestamp("2026-07-01T00:00:00Z")!), true, "expired at the time");
  assert.equal(needsConfirmation(stored, false, offered, parseTimestamp("2025-07-01T00:00:00Z")!), true, "not yet valid at the time");
  assert.equal(needsConfirmation(stored, true, offered), true, "revoked");
});
