// SPDX-License-Identifier: Apache-2.0

// The vocabulary is looked up by names that come from mandates and requests: names of
// Object.prototype must not be found in it.
import assert from "node:assert/strict";
import { test } from "node:test";
import { evaluate, parseMandate } from "../src/index.ts";
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
