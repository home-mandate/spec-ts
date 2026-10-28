// SPDX-License-Identifier: Apache-2.0

// Mirrors FuzzServe of the Go harness: whatever line arrives on the test interface
// (SPEC-v0 section 10.2), the harness answers with one line of JSON and never throws.
import assert from "node:assert/strict";
import fc from "fast-check";
import { respond } from "../../src/harness.ts";
import { anyText, editedJson, fuzz, jsonInput } from "./fuzz.ts";
import { shippedMandates } from "./seeds.ts";

const SEEDS = [
  '{"op":"capabilities"}',
  '{"op":"validate","mandate":"{}"}',
  '{"op":"evaluate","mandate":"{}","request":{"resource":{"entity_id":"a","category":"light"},"action":"read","time":"2026-10-12T19:00:00+02:00","parameters":{"x":1e99}}}',
  '{"op":"evaluate","mandate":"{}","request":{"resource":{"entity_id":"a","category":"climate"},"action":"set_mode","time":"2026-10-12T19:00:00+02:00","parameters":{"mode":"heat","x":true}}}',
  '{"op":"select","mandates":[{"mandate":"x"}],"subject":{"client_id":"a","principal":"b"},"request":{"time":"x"}}',
  '{"op":"verify_audit","jsonl":"{}\\n{}","keys":{"keys":[]}}',
  '{"op":"verify_signed","jws":"a.b.c","keys":{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}}',
  '{"op":"succession","stored":"{}","offered":"{}"}',
  '{"op":"entry_digest","entry":"{\\"seq\\":1}"}',
  "nope",
];

// Requests with a shipped mandate, so that evaluation and selection get past validation.
const withMandate = shippedMandates.flatMap((mandate) => [
  JSON.stringify({ op: "validate", mandate }),
  JSON.stringify({
    op: "evaluate", mandate,
    request: { resource: { entity_id: "lock.haustuer", category: "lock", areas: ["flur"] }, action: "unlock", time: "2026-10-12T19:00:00+02:00", timezone: "Europe/Berlin" },
  }),
  JSON.stringify({ op: "succession", stored: mandate, offered: mandate }),
]);

const input = fc.oneof(
  { arbitrary: jsonInput(SEEDS), weight: 4 },
  { arbitrary: editedJson(withMandate), weight: 2 },
  { arbitrary: anyText(128), weight: 1 },
).filter((line) => line !== "" && !/[\n\r]/.test(line));

fuzz("harness", input, (line) => {
  const response = respond(line);
  assert.ok(!/[\n\r]/.test(response), `more than one response line for ${JSON.stringify(line)}`);
  const value: unknown = JSON.parse(response);
  assert.ok(typeof value === "object" && value !== null && !Array.isArray(value), `response is no JSON object: ${response}`);
}, SEEDS);
