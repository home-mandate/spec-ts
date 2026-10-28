// SPDX-License-Identifier: Apache-2.0

// Mirrors FuzzParse of the Go reference: whatever text arrives, parseMandate returns a
// mandate or throws MandateError, accepts only well-formed Unicode JSON text of at most
// 256 KiB, and is deterministic.
import assert from "node:assert/strict";
import { MandateError, parseMandate, tryParseMandate, type Mandate } from "../../src/mandate.ts";
import { utf8Length } from "../../src/ijson.ts";
import { fuzz, jsonInput } from "./fuzz.ts";
import { invalidMandates, shippedMandates } from "./seeds.ts";

const MAX_BYTES = 256 * 1024;

const examples = [
  ...shippedMandates,
  '{"a":1,"a":2}',
  '"\\ud800"',
  "[".repeat(34) + "]".repeat(34),
];

fuzz("parse", jsonInput([...shippedMandates, ...invalidMandates]), (text) => {
  let mandate: Mandate | null = null;
  try {
    mandate = parseMandate(text);
  } catch (e) {
    if (!(e instanceof MandateError)) throw e;
  }
  assert.equal(tryParseMandate(text)?.digest, mandate?.digest, "parseMandate is not deterministic");
  if (mandate === null) return;
  assert.ok(text.isWellFormed(), "accepted text that is not well-formed Unicode");
  assert.doesNotThrow(() => JSON.parse(text), "accepted text that is not JSON");
  assert.ok(utf8Length(text) <= MAX_BYTES, "accepted more than 256 KiB");
  assert.match(mandate.digest, /^sha256:[0-9a-f]{64}$/);
}, [...examples, ...invalidMandates]);

