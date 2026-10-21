// SPDX-License-Identifier: Apache-2.0

// Numbers are read by their exact decimal value (SPEC-v0 section 4.5): a fraction is never
// taken for an integer because floating point rounds it to one.
import assert from "node:assert/strict";
import { test } from "node:test";
import { exactNumber } from "../src/number.ts";
import { JsonError, parseJson } from "../src/ijson.ts";

test("integers keep their value in every spelling", () => {
  for (const [text, value] of [["20", 20], ["20.0", 20], ["2e1", 20], ["2.000E+1", 20], ["-0", -0], ["0e-5", 0], ["1.0e2", 100], ["5e1", 50], ["1000e-3", 1]] as const) {
    assert.equal(exactNumber(text), value, text);
  }
});

test("fractions stay fractions", () => {
  assert.equal(exactNumber("1.5"), 1.5);
  assert.equal(exactNumber("-2.25e1"), -22.5);
});

test("a fraction that floating point rounds to an integer is no number of the document", () => {
  for (const text of ["50.00000000000000000001", "1e-400", "-1e-400", "9007199254740990.5", "123456789e-1000000000000"]) {
    assert.ok(Number.isNaN(exactNumber(text)), text);
  }
});

test("large integers are read as floating point, so that range checks reject them", () => {
  assert.equal(exactNumber("9007199254740993"), 9007199254740992);
  assert.equal(exactNumber("1e400"), Infinity);
});

test("the I-JSON parser rejects a fraction that would round to an integer", () => {
  assert.throws(() => parseJson('{"min": 1e-400}'), JsonError);
  assert.throws(() => parseJson("[50.00000000000000000001]"), JsonError);
  assert.deepEqual(parseJson("[5e1, 1.0e2, 0.5]"), [50, 100, 0.5]);
});
