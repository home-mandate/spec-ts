// SPDX-License-Identifier: Apache-2.0

// Mirrors FuzzValue of the Go reference: a valid parameter value survives JSON unchanged,
// and exactNumber agrees with exact arithmetic on integers (BigInt) about which JSON
// numbers denote an integer (SPEC-v0 section 4.5).
import assert from "node:assert/strict";
import fc from "fast-check";
import { parseJson } from "../../src/ijson.ts";
import { exactNumber } from "../../src/number.ts";
import { validValue } from "../../src/parameters.ts";
import { anyText, editedText, fuzz } from "./fuzz.ts";

const SEEDS = [
  "50", "-0", "5e1", "2150.00e0", "1e-400", "9007199254740991", "9007199254740992", "50.00000000000000000001",
  '"heat"', '"fan only"', '""', "true", "null", "1e99999",
];

const JSON_NUMBER = /^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/;

/** Exponents longer than this are out of scope, as in the Go target: 10^exponent would be materialized. */
const MAX_EXPONENT_DIGITS = 4;

/** The exact value of the text of a JSON number if it is an integer, null for a fraction, undefined if out of scope. */
function exactInteger(text: string): bigint | null | undefined {
  const m = JSON_NUMBER.exec(text);
  if (!m) return undefined;
  const [, sign, whole, fraction = "", exponentText = "0"] = m;
  if (exponentText.replace(/^[+-]/, "").replace(/^0+/, "").length > MAX_EXPONENT_DIGITS) return undefined;
  let digits = BigInt(whole! + fraction);
  let exponent = Number(exponentText) - fraction.length;
  if (digits === 0n) return 0n;
  while (exponent < 0 && digits % 10n === 0n) {
    digits /= 10n;
    exponent++;
  }
  if (exponent < 0) return null;
  const value = digits * 10n ** BigInt(exponent);
  return sign === "-" ? -value : value;
}

const digits = (min: number, max: number) => fc.string({ unit: fc.constantFrom(..."0123456789"), minLength: min, maxLength: max });

/** The text of a JSON number, with long fractions, trailing zeros and large exponents. */
const numberText = fc.tuple(
  fc.constantFrom("", "-"),
  fc.oneof(fc.constant("0"), fc.tuple(fc.constantFrom(..."123456789"), digits(0, 20)).map(([a, b]) => a + b)),
  fc.option(digits(1, 30), { nil: undefined }),
  fc.option(fc.tuple(fc.constantFrom("e", "E"), fc.constantFrom("", "+", "-"), digits(1, 6)).map((p) => p.join("")), { nil: undefined }),
).map(([sign, whole, fraction, exponent]) => sign + whole + (fraction === undefined ? "" : "." + fraction) + (exponent ?? ""));

const input = fc.oneof(numberText, editedText(SEEDS), anyText(32));

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

fuzz("value", input, (text) => {
  let value: unknown;
  try {
    value = parseJson(text);
  } catch {
    value = undefined;
  }
  if (validValue(value)) {
    const again = parseJson(JSON.stringify(value));
    assert.ok(again === value, `round trip ${text} -> ${JSON.stringify(value)} -> ${JSON.stringify(again)}`);
  }
  const got = exactNumber(text);
  const want = exactInteger(text);
  if (want === undefined) return;
  if (want === null) {
    assert.ok(!Number.isInteger(got), `exactNumber(${text}) = ${got}, but it is a fraction`);
    return;
  }
  assert.equal(got, Number(text), `exactNumber(${text}) = ${got}, but it is the integer ${want}`);
  const magnitude = want < 0n ? -want : want;
  if (magnitude <= MAX_SAFE) assert.ok(BigInt(got) === want, `exactNumber(${text}) = ${got}, want ${want}`);
}, SEEDS);
