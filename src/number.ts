// SPDX-License-Identifier: Apache-2.0

// Numbers read by their exact decimal value (SPEC-v0 section 4.5): mandates, requests and
// audit entries contain no fractions, and a fraction is never taken for an integer because
// floating point rounds it to one (50.00000000000000000001, 1e-400).

const JSON_NUMBER = /^-?(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/;

/** Whether the text of a JSON number (RFC 8259) denotes an integer, decided without rounding. */
function denotesInteger(text: string): boolean {
  const m = JSON_NUMBER.exec(text);
  if (!m) return false;
  const fraction = m[2] ?? "";
  const digits = (m[1]! + fraction).replace(/^0+/, "");
  if (digits === "") return true;
  const trailingZeros = digits.length - digits.replace(/0+$/, "").length;
  // value = digits × 10^(exponent − length of fraction); trailing zeros move into the
  // exponent. An exponent too long for a double is ±Infinity, which compares correctly.
  return Number(m[3] ?? 0) + trailingZeros - fraction.length >= 0;
}

/**
 * The value of the text of a JSON number: as floating point, except that a fraction that
 * floating point would round to an integer yields NaN, so that it is never accepted as an
 * integer. Integers of any spelling (20, 20.0, 2e1) keep their value.
 */
export function exactNumber(text: string): number {
  const value = Number(text);
  return Number.isInteger(value) && !denotesInteger(text) ? NaN : value;
}
