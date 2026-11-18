// SPDX-License-Identifier: Apache-2.0

// The one form of a public origin (SPEC-v0 section 11.7 item 1), as an audit verifier checks
// it in config.changed (section 9.4 condition 1): without IDNA, so that two verifiers agree.
// The cases are in conformance/origin-v0.json.

const MAX_HOST_LENGTH = 253;
const MAX_LABEL_LENGTH = 63;
const DEFAULT_PORT = 443;
const MAX_PORT = 65535;
const ACE_PREFIX = "xn--";
/** U+00A0, the first code point after the C1 controls. */
const FIRST_NON_CONTROL = 0xa0;

/** Whether value is a public origin in the one form of SPEC-v0 section 11.7 item 1. */
export function validPublicOrigin(value: string): boolean {
  if (!value.startsWith("https://")) return false;
  const rest = value.slice("https://".length);
  if (/[/?#@\\]/.test(rest)) return false;
  const colon = rest.indexOf(":");
  if (colon >= 0 && !validPort(rest.slice(colon + 1))) return false;
  return validHost(colon >= 0 ? rest.slice(0, colon) : rest);
}

/** Decimal digits without a leading zero, 1 to 65535, and not the default port. */
function validPort(port: string): boolean {
  if (!/^[1-9][0-9]*$/.test(port)) return false;
  const n = Number(port);
  return n <= MAX_PORT && n !== DEFAULT_PORT;
}

/**
 * At least two labels of letters, digits and hyphens in lower case, neither beginning nor
 * ending with a hyphen; the last label contains a letter and is not 0x followed by hexadecimal
 * digits, so that no URL parser reads the host as an IPv4 address; and every A-label survives
 * the Punycode round trip.
 */
function validHost(host: string): boolean {
  if (host === "" || host.length > MAX_HOST_LENGTH) return false;
  const labels = host.split(".");
  if (labels.length < 2 || !labels.every((l) => validLabel(l) && roundTrips(l))) return false;
  return !looksLikeANumber(labels[labels.length - 1]!);
}

function validLabel(label: string): boolean {
  return label.length <= MAX_LABEL_LENGTH && /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(label);
}

function looksLikeANumber(last: string): boolean {
  return !/[a-z]/.test(last) || /^0x[0-9a-f]*$/.test(last);
}

/**
 * Whether a label that begins with xn-- decodes with Punycode (RFC 3492) to a label with a
 * character outside ASCII and none from U+0080 to U+009F, and encodes back to itself.
 */
function roundTrips(label: string): boolean {
  if (!label.startsWith(ACE_PREFIX)) return true;
  const decoded = punycodeDecode(label.slice(ACE_PREFIX.length));
  if (decoded === null || !decoded.some((c) => c > 0x7f) || decoded.some((c) => c > 0x7f && c < FIRST_NON_CONTROL)) return false;
  return ACE_PREFIX + punycodeEncode(decoded) === label;
}

// RFC 3492 section 5.
const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 0x80;
const MAX_INT32 = 0x7fffffff;
const MAX_CODE_POINT = 0x10ffff;
const MAX_DECODED = 1024;

function adapt(delta: number, points: number, first: boolean): number {
  let d = Math.floor(first ? delta / DAMP : delta / 2);
  d += Math.floor(d / points);
  let k = 0;
  while (d > ((BASE - TMIN) * TMAX) >> 1) {
    d = Math.floor(d / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * d) / (d + SKEW));
}

function threshold(k: number, bias: number): number {
  return k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
}

function digitOf(c: string): number {
  const code = c.charCodeAt(0);
  if (code >= 0x30 && code <= 0x39) return code - 0x30 + 26;
  if (code >= 0x41 && code <= 0x5a) return code - 0x41;
  if (code >= 0x61 && code <= 0x7a) return code - 0x61;
  return -1;
}

/**
 * The code points of a Punycode label without its prefix; null if it does not decode. A
 * surrogate is no code point of a string, so a label that decodes to one does not round-trip.
 */
function punycodeDecode(encoded: string): number[] | null {
  if (encoded === "") return [];
  const delimiter = encoded.lastIndexOf("-");
  if (delimiter === 0) return null;
  if (delimiter === encoded.length - 1) return [...encoded.slice(0, -1)].map((c) => c.codePointAt(0)!);
  const output = delimiter > 0 ? [...encoded.slice(0, delimiter)].map((c) => c.codePointAt(0)!) : [];
  let pos = delimiter + 1;
  let [i, n, bias] = [0, INITIAL_N, INITIAL_BIAS];
  while (pos < encoded.length) {
    const oldI = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (pos === encoded.length) return null;
      const digit = digitOf(encoded[pos++]!);
      if (digit < 0) return null;
      i += digit * w;
      if (i > MAX_INT32) return null;
      const t = threshold(k, bias);
      if (digit < t) break;
      w *= BASE - t;
      if (w > MAX_INT32) return null;
    }
    if (output.length >= MAX_DECODED) return null;
    const x = output.length + 1;
    bias = adapt(i - oldI, x, oldI === 0);
    n += Math.floor(i / x);
    i %= x;
    if (n > MAX_CODE_POINT || (n >= 0xd800 && n <= 0xdfff)) return null;
    output.splice(i, 0, n);
    i++;
  }
  return output;
}

function digitChar(d: number): string {
  return String.fromCharCode(d < 26 ? 0x61 + d : 0x30 + d - 26);
}

/** The Punycode of code points, without the prefix (RFC 3492 section 6.3). */
function punycodeEncode(input: readonly number[]): string {
  let output = input.filter((c) => c < 0x80).map((c) => String.fromCodePoint(c)).join("");
  const basic = output.length;
  let handled = basic;
  if (basic > 0) output += "-";
  let [n, delta, bias] = [INITIAL_N, 0, INITIAL_BIAS];
  while (handled < input.length) {
    const m = Math.min(...input.filter((c) => c >= n));
    delta += (m - n) * (handled + 1);
    n = m;
    for (const c of input) {
      if (c < n) delta++;
      if (c !== n) continue;
      let q = delta;
      for (let k = BASE; ; k += BASE) {
        const t = threshold(k, bias);
        if (q < t) break;
        output += digitChar(t + ((q - t) % (BASE - t)));
        q = Math.floor((q - t) / (BASE - t));
      }
      output += digitChar(q);
      bias = adapt(delta, handled + 1, handled === basic);
      delta = 0;
      handled++;
    }
    delta++;
    n++;
  }
  return output;
}
