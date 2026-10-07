// SPDX-License-Identifier: Apache-2.0

// JSON Canonicalization Scheme (RFC 8785) for the documents of mandate-spec, which
// contain only integers (SPEC-v0 section 3.2), and the digests built on it.
import { type Json, JsonError } from "./ijson.ts";
import { sha256Hex } from "./sha256.ts";

export function canonicalize(value: Json): string {
  if (value === null || typeof value === "boolean") return String(value);
  if (typeof value === "number") {
    if (!Number.isInteger(value) || Math.abs(value) >= 2 ** 53) throw new JsonError("unsupported number");
    return String(value === 0 ? 0 : value);
  }
  if (typeof value === "string") return canonicalString(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  // The default sort of strings compares UTF-16 code units, as RFC 8785 requires.
  const keys = Object.keys(value).sort();
  return "{" + keys.map((k) => canonicalString(k) + ":" + canonicalize(value[k]!)).join(",") + "}";
}

function canonicalString(s: string): string {
  let out = '"';
  for (const c of s) {
    const code = c.codePointAt(0)!;
    if (c === '"') out += '\\"';
    else if (c === "\\") out += "\\\\";
    else if (c === "\b") out += "\\b";
    else if (c === "\f") out += "\\f";
    else if (c === "\n") out += "\\n";
    else if (c === "\r") out += "\\r";
    else if (c === "\t") out += "\\t";
    else if (code < 0x20) out += "\\u" + code.toString(16).padStart(4, "0");
    else out += c;
  }
  return out + '"';
}

export function digest(value: Json): string {
  return "sha256:" + sha256Hex(new TextEncoder().encode(canonicalize(value)));
}
