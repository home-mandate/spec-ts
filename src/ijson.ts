// SPDX-License-Identifier: Apache-2.0

import { exactNumber } from "./number.ts";

// A strict JSON parser for I-JSON (RFC 7493): exactly one value, no duplicate keys, no
// lone surrogates, no noncharacters, and no number with more precision than floating point
// keeps (a fraction it would round to an integer). JSON.parse silently keeps the last of
// two equal keys, so it cannot be used for mandates and audit entries.

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export class JsonError extends Error {}

const MAX_DEPTH = 32;

const NONCHARACTER = /[\uFDD0-\uFDEF\uFFFE\uFFFF\u{1FFFE}\u{1FFFF}\u{2FFFE}\u{2FFFF}\u{3FFFE}\u{3FFFF}\u{4FFFE}\u{4FFFF}\u{5FFFE}\u{5FFFF}\u{6FFFE}\u{6FFFF}\u{7FFFE}\u{7FFFF}\u{8FFFE}\u{8FFFF}\u{9FFFE}\u{9FFFF}\u{AFFFE}\u{AFFFF}\u{BFFFE}\u{BFFFF}\u{CFFFE}\u{CFFFF}\u{DFFFE}\u{DFFFF}\u{EFFFE}\u{EFFFF}\u{FFFFE}\u{FFFFF}\u{10FFFE}\u{10FFFF}]/u;

const NUMBER = /-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/y;

export function parseJson(text: string): Json {
  return parse(text, false);
}

/**
 * parseJson for what was written before the rule was enforced: it tolerates the deviations
 * listed in data/corrections-v0.json (SPEC-v0 section 14, Correction) and nothing else.
 * Audit verification and the attribution of a stored document use it. A key set, which is
 * no format of the specification, can be read with it too, before parseJwks.
 */
export function parseRecorded(text: string): Json {
  return parse(text, true);
}

function parse(text: string, recorded: boolean): Json {
  const p = new Parser(text, recorded);
  p.space();
  const value = p.value(0);
  p.space();
  if (p.pos !== text.length) throw new JsonError("more than one JSON value");
  return value;
}

class Parser {
  pos = 0;
  private readonly text: string;
  private readonly recorded: boolean;

  constructor(text: string, recorded: boolean) {
    this.text = text;
    this.recorded = recorded;
  }

  space(): void {
    while (this.pos < this.text.length && " \t\n\r".includes(this.text[this.pos]!)) this.pos++;
  }

  value(depth: number): Json {
    if (depth > MAX_DEPTH) throw new JsonError("nesting too deep");
    const c = this.text[this.pos];
    if (c === "{") return this.object(depth);
    if (c === "[") return this.array(depth);
    if (c === '"') return this.string();
    if (c === "t") return this.literal("true", true);
    if (c === "f") return this.literal("false", false);
    if (c === "n") return this.literal("null", null);
    return this.number();
  }

  private literal<T extends Json>(word: string, value: T): T {
    if (!this.text.startsWith(word, this.pos)) throw new JsonError("unexpected token");
    this.pos += word.length;
    return value;
  }

  private object(depth: number): Json {
    const out: { [key: string]: Json } = Object.create(null);
    this.pos++;
    this.space();
    if (this.text[this.pos] === "}") {
      this.pos++;
      return out;
    }
    for (;;) {
      this.space();
      if (this.text[this.pos] !== '"') throw new JsonError("expected a key");
      const key = this.string();
      if (Object.hasOwn(out, key)) throw new JsonError(`duplicate key ${JSON.stringify(key)}`);
      this.space();
      if (this.text[this.pos] !== ":") throw new JsonError("expected ':'");
      this.pos++;
      this.space();
      out[key] = this.value(depth + 1);
      this.space();
      const c = this.text[this.pos++];
      if (c === "}") return out;
      if (c !== ",") throw new JsonError("expected ',' or '}'");
    }
  }

  private array(depth: number): Json {
    const out: Json[] = [];
    this.pos++;
    this.space();
    if (this.text[this.pos] === "]") {
      this.pos++;
      return out;
    }
    for (;;) {
      this.space();
      out.push(this.value(depth + 1));
      this.space();
      const c = this.text[this.pos++];
      if (c === "]") return out;
      if (c !== ",") throw new JsonError("expected ',' or ']'");
    }
  }

  private string(): string {
    let out = "";
    this.pos++;
    for (;;) {
      if (this.pos >= this.text.length) throw new JsonError("unterminated string");
      const c = this.text[this.pos++]!;
      if (c === '"') break;
      if (c < " ") throw new JsonError("control character in string");
      if (c !== "\\") {
        out += c;
        continue;
      }
      const e = this.text[this.pos++];
      const simple: Record<string, string> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
      if (e !== undefined && e in simple) {
        out += simple[e];
      } else if (e === "u") {
        const hex = this.text.slice(this.pos, this.pos + 4);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new JsonError("invalid \\u escape");
        out += String.fromCharCode(parseInt(hex, 16));
        this.pos += 4;
      } else {
        throw new JsonError("invalid escape");
      }
    }
    if (!out.isWellFormed()) throw new JsonError("lone surrogate");
    if (!this.recorded && NONCHARACTER.test(out)) throw new JsonError("noncharacter");
    return out;
  }

  private number(): number {
    NUMBER.lastIndex = this.pos;
    const m = NUMBER.exec(this.text);
    if (!m) throw new JsonError("unexpected token");
    this.pos += m[0].length;
    const n = exactNumber(m[0]);
    if (Number.isNaN(n)) throw new JsonError("a fraction that floating point would round to an integer");
    if (!Number.isFinite(n)) throw new JsonError("number out of range");
    return n;
  }
}

export function isObject(v: Json | undefined): v is { [key: string]: Json } {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Length of the text in UTF-8 bytes; a lone surrogate counts as its replacement character (3 bytes). */
export function utf8Length(text: string): number {
  let bytes = 0;
  for (const c of text) {
    const code = c.codePointAt(0)!;
    bytes += code < 0x80 ? 1 : code < 0x800 ? 2 : code < 0x10000 ? 3 : 4;
  }
  return bytes;
}
