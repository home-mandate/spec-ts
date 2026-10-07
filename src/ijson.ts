// SPDX-License-Identifier: Apache-2.0

// A strict JSON parser for I-JSON (RFC 7493): exactly one value, no duplicate keys, no
// lone surrogates. JSON.parse silently keeps the last of two equal keys, so it cannot
// be used for mandates and audit entries.

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export class JsonError extends Error {}

const MAX_DEPTH = 32;

export function parseJson(text: string): Json {
  const p = new Parser(text);
  p.space();
  const value = p.value(0);
  p.space();
  if (p.pos !== text.length) throw new JsonError("more than one JSON value");
  return value;
}

class Parser {
  pos = 0;
  private readonly text: string;

  constructor(text: string) {
    this.text = text;
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
    return out;
  }

  private number(): number {
    const m = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(this.text.slice(this.pos, this.pos + 400));
    if (!m) throw new JsonError("unexpected token");
    this.pos += m[0].length;
    const n = Number(m[0]);
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
