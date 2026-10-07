// SPDX-License-Identifier: Apache-2.0

// The SHA-256 of src/sha256.ts against the test vectors of FIPS 180-4 (NIST CSRC examples)
// and against node:crypto for every message length across the padding boundaries.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { sha256Hex } from "../src/sha256.ts";

const ascii = (text: string) => new TextEncoder().encode(text);

test("SHA-256 test vectors", () => {
  const vectors: [Uint8Array, string][] = [
    [ascii(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    [ascii("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"],
    [ascii("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"],
    [
      ascii("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
      "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
    ],
    [new Uint8Array(1_000_000).fill(0x61), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"],
  ];
  for (const [message, expected] of vectors) assert.equal(sha256Hex(message), expected, `length ${message.length}`);
});

test("SHA-256 agrees with node:crypto for lengths 0 to 300", () => {
  for (let length = 0; length <= 300; length++) {
    const message = Uint8Array.from({ length }, (_, i) => (i * 131 + length * 7) & 0xff);
    assert.equal(sha256Hex(message), createHash("sha256").update(message).digest("hex"), `length ${length}`);
  }
});
