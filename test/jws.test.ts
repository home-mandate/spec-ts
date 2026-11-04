// SPDX-License-Identifier: Apache-2.0

// Signed mandates (SPEC-v0 section 7.1): what a signed mandate carries, and that a key and
// a signature have exactly one form. The conformance cases cover the rest.
import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { test } from "node:test";
import { canonicalize, type Json, parseJwks, SignatureError, verifyDetached, verifySigned } from "../src/index.ts";
import { smallOrderEd25519 } from "../src/jws.ts";
import { specFile } from "../src/spec.ts";

const ISSUER = "https://issuer.example/mandates";
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const jwk = publicKey.export({ format: "jwk" }) as { kty: string; crv: string; x: string };
const KEYS: Json = { keys: [{ ...jwk, kid: "k1" }] };

/** The example mandate as a signed one: issuer, version, audience and expires added, then changed. */
function signed(change: (m: Record<string, Json>) => void): string {
  const mandate = JSON.parse(specFile("examples/voice-assistant.json")) as Record<string, Json>;
  Object.assign(mandate, { issuer: ISSUER, version: 1, audience: "https://gateway.example/home-mandate", expires: "2027-01-01T00:00:00Z" });
  change(mandate);
  const head = Buffer.from('{"alg":"EdDSA","kid":"k1"}').toString("base64url");
  const payload = Buffer.from(canonicalize(mandate)).toString("base64url");
  const signature = sign(null, Buffer.from(`${head}.${payload}`), privateKey).toString("base64url");
  return `${head}.${payload}.${signature}`;
}

test("a signed mandate with issuer, version, audience and expires verifies", () => {
  const mandate = verifySigned(signed(() => {}), ISSUER, parseJwks(KEYS));
  assert.equal(mandate.audience, "https://gateway.example/home-mandate");
  assert.ok(mandate.expires);
});

test("a signed mandate names its audience and expires", () => {
  for (const [member, why] of [["audience", /audience/], ["expires", /expires/]] as const) {
    const jws = signed((m) => delete m[member]);
    assert.throws(() => verifySigned(jws, ISSUER, parseJwks(KEYS)), (e: unknown) => e instanceof SignatureError && why.test(e.message), member);
  }
});

test("an Ed25519 public key that is not canonically encoded is no key", () => {
  // Every bit set: the y coordinate (without the sign bit) is 2^255 − 1, not below p = 2^255 − 19.
  const x = Buffer.alloc(32, 0xff).toString("base64url");
  assert.throws(() => parseJwks({ keys: [{ kty: "OKP", crv: "Ed25519", kid: "k2", x }] }), SignatureError);
  // A key of the wrong length, and a P-256 key without y, are no keys either.
  assert.throws(() => parseJwks({ keys: [{ kty: "OKP", crv: "Ed25519", kid: "k3", x: Buffer.alloc(31, 1).toString("base64url") }] }), SignatureError);
  assert.throws(() => parseJwks({ keys: [{ kty: "EC", crv: "P-256", kid: "k4", x: Buffer.alloc(32, 1).toString("base64url") }] }), SignatureError);
});

test("an EdDSA signature whose S is not below the group order does not verify", () => {
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  const jws = signed(() => {});
  const [head, payload, signature] = jws.split(".") as [string, string, string];
  const sig = Buffer.from(signature, "base64url");
  // S + L encodes the same value modulo L; only the canonical S is a signature.
  let s = BigInt("0x" + Buffer.from(sig.subarray(32)).reverse().toString("hex")) + L;
  const bytes = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number(s & 0xffn);
    s >>= 8n;
  }
  const forged = `${head}.${payload}.${Buffer.concat([sig.subarray(0, 32), bytes]).toString("base64url")}`;
  assert.throws(() => verifySigned(forged, ISSUER, parseJwks(KEYS)), SignatureError);
});

const SMALL_ORDER = [
  "0100000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000080",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
];

test("an Ed25519 key of small order is no key, by our own check and not only the library's (SPEC-v0 section 7.1)", () => {
  for (const hex of SMALL_ORDER) {
    const x = Buffer.from(hex, "hex").toString("base64url");
    assert.throws(() => parseJwks({ keys: [{ kty: "OKP", crv: "Ed25519", kid: "k", x }] }), SignatureError, hex);
    assert.equal(smallOrderEd25519(Buffer.from(hex, "hex")), true, hex);
  }
  const good = Buffer.from("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "base64url");
  assert.equal(smallOrderEd25519(good), false);
  assert.doesNotThrow(() => parseJwks({ keys: [{ kty: "OKP", crv: "Ed25519", kid: "k", x: good.toString("base64url") }] }));
});

test("a key of small order built without a key set does not verify", () => {
  // S = 0 and R = the identity: with the identity as key, this holds for every message.
  const hex = SMALL_ORDER[0]!;
  const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(hex, "hex").toString("base64url") }, format: "jwk" });
  const head = Buffer.from('{"alg":"EdDSA","kid":"k"}').toString("base64url");
  const signature = Buffer.concat([Buffer.from(hex, "hex"), Buffer.alloc(32)]).toString("base64url");
  assert.throws(() => verifyDetached(`${head}..${signature}`, "any payload", new Map([["k", { key, alg: "EdDSA" as const }]])), SignatureError);
});
