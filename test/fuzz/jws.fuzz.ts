// SPDX-License-Identifier: Apache-2.0

// Mirrors FuzzVerify of the Go jws package: arbitrary or mutated input never throws
// anything but SignatureError and never verifies unless it is a JWS that was signed:
// the valid signed mandates of the conformance cases (SPEC-v0 section 7.1) and detached
// signatures made here with the private test keys (section 9.5).
import assert from "node:assert/strict";
import { createPrivateKey, sign } from "node:crypto";
import fc from "fast-check";
import { JsonError, parseJson, type Json } from "../../src/ijson.ts";
import { parseJwks, SignatureError, verifyDetached, verifySigned } from "../../src/jws.ts";
import { specFile } from "../../src/spec.ts";
import { cases } from "../cases.ts";
import { anyText, editedText, fuzz } from "./fuzz.ts";

const ISSUER = "https://issuer.example/mandates";
const PAYLOAD = '{"a":1}';
const signedCases = cases("conformance/signed-v0.json");
const keys = parseJwks(JSON.parse(specFile("conformance/keys/test-keys.json")) as Json);
const privateKeys = (JSON.parse(specFile("conformance/keys/test-keys.private.json")) as { keys: Record<string, string>[] }).keys;

const valid = new Set(signedCases.filter((c) => c.expected === "valid" && c.issuer === ISSUER).map((c) => c.jws as string));
if (valid.size === 0) throw new Error("no valid signed mandate in conformance/signed-v0.json");

const b64 = (text: string) => Buffer.from(text, "utf8").toString("base64url");

/** A detached JWS over PAYLOAD with one of the private test keys. */
function detached(jwk: Record<string, string>): string {
  const alg = jwk.kty === "OKP" ? "EdDSA" : "ES256";
  const head = b64(JSON.stringify({ alg, kid: jwk.kid }));
  const key = createPrivateKey({ key: jwk, format: "jwk" });
  const input = Buffer.from(`${head}.${b64(PAYLOAD)}`, "ascii");
  const signature = alg === "EdDSA" ? sign(null, input, key) : sign("sha256", input, { key, dsaEncoding: "ieee-p1363" });
  return `${head}..${signature.toString("base64url")}`;
}
// ES256 has two valid values of s; only the lower one verifies, so sign until it is.
const MAX_ATTEMPTS = 64;
const signedDetached = new Set(privateKeys.map((jwk) => {
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    const jws = detached(jwk);
    try {
      verifyDetached(jws, PAYLOAD, keys);
      return jws;
    } catch {
      // the higher s
    }
  }
  throw new Error(`no detached signature with ${jwk.kid} verifies`);
}));

const seeds = [...signedCases.map((c) => c.jws as string), ...signedDetached, "", "..", "a.b.c", "eyJhbGciOiJub25lIiwia2lkIjoiayJ9..", [...valid][0]! + "A"];

// A JWS assembled from parts of the seeds, headers with other members, and arbitrary parts.
const parts = seeds.flatMap((s) => s.split("."));
const headers = [
  { alg: "none", kid: "test-ed25519" }, { alg: "EdDSA", kid: "test-p256" }, { alg: "ES256", kid: "test-ed25519" },
  { alg: "EdDSA", kid: "test-ed25519", b64: false }, { alg: "EdDSA", kid: "test-ed25519", crit: ["b64"] }, { kid: "test-ed25519" },
].map((h) => b64(JSON.stringify(h)));
const part = fc.oneof(fc.constantFrom(...parts), fc.constantFrom(...headers), fc.constant(""), anyText(16), fc.base64String().map((s) => s.replace(/=+$/, "").replaceAll("+", "-").replaceAll("/", "_")));
const assembled = fc.array(part, { minLength: 1, maxLength: 4 }).map((p) => p.join("."));

const input = fc.oneof(editedText(seeds), assembled, fc.json({ maxDepth: 3 }), anyText(64));

function rejected(e: unknown, ...defined: (new (...args: never[]) => Error)[]): void {
  if (!defined.some((type) => e instanceof type)) throw e;
}

fuzz("jws", input, (text) => {
  try {
    const mandate = verifySigned(text, ISSUER, keys);
    assert.ok(valid.has(text), `verifySigned accepted ${JSON.stringify(text)}`);
    assert.equal(mandate.issuer, ISSUER);
  } catch (e) {
    rejected(e, SignatureError);
  }
  try {
    verifyDetached(text, PAYLOAD, keys);
    assert.ok(signedDetached.has(text), `verifyDetached accepted ${JSON.stringify(text)}`);
  } catch (e) {
    rejected(e, SignatureError);
  }
  try {
    parseJwks(parseJson(text));
    assert.ok(text.length >= 20, `parseJwks accepted ${JSON.stringify(text)}`);
  } catch (e) {
    rejected(e, SignatureError, JsonError);
  }
}, seeds);
