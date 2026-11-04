// SPDX-License-Identifier: Apache-2.0

// The part of JSON Web Signature that the Home-Mandate Specification uses (SPEC-v0 sections 7.1 and 9.5):
// compact serialization, also with detached payload, EdDSA (Ed25519) and ES256.
import { createPublicKey, type KeyObject, verify as cryptoVerify } from "node:crypto";
import { isObject, type Json, parseJson } from "./ijson.ts";
import { canonicalize } from "./jcs.ts";
import { type Mandate, tryParseMandate } from "./mandate.ts";

export class SignatureError extends Error {}

const P256_HALF_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n >> 1n;
/** p = 2^255 − 19: an Ed25519 point encoding is canonical if its y coordinate (the lower 255 bits) is less than p (RFC 8032 section 5.1.3). */
const ED25519_FIELD_PRIME = (1n << 255n) - 19n;
/** L, the order of the Ed25519 group: S of a signature is less than it (RFC 8032 section 5.1.7). */
const ED25519_GROUP_ORDER = (1n << 252n) + 27742317777372353535851937790883648493n;
const ED25519_BYTES = 32;
const KID = /^[A-Za-z0-9._-]{1,64}$/;
/**
 * The encodings of the Ed25519 points of small order (SPEC-v0 section 7.1). With such a key
 * a signature verifies for every message of a class, so anyone could sign in the name of
 * its holder. Whether a crypto library refuses them depends on its version.
 */
const SMALL_ORDER = new Set([
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
]);
const BASE64URL = /^[A-Za-z0-9_-]*$/;

export type Keys = Map<string, { key: KeyObject; alg: "EdDSA" | "ES256" }>;

/** Reads the public keys of a JWK Set; private keys and other key types are rejected. */
export function parseJwks(jwks: Json): Keys {
  if (!isObject(jwks) || !Array.isArray(jwks.keys) || jwks.keys.length === 0) throw new SignatureError("JWK Set without keys");
  const keys: Keys = new Map();
  for (const jwk of jwks.keys) {
    if (!isObject(jwk) || typeof jwk.kid !== "string" || !KID.test(jwk.kid)) throw new SignatureError("key without a valid kid");
    if (keys.has(jwk.kid)) throw new SignatureError("duplicate kid");
    if ("d" in jwk) throw new SignatureError("private key");
    let alg: "EdDSA" | "ES256";
    if (jwk.kty === "OKP" && jwk.crv === "Ed25519") alg = "EdDSA";
    else if (jwk.kty === "EC" && jwk.crv === "P-256") alg = "ES256";
    else throw new SignatureError("unsupported key type");
    const { kty, crv, x, y } = jwk as Record<string, string | undefined>;
    if (typeof x !== "string" || (alg === "ES256") !== (typeof y === "string")) throw new SignatureError("invalid key");
    try {
      const coordinates = [decode(x), ...(y === undefined ? [] : [decode(y)])];
      if (coordinates.some((c) => c.length !== ED25519_BYTES)) throw new SignatureError("invalid key");
      // Of the two encodings of an Ed25519 public key only the canonical one is a key.
      if (alg === "EdDSA" && !usableEd25519(coordinates[0]!)) throw new SignatureError("invalid key");
      keys.set(jwk.kid, { key: createPublicKey({ key: y === undefined ? { kty, crv, x } : { kty, crv, x, y }, format: "jwk" }), alg });
    } catch {
      throw new SignatureError("invalid key");
    }
  }
  return keys;
}

export function smallOrderEd25519(encoded: Buffer): boolean {
  return SMALL_ORDER.has(encoded.toString("hex"));
}

function usableEd25519(encoded: Buffer): boolean {
  return canonicalEd25519(encoded) && !smallOrderEd25519(encoded);
}

/** The little-endian value of 32 bytes without the top bit: the y coordinate of an encoded Ed25519 point. */
function canonicalEd25519(encoded: Buffer): boolean {
  const y = Buffer.from(encoded);
  y[ED25519_BYTES - 1]! &= 0x7f;
  return littleEndian(y) < ED25519_FIELD_PRIME;
}

function littleEndian(bytes: Buffer): bigint {
  return BigInt("0x" + Buffer.from(bytes).reverse().toString("hex"));
}

function decode(part: string): Buffer {
  if (!BASE64URL.test(part) || part.length % 4 === 1) throw new SignatureError("not base64url");
  const bytes = Buffer.from(part, "base64url");
  if (bytes.toString("base64url") !== part) throw new SignatureError("not canonical base64url");
  return bytes;
}

/** A key can come from a Keys map built without parseJwks, so it is checked here as well. */
function usableKey(key: KeyObject): boolean {
  const { x } = key.export({ format: "jwk" });
  return typeof x === "string" && usableEd25519(Buffer.from(x, "base64url"));
}

/** Checks the signature over head.payload and returns the key ID. */
function verifyParts(head: string, payload: Buffer, signature: string, keys: Keys): string {
  let header: Json;
  try {
    header = parseJson(decode(head).toString("utf8"));
  } catch {
    throw new SignatureError("header");
  }
  // Exactly alg and kid: anything else would change how the signature must be checked.
  if (!isObject(header) || Object.keys(header).sort().join() !== "alg,kid") throw new SignatureError("header members");
  const { alg, kid } = header;
  if (typeof kid !== "string" || !KID.test(kid)) throw new SignatureError("kid");
  const entry = keys.get(kid);
  if (!entry || entry.alg !== alg) throw new SignatureError("unknown key or algorithm");
  const input = Buffer.from(head + "." + payload.toString("base64url"), "ascii");
  const sig = decode(signature);
  // A signature has exactly one form (SPEC-v0 section 7.1): for ES256, of the two values of
  // s that verify only the lower one; for EdDSA, S below the group order and R canonical.
  const ok = alg === "EdDSA"
    ? usableKey(entry.key) && sig.length === 2 * ED25519_BYTES && canonicalEd25519(sig.subarray(0, ED25519_BYTES)) &&
      littleEndian(sig.subarray(ED25519_BYTES)) < ED25519_GROUP_ORDER && cryptoVerify(null, input, entry.key, sig)
    : sig.length === 64 && BigInt("0x" + sig.subarray(32).toString("hex")) <= P256_HALF_ORDER &&
      cryptoVerify("sha256", input, { key: entry.key, dsaEncoding: "ieee-p1363" }, sig);
  if (!ok) throw new SignatureError("signature does not verify");
  return kid;
}

/** Verifies a compact JWS with detached payload. */
export function verifyDetached(jws: string, payload: string, keys: Keys): string {
  const parts = jws.split(".");
  if (parts.length !== 3 || parts[1] !== "") throw new SignatureError("not a detached JWS");
  return verifyParts(parts[0]!, Buffer.from(payload, "utf8"), parts[2]!, keys);
}

/**
 * Verifies a signed mandate (section 7.1) against the keys trusted for an issuer: a
 * canonical payload that is a valid mandate with issuer, version, audience and expires.
 * The caller decides whether the audience is its own and whether the issuer may issue for
 * the principal and the agent.
 */
export function verifySigned(jws: string, issuer: string, keys: Keys): Mandate {
  const parts = jws.split(".");
  if (parts.length !== 3 || parts[1] === "") throw new SignatureError("not a compact JWS with payload");
  const payload = decode(parts[1]!);
  verifyParts(parts[0]!, payload, parts[2]!, keys);
  const text = payload.toString("utf8");
  let canonical: string;
  try {
    canonical = canonicalize(parseJson(text));
  } catch {
    throw new SignatureError("payload is not I-JSON");
  }
  if (canonical !== text || !Buffer.from(text, "utf8").equals(payload)) throw new SignatureError("payload is not canonical");
  const mandate = tryParseMandate(text);
  if (!mandate) throw new SignatureError("payload is not a valid mandate");
  if (issuer === "" || mandate.issuer !== issuer) throw new SignatureError("keys are not trusted for the issuer of the mandate");
  // A signed mandate names the verifier it is for and expires (SPEC-v0 section 7.1); whether
  // the audience is the verifier's own is the verifier's decision, like the trust in the issuer.
  if (mandate.audience === "") throw new SignatureError("a signed mandate names its audience");
  if (!mandate.expires) throw new SignatureError("a signed mandate expires");
  return mandate;
}
