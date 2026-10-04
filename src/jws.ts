// SPDX-License-Identifier: Apache-2.0

// The part of JSON Web Signature that mandate-spec uses (SPEC-v0 sections 7.1 and 9.5):
// compact serialization, also with detached payload, EdDSA (Ed25519) and ES256.
import { createPublicKey, type KeyObject, verify as cryptoVerify } from "node:crypto";
import { isObject, type Json, parseJson } from "./ijson.ts";
import { canonicalize } from "./jcs.ts";
import { type Mandate, tryParseMandate } from "./mandate.ts";

export class SignatureError extends Error {}

const P256_HALF_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n >> 1n;
const KID = /^[A-Za-z0-9._-]{1,64}$/;
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
    try {
      const { kty, crv, x, y } = jwk as Record<string, string>;
      keys.set(jwk.kid, { key: createPublicKey({ key: y === undefined ? { kty, crv, x } : { kty, crv, x, y }, format: "jwk" }), alg });
    } catch {
      throw new SignatureError("invalid key");
    }
  }
  return keys;
}

function decode(part: string): Buffer {
  if (!BASE64URL.test(part) || part.length % 4 === 1) throw new SignatureError("not base64url");
  const bytes = Buffer.from(part, "base64url");
  if (bytes.toString("base64url") !== part) throw new SignatureError("not canonical base64url");
  return bytes;
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
  // ES256: of the two values of s that verify, only the lower one is accepted.
  const ok = alg === "EdDSA"
    ? sig.length === 64 && cryptoVerify(null, input, entry.key, sig)
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

/** Verifies a signed mandate (section 7.1) against the keys trusted for an issuer. */
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
  return mandate;
}
