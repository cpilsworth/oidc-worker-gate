import { base64UrlDecode, decodeJsonSegment, base64UrlEncode, utf8, timingSafeEqual } from "./encoding.js";

const CACHE_TTL_SECONDS = 3600;

export async function getDiscovery(config) {
  return cachedJson(config.kv, `discovery:${config.issuer}`, async () => {
    const res = await fetch(`${config.issuer}/.well-known/openid-configuration`);
    if (!res.ok) throw new Error(`discovery fetch failed: ${res.status}`);
    return res.json();
  });
}

async function getJwks(config, jwksUri, { force = false } = {}) {
  return cachedJson(config.kv, `jwks:${jwksUri}`, async () => {
    const res = await fetch(jwksUri);
    if (!res.ok) throw new Error(`jwks fetch failed: ${res.status}`);
    return res.json();
  }, { force });
}

/**
 * Verify an id_token. Throws on any failure (caller converts to a 400/401).
 * @param {string} idToken
 * @param {import("./policy.js").Config} config
 * @param {string} expectedNonce
 * @param {{ code?: string, accessToken?: string }} [hashes] for c_hash/at_hash checks
 */
export async function verifyIdToken(idToken, config, expectedNonce, hashes = {}) {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("malformed JWT");
  const [headerB64, payloadB64, sigB64] = parts;
  const header = decodeJsonSegment(headerB64);
  const claims = decodeJsonSegment(payloadB64);

  if (header.alg !== "RS256") throw new Error(`unsupported alg: ${header.alg}`); // N2

  // --- signature, with single JWKS refetch on kid miss (N7) ---
  const discovery = await getDiscovery(config);
  const key = await importSigningKey(config, discovery.jwks_uri, header.kid);
  const signingInput = utf8(`${headerB64}.${payloadB64}`);
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5", key, base64UrlDecode(sigB64), signingInput);
  if (!valid) throw new Error("invalid token signature"); // N1

  // --- claims ---
  const now = Math.floor(Date.now() / 1000);
  const skew = 60;
  if (claims.iss !== config.issuer) throw new Error("iss mismatch");                 // N3
  if (!audienceMatches(claims.aud, config.clientId)) throw new Error("aud mismatch"); // N4
  if (claims.azp !== undefined && claims.azp !== config.clientId) throw new Error("azp mismatch");
  if (Array.isArray(claims.aud) && claims.aud.length > 1 && claims.azp !== config.clientId)
    throw new Error("azp required for multi-valued aud");                            // N4b
  if (typeof claims.exp !== "number" || claims.exp + skew < now) throw new Error("token expired"); // N5
  if (typeof claims.nbf === "number" && claims.nbf - skew > now) throw new Error("token not yet valid");
  if (typeof claims.iat === "number" && claims.iat - skew > now) throw new Error("token iat in the future");
  if (expectedNonce && claims.nonce !== expectedNonce) throw new Error("nonce mismatch"); // N6

  // --- c_hash / at_hash when the corresponding artifact is present (N11) ---
  if (hashes.code && claims.c_hash && !timingSafeEqual(claims.c_hash, await leftHalfHash(hashes.code)))
    throw new Error("c_hash mismatch");
  if (hashes.accessToken && claims.at_hash && !timingSafeEqual(claims.at_hash, await leftHalfHash(hashes.accessToken)))
    throw new Error("at_hash mismatch");

  return claims;
}

async function importSigningKey(config, jwksUri, kid) {
  let jwks = await getJwks(config, jwksUri);
  let jwk = jwks.keys.find((k) => k.kid === kid && k.kty === "RSA");
  if (!jwk) {                                  // kid miss → refetch JWKS exactly once
    jwks = await getJwks(config, jwksUri, { force: true });
    jwk = jwks.keys.find((k) => k.kid === kid && k.kty === "RSA");
  }
  if (!jwk) throw new Error(`no JWKS key for kid ${kid}`);
  return crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
}

function audienceMatches(aud, clientId) {
  return Array.isArray(aud) ? aud.includes(clientId) : aud === clientId;
}

/** OIDC hash claim: base64url(left-128-bits(SHA-256(ascii(value)))). */
async function leftHalfHash(value) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(value)));
  return base64UrlEncode(digest.slice(0, digest.length / 2));
}

/** KV-backed JSON cache. `force` bypasses the read (used for kid-rotation refetch). */
async function cachedJson(kv, key, fetcher, { force = false } = {}) {
  if (kv && !force) {
    const hit = await kv.get(key, "json");
    if (hit && hit.expires > Date.now()) return hit.value;
  }
  const value = await fetcher();
  if (kv) {
    await kv.put(key, JSON.stringify({ value, expires: Date.now() + CACHE_TTL_SECONDS * 1000 }),
      { expirationTtl: CACHE_TTL_SECONDS });
  }
  return value;
}
