import { base64UrlDecode, decodeJsonSegment, base64UrlEncode, utf8, timingSafeEqual } from "./encoding.js";
import { kvGetFresh, kvPutWithTtl } from "./kv.js";

const CACHE_TTL_SECONDS = 3600;

export async function getDiscovery(config) {
  const doc = await cachedJson(config.kv, `discovery:${config.issuer}`, async () => {
    const res = await fetch(`${config.issuer}/.well-known/openid-configuration`);
    if (!res.ok) throw new Error(`discovery fetch failed: ${res.status}`);
    return res.json();
  });
  // Don't trust the discovery JSON blindly (H8): the issuer must match what we
  // were configured with, and the endpoints we will redirect/POST to must be
  // https. Validate on every read so a poisoned cache entry can't slip through.
  assertValidDiscovery(doc, config.issuer);
  return doc;
}

function assertValidDiscovery(doc, issuer) {
  if (!doc || typeof doc !== "object") throw new Error("discovery document malformed");
  if (typeof doc.issuer !== "string" || doc.issuer.replace(/\/$/, "") !== issuer) {
    throw new Error("discovery issuer mismatch");
  }
  // Endpoints must be https AND share the issuer's origin (M-1). The discovery
  // doc is cached in KV; a poisoned entry pointing token_endpoint at an attacker
  // host would exfiltrate client_secret + the auth code, and a poisoned jwks_uri
  // would let attacker-signed id_tokens verify. Pinning to the issuer origin
  // (host + scheme + port) closes both. Note: multi-host IdPs such as Google
  // serve endpoints off a different origin and would need a code-level allowlist.
  const issuerOrigin = originOf(issuer);
  for (const ep of ["authorization_endpoint", "token_endpoint", "jwks_uri"]) {
    if (!isHttpsUrl(doc[ep])) throw new Error(`discovery ${ep} must be an https URL`);
    if (originOf(doc[ep]) !== issuerOrigin) throw new Error(`discovery ${ep} must share the issuer origin`);
  }
  if (doc.end_session_endpoint !== undefined) {
    if (!isHttpsUrl(doc.end_session_endpoint)) throw new Error("discovery end_session_endpoint must be an https URL");
    if (originOf(doc.end_session_endpoint) !== issuerOrigin) throw new Error("discovery end_session_endpoint must share the issuer origin");
  }
}

/** URL origin (scheme://host:port), or null when the value isn't a parseable URL. */
function originOf(value) {
  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
}

function isHttpsUrl(value) {
  if (typeof value !== "string" || !value) return false;
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
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
  if (typeof claims.iss !== "string" || claims.iss.replace(/\/$/, "") !== config.issuer)
    throw new Error("iss mismatch"); // N3
  if (!audienceMatches(claims.aud, config.clientId)) throw new Error("aud mismatch"); // N4
  if (claims.azp !== undefined && claims.azp !== config.clientId) throw new Error("azp mismatch");
  if (Array.isArray(claims.aud) && claims.aud.length > 1 && claims.azp !== config.clientId)
    throw new Error("azp required for multi-valued aud");                            // N4b
  if (typeof claims.sub !== "string" || claims.sub.length === 0) throw new Error("sub required");
  if (typeof claims.exp !== "number" || claims.exp + skew < now) throw new Error("token expired"); // N5
  if (typeof claims.nbf === "number" && claims.nbf - skew > now) throw new Error("token not yet valid");
  if (typeof claims.iat !== "number") throw new Error("iat required");
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
  let jwk = selectSigningJwk(await getJwks(config, jwksUri), kid);
  if (!jwk) {                                  // kid miss / rotation → refetch JWKS exactly once
    jwk = selectSigningJwk(await getJwks(config, jwksUri, { force: true }), kid);
  }
  if (!jwk) throw new Error(`no JWKS key for kid ${kid ?? "(absent)"}`);
  return crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
}

/**
 * Pick the RSA verification key. Consider only keys usable for RS256 signature
 * verification: `kty:"RSA"`, not `use:"enc"`, and `alg` either absent or `RS256`
 * — so a JWKS that also serves an encryption RSA key can't have it chosen on the
 * kid-less single-key path. When the token header carries a `kid`, match it
 * exactly (a mismatch is a rotation → caller refetches once, then rejects). When
 * the header omits `kid`, the choice is only unambiguous if exactly one signing
 * key remains — OIDC permits omitting `kid` then; multiple → reject.
 */
function selectSigningJwk(jwks, kid) {
  const signing = (jwks.keys || []).filter(
    (k) => k.kty === "RSA" && k.use !== "enc" && (k.alg === undefined || k.alg === "RS256"),
  );
  if (kid) return signing.find((k) => k.kid === kid) || null;
  return signing.length === 1 ? signing[0] : null;
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
  if (!force) {
    const hit = await kvGetFresh(kv, key);
    if (hit !== null) return hit;
  }
  const value = await fetcher();
  await kvPutWithTtl(kv, key, value, CACHE_TTL_SECONDS);
  return value;
}
