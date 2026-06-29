import { parseCookies, serializeCookie, sign, unsign, deriveCookieKey } from "./cookies.js";
import { kvGetFresh, kvPutWithTtl } from "./kv.js";

// `__Host-` prefix (H3): the browser only accepts these when Secure, Path=/ and
// Domain-less, which blocks a sibling/non-secure subdomain from overwriting them.
// serializeCookie already emits Secure + Path=/ and never sets Domain.
export const SESSION_COOKIE = "__Host-gate_session";
export const STATE_COOKIE = "__Host-gate_login";

/** Cookie names the gate owns — stripped from any origin Set-Cookie response. */
export const GATE_COOKIE_NAMES = new Set([SESSION_COOKIE, STATE_COOKIE]);

// HKDF labels giving each cookie its own derived signing key (M-4). Bump the
// version suffix to force a key rotation (invalidates outstanding cookies).
export const SESSION_KEY_LABEL = "gate-session-v1";
export const STATE_KEY_LABEL = "gate-login-state-v1";

const sessionSigningKey = (config) => deriveCookieKey(config.sessionKey, SESSION_KEY_LABEL);
const stateSigningKey = (config) => deriveCookieKey(config.sessionKey, STATE_KEY_LABEL);

/** KV key under which the id_token for a session is stored (M-3). */
export const idTokenKey = (jti) => `idtoken:${jti}`;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isValidSession(session) {
  if (!isRecord(session)) return false;
  if (typeof session.sub !== "string" || !session.sub) return false;
  if (typeof session.iat !== "number" || !Number.isFinite(session.iat)) return false;
  if (typeof session.exp !== "number" || !Number.isFinite(session.exp)) return false;
  if (session.exp * 1000 <= Date.now()) return false;
  if (!Array.isArray(session.groups)) return false;
  // M-3: the cookie carries only an opaque session id; the id_token lives in KV.
  if (session.jti !== undefined && typeof session.jti !== "string") return false;
  return true;
}

function isValidLoginState(state) {
  if (!isRecord(state)) return false;
  if (typeof state.state !== "string" || !state.state) return false;
  if (typeof state.nonce !== "string" || !state.nonce) return false;
  if (typeof state.verifier !== "string" || !state.verifier) return false;
  if (typeof state.returnTo !== "string" || !state.returnTo) return false;
  return true;
}

/**
 * Shared reader for the gate's signed cookies (S1): parse → HMAC-verify →
 * JSON-parse → validate. Any failure (missing, tampered, malformed, invalid
 * shape) resolves to null so callers can treat the request as unauthenticated.
 */
async function readSignedCookie(req, name, key, isValid) {
  try {
    const token = parseCookies(req.headers.get("cookie"))[name];
    if (!token) return null;
    const payload = await unsign(token, key);
    if (!payload) return null;
    const value = JSON.parse(payload);
    return isValid(value) ? value : null;
  } catch {
    return null;
  }
}

export async function readSession(req, config) {
  return readSignedCookie(req, SESSION_COOKIE, await sessionSigningKey(config), isValidSession);
}

export async function mintSessionCookie(claims, config, idToken) {
  const now = Math.floor(Date.now() / 1000);
  const session = {
    sub: claims.sub,
    groups: normalizeAudiences(extractClaimGroups(claims, config.groupsClaim), config.audienceMap),
    iat: now, exp: now + config.sessionTtlSeconds,
  };
  // Keep the id_token server-side in KV keyed by an opaque session id (M-3): only
  // the jti — not PII or a 1–2 KB token — lives in the browser cookie. handleLogout
  // resolves the jti back to the id_token for `id_token_hint` (H9). The id_token is
  // never forwarded to origin (see origin.js, which only emits sub/groups).
  if (typeof idToken === "string" && idToken && config.kv) {
    const jti = crypto.randomUUID();
    await kvPutWithTtl(config.kv, idTokenKey(jti), idToken, config.sessionTtlSeconds);
    session.jti = jti;
  }
  const token = await sign(JSON.stringify(session), await sessionSigningKey(config));
  return serializeCookie(SESSION_COOKIE, token, { maxAge: config.sessionTtlSeconds });
}

export function clearSessionCookie() { return serializeCookie(SESSION_COOKIE, "", { maxAge: 0 }); }

/** Resolve (and delete) the id_token kept in KV for a session's logout hint (M-3). */
export async function takeSessionIdToken(session, config) {
  if (!session?.jti || !config.kv) return null;
  const idToken = await kvGetFresh(config.kv, idTokenKey(session.jti));
  await config.kv.delete(idTokenKey(session.jti)).catch(() => {});
  return idToken;
}

export async function mintStateCookie(state, config) {
  const token = await sign(JSON.stringify(state), await stateSigningKey(config));
  return serializeCookie(STATE_COOKIE, token, { maxAge: 600, sameSite: "Lax" });
}

export async function readStateCookie(req, config) {
  return readSignedCookie(req, STATE_COOKIE, await stateSigningKey(config), isValidLoginState);
}

export function clearStateCookie() { return serializeCookie(STATE_COOKIE, "", { maxAge: 0 }); }

/**
 * Read membership from exactly one configured claim (H4). A non-array value
 * (e.g. a string) yields no groups rather than a malformed session — which also
 * avoids the string-claim login loop.
 */
function extractClaimGroups(claims, groupsClaim) {
  const values = claims[groupsClaim || "groups"];
  return Array.isArray(values) ? values.filter((v) => typeof v === "string" && v) : [];
}

function normalizeAudiences(values, audienceMap = {}) {
  const entries = Object.entries(audienceMap || {});
  const out = new Set();
  const reverse = new Map();
  for (const [audience, rawValues] of entries) {
    if (!Array.isArray(rawValues)) continue;
    for (const raw of rawValues) {
      if (typeof raw === "string" && raw) reverse.set(raw, audience);
    }
  }

  for (const value of values) {
    const audience = reverse.get(value);
    if (audience) out.add(audience);
    else console.info("audience mapping miss", { value });
  }
  return [...out];
}
