import { parseCookies, serializeCookie, sign, unsign } from "./cookies.js";

export const SESSION_COOKIE = "__gate_session";
const STATE_COOKIE = "__gate_login";

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

export async function readSession(req, config) {
  try {
    const token = parseCookies(req.headers.get("cookie"))[SESSION_COOKIE];
    if (!token) return null;
    const payload = await unsign(token, config.sessionKey);
    if (!payload) return null;
    const session = JSON.parse(payload);
    if (!isValidSession(session)) return null;
    return session;
  } catch {
    return null;
  }
}

export async function mintSessionCookie(claims, config) {
  const now = Math.floor(Date.now() / 1000);
  const session = {
    sub: claims.sub,
    groups: claims["https://oidc.workers.dev/groups"] || claims.groups || claims.roles || [],
    iat: now, exp: now + config.sessionTtlSeconds,
  };
  const token = await sign(JSON.stringify(session), config.sessionKey);
  return serializeCookie(SESSION_COOKIE, token, { maxAge: config.sessionTtlSeconds });
}

export function clearSessionCookie() { return serializeCookie(SESSION_COOKIE, "", { maxAge: 0 }); }

export async function mintStateCookie(state, config) {
  const token = await sign(JSON.stringify(state), config.sessionKey);
  return serializeCookie(STATE_COOKIE, token, { maxAge: 600, sameSite: "Lax" });
}

export async function readStateCookie(req, config) {
  try {
    const token = parseCookies(req.headers.get("cookie"))[STATE_COOKIE];
    if (!token) return null;
    const payload = await unsign(token, config.sessionKey);
    if (!payload) return null;
    const state = JSON.parse(payload);
    if (!isValidLoginState(state)) return null;
    return state;
  } catch {
    return null;
  }
}

export function clearStateCookie() { return serializeCookie(STATE_COOKIE, "", { maxAge: 0 }); }
