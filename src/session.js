import { parseCookies, serializeCookie, sign, unsign } from "./cookies.js";

export const SESSION_COOKIE = "__gate_session";
const STATE_COOKIE = "__gate_login";

export async function readSession(req, config) {
  const token = parseCookies(req.headers.get("cookie"))[SESSION_COOKIE];
  if (!token) return null;
  const payload = await unsign(token, config.sessionKey);
  if (!payload) return null;
  try {
    const session = JSON.parse(payload);
    if (typeof session.exp !== "number" || session.exp * 1000 <= Date.now()) return null;
    return session;
  } catch { return null; }
}

export async function mintSessionCookie(claims, config) {
  const now = Math.floor(Date.now() / 1000);
  const session = {
    sub: claims.sub, email: claims.email, name: claims.name,
    groups: claims.groups || claims.roles || [],
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
  const token = parseCookies(req.headers.get("cookie"))[STATE_COOKIE];
  if (!token) return null;
  const payload = await unsign(token, config.sessionKey);
  if (!payload) return null;
  try { return JSON.parse(payload); } catch { return null; }
}

export function clearStateCookie() { return serializeCookie(STATE_COOKIE, "", { maxAge: 0 }); }
