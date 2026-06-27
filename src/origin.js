import { GATE_COOKIE_NAMES } from "./session.js";
import { NO_STORE } from "./http.js";

/**
 * Forward a request to the EDS origin per AEM BYO-CDN rules. For protected/secured
 * tiers, disable edge caching and rewrite the response so per-user content can never
 * be stored or cross-served. Public responses pass through with origin caching intact.
 * @param {Request} request
 * @param {object|null} session  null for the public tier
 * @param {string} tier          "public" | "protected" | "secured"
 * @param {import("./policy.js").Config} config
 * @param {string} [pathname]    canonicalized path (H1); falls back to the raw path
 */
export async function forwardToOrigin(request, session, tier, config, pathname) {
  const inUrl = new URL(request.url);
  const path = pathname || inUrl.pathname;
  const originUrl = `https://${config.originHostname}${path}${inUrl.search}`;

  const headers = new Headers(request.headers);
  headers.delete("cookie"); // never leak the gate session to origin
  // Strip any client-supplied trusted headers so they cannot be spoofed to the origin.
  for (const name of [...headers.keys()]) {
    if (name.toLowerCase().startsWith("x-auth-")) headers.delete(name);
  }
  headers.delete("x-push-invalidation");
  headers.set("host", config.originHostname);
  headers.set("x-forwarded-host", config.forwardedHost);
  if (config.pushInvalidation) headers.set("x-push-invalidation", "enabled");

  if (session) {
    headers.set("x-auth-subject", session.sub || "");
    headers.set("x-auth-groups", Array.isArray(session.groups) ? session.groups.join(",") : "");
  }
  // Edge↔origin correlation (see README Observability).
  headers.set("x-auth-request-id", request.headers.get("cf-ray") || crypto.randomUUID());

  const cacheOff = tier !== "public";
  const forwarded = new Request(originUrl, {
    method: request.method,
    headers,
    body: request.body,
    ...(cacheOff ? { cf: { cacheTtl: 0, cacheEverything: false } } : {}),
  });

  const res = await fetch(forwarded);
  const out = new Response(res.body, res);
  stripGateSetCookies(out.headers);
  if (!cacheOff) return out;

  out.headers.set("cache-control", NO_STORE);
  out.headers.delete("age");
  return out;
}

function stripGateSetCookies(headers) {
  const setCookies = headers.getSetCookie ? headers.getSetCookie() : [headers.get("set-cookie")].filter(Boolean);
  if (setCookies.length === 0) return;

  headers.delete("set-cookie");
  for (const line of setCookies) {
    if (!GATE_COOKIE_NAMES.has(cookieName(line))) headers.append("set-cookie", line);
  }
}

function cookieName(setCookieLine) {
  return setCookieLine.slice(0, setCookieLine.indexOf("=")).trim();
}
