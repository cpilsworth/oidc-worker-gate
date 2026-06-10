/**
 * Forward a request to the EDS origin per AEM BYO-CDN rules. For protected/secured
 * tiers, disable edge caching and rewrite the response so per-user content can never
 * be stored or cross-served. Public responses pass through with origin caching intact.
 * @param {Request} request
 * @param {object|null} session  null for the public tier
 * @param {string} tier          "public" | "protected" | "secured"
 * @param {import("./policy.js").Config} config
 */
export async function forwardToOrigin(request, session, tier, config) {
  const inUrl = new URL(request.url);
  const originUrl = `https://${config.originHostname}${inUrl.pathname}${inUrl.search}`;

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
    headers.set("x-auth-email", session.email || "");
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
  if (!cacheOff) return res;

  const out = new Response(res.body, res);
  out.headers.set("cache-control", "private, no-store");
  out.headers.delete("age");
  return out;
}
