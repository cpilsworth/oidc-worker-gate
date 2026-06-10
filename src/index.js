import { loadConfig } from "./config.js";
import { OidcClient } from "./oidc.js";
import { readSession } from "./session.js";
import { classify, isAuthorized } from "./policy.js";
import { forwardToOrigin } from "./origin.js";

export default {
  /**
   * @param {Request} request
   * @param {Record<string, any>} env
   */
  async fetch(request, env) {
    const url = new URL(request.url);
    const config = loadConfig(env);
    const oidc = new OidcClient(config);

    // Gate-owned routes first.
    if (url.pathname === config.routes.callback) return oidc.handleCallback(request, url);
    if (url.pathname === config.routes.logout) return oidc.handleLogout(request, url);

    const { tier, audience } = classify(url.pathname, config.policy);

    // public: forward before touching the cookie.
    if (tier === "public") return forwardToOrigin(request, null, "public", config);

    // protected / secured: validate the local session.
    const session = await readSession(request, config);
    if (!session) {
      return tier === "secured" ? unauthorizedJson() : oidc.startLogin(request, url);
    }
    if (!isAuthorized(session, audience)) return forbidden();

    return forwardToOrigin(request, session, tier, config);
  },
};

function unauthorizedJson() {
  return new Response(JSON.stringify({ error: "unauthorized" }), {
    status: 401,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "private, no-store" },
  });
}

function forbidden() {
  return new Response(JSON.stringify({ error: "forbidden" }), {
    status: 403,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "private, no-store" },
  });
}
