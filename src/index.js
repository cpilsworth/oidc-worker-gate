import { loadConfig } from "./config.js";
import { OidcClient } from "./oidc.js";
import { readSession } from "./session.js";
import { classify, isAuthorized, matchGlob } from "./policy.js";
import { forwardToOrigin } from "./origin.js";
import { loadRuntimePolicy, PolicyUnavailableError } from "./policy-snapshot.js";

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

    let runtimePolicy;
    try {
      runtimePolicy = await policyForPath(url.pathname, config);
    } catch (err) {
      if (err instanceof PolicyUnavailableError) return policyUnavailable(url.pathname, err);
      throw err;
    }
    const { tier, audience } = classify(url.pathname, runtimePolicy.policy);

    // public: forward before touching the cookie.
    if (tier === "public") return forwardToOrigin(request, null, "public", config);

    // protected / secured: validate the local session.
    const session = await readSession(request, config);
    if (!session) {
      console.info("authorization denied", {
        status: tier === "secured" ? 401 : 302,
        reason: "missing_session",
        path: url.pathname,
        tier,
        policy_version: runtimePolicy.version,
        policy_source: runtimePolicy.source,
      });
      return tier === "secured" ? unauthorizedJson() : oidc.startLogin(request, url);
    }
    if (!isAuthorized(session, audience)) {
      console.info("authorization denied", {
        status: 403,
        reason: "audience_mismatch",
        path: url.pathname,
        tier,
        policy_version: runtimePolicy.version,
        policy_source: runtimePolicy.source,
      });
      return forbidden();
    }

    return forwardToOrigin(request, session, tier, config);
  },
};

async function policyForPath(pathname, config) {
  if (isWorkerManagedPath(pathname, config)) {
    return { policy: config.policy, source: "worker-managed", version: "static" };
  }
  return loadRuntimePolicy(config);
}

function isWorkerManagedPath(pathname, config) {
  return (config.workerManagedPaths || []).some((pattern) => matchGlob(pattern, pathname));
}

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

function policyUnavailable(path, err) {
  console.warn("authorization unavailable", { status: 503, path, reason: err.message });
  return new Response(JSON.stringify({ error: "policy_unavailable" }), {
    status: 503,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "private, no-store" },
  });
}
