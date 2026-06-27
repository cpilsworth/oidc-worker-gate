import { loadConfig } from "./config.js";
import { OidcClient } from "./oidc.js";
import { readSession } from "./session.js";
import { classify, isAuthorized, matchesAny } from "./policy.js";
import { forwardToOrigin } from "./origin.js";
import { loadRuntimePolicy, PolicyUnavailableError } from "./policy-snapshot.js";
import { normalizePath } from "./path.js";
import { errorResponse, requestId } from "./http.js";

export default {
  /**
   * @param {Request} request
   * @param {Record<string, any>} env
   */
  async fetch(request, env) {
    const url = new URL(request.url);
    const config = loadConfig(env);
    const oidc = new OidcClient(config);

    // Gate-owned routes first (exact match on the raw path).
    if (url.pathname === config.routes.callback) return oidc.handleCallback(request, url);
    if (url.pathname === config.routes.logout) return oidc.handleLogout(request, url);

    // Canonicalize before classifying so encoded/relative/duplicate-separator
    // variants cannot be matched differently from what the origin serves (H1).
    const normalized = normalizePath(url.pathname);
    if (!normalized.ok) {
      console.info("authorization denied", {
        status: 400, reason: "bad_path", detail: normalized.reason, path: url.pathname,
      });
      return errorResponse(400, "bad_request", { requestId: requestId(request) });
    }
    const pathname = normalized.path;

    let runtimePolicy;
    try {
      runtimePolicy = await policyForPath(pathname, config);
    } catch (err) {
      if (err instanceof PolicyUnavailableError) return policyUnavailable(request, pathname, err);
      throw err;
    }
    const { tier, audience } = classify(pathname, runtimePolicy.policy);

    // public: forward before touching the cookie.
    if (tier === "public") return forwardToOrigin(request, null, "public", config, pathname);

    // protected / secured: validate the local session.
    const session = await readSession(request, config);
    if (!session) {
      console.info("authorization denied", {
        status: tier === "secured" ? 401 : 302,
        reason: "missing_session",
        path: pathname,
        tier,
        policy_version: runtimePolicy.version,
        policy_source: runtimePolicy.source,
      });
      return tier === "secured" ? unauthorized(request) : oidc.startLogin(request, url);
    }
    if (!isAuthorized(session, audience)) {
      console.info("authorization denied", {
        status: 403,
        reason: "audience_mismatch",
        path: pathname,
        tier,
        policy_version: runtimePolicy.version,
        policy_source: runtimePolicy.source,
      });
      return forbidden(request);
    }

    return forwardToOrigin(request, session, tier, config, pathname);
  },
};

async function policyForPath(pathname, config) {
  if (isWorkerManagedPath(pathname, config)) {
    return { policy: config.policy, source: "worker-managed", version: "static" };
  }
  return loadRuntimePolicy(config);
}

function isWorkerManagedPath(pathname, config) {
  return matchesAny(config.workerManagedPaths, pathname);
}

function unauthorized(request) {
  return errorResponse(401, "unauthorized", {
    requestId: requestId(request),
    wwwAuthenticate: 'Bearer error="invalid_token"',
  });
}

function forbidden(request) {
  return errorResponse(403, "forbidden", { requestId: requestId(request) });
}

function policyUnavailable(request, path, err) {
  console.warn("authorization unavailable", { status: 503, path, reason: err.message });
  return errorResponse(503, "policy_unavailable", { requestId: requestId(request) });
}
