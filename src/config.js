import { DEFAULT_WORKER_MANAGED_PATHS } from "./policy-defaults.js";

/**
 * Build the worker Config from Cloudflare bindings. Unlike the Fastly sibling's
 * async ConfigStore/SecretStore, CF exposes everything synchronously on `env`.
 * @param {Record<string, any>} env
 * @returns {import("./policy.js").Config}
 */
export function loadConfig(env) {
  const sessionKey = required(env, "SESSION_HMAC_KEY");
  const clientSecret = required(env, "OIDC_CLIENT_SECRET");
  const policySource = env.POLICY_SOURCE || "auto";
  if (!["auto", "worker", "required"].includes(policySource)) throw new Error(`Invalid POLICY_SOURCE: ${policySource}`);
  return {
    issuer: trimSlash(env.OIDC_ISSUER),
    clientId: env.CLIENT_ID,
    clientSecret,
    redirectUri: env.REDIRECT_URI,
    scopes: env.SCOPES || "openid profile email",
    sessionTtlSeconds: parseInt(env.SESSION_TTL || "3600", 10),
    sessionKey,
    originHostname: env.ORIGIN_HOSTNAME,
    forwardedHost: env.FORWARDED_HOST,
    pushInvalidation: env.PUSH_INVALIDATION === "enabled",
    routes: JSON.parse(env.ROUTES || '{"callback":"/.auth/callback","logout":"/.auth/logout"}'),
    policy: JSON.parse(env.ACCESS_POLICY || '{"rules":[],"default_tier":"protected"}'),
    policySource,
    policySiteId: env.POLICY_SITE_ID || "",
    policyHmacKey: env.POLICY_HMAC_KEY || "",
    policyRefreshTtlSeconds: parseInt(env.POLICY_REFRESH_TTL_SECONDS || "60", 10),
    policyStaleTtlSeconds: parseInt(env.POLICY_STALE_TTL_SECONDS || "900", 10),
    audienceMap: JSON.parse(env.AUDIENCE_MAP || "{}"),
    workerManagedPaths: JSON.parse(env.WORKER_MANAGED_PATHS || JSON.stringify(DEFAULT_WORKER_MANAGED_PATHS)),
    kv: env.OIDC_CACHE || null,
  };
}

function required(env, key) {
  const v = env[key];
  if (!v) throw new Error(`Missing required binding: ${key}`);
  return v;
}

function trimSlash(s) { return (s || "").replace(/\/$/, ""); }
