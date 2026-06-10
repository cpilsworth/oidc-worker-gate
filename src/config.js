/**
 * Build the worker Config from Cloudflare bindings. Unlike the Fastly sibling's
 * async ConfigStore/SecretStore, CF exposes everything synchronously on `env`.
 * @param {Record<string, any>} env
 * @returns {import("./policy.js").Config}
 */
export function loadConfig(env) {
  const sessionKey = required(env, "SESSION_HMAC_KEY");
  const clientSecret = required(env, "OIDC_CLIENT_SECRET");
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
    kv: env.OIDC_CACHE || null,
  };
}

function required(env, key) {
  const v = env[key];
  if (!v) throw new Error(`Missing required binding: ${key}`);
  return v;
}

function trimSlash(s) { return (s || "").replace(/\/$/, ""); }
