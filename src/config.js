import { DEFAULT_WORKER_MANAGED_PATHS } from "./policy-defaults.js";

const MIN_HMAC_KEY_BYTES = 32;
const encoder = new TextEncoder();

// Stable parsed-JSON references (S4). Parsing `ACCESS_POLICY` / `WORKER_MANAGED_PATHS`
// to a fresh object each request would defeat policy.js's compile-once cache, so we
// memoize by the raw string: a warm isolate reuses the same object reference, and
// the matcher is compiled exactly once for it.
const parsedJsonCache = new Map();

/**
 * Build the worker Config from Cloudflare bindings. Unlike the Fastly sibling's
 * async ConfigStore/SecretStore, CF exposes everything synchronously on `env`.
 * @param {Record<string, any>} env
 * @returns {import("./policy.js").Config}
 */
export function loadConfig(env) {
  const sessionKey = requiredKey(env, "SESSION_HMAC_KEY");
  const clientSecret = required(env, "OIDC_CLIENT_SECRET");
  const policySource = env.POLICY_SOURCE || "auto";
  if (!["auto", "worker", "required"].includes(policySource)) throw new Error(`Invalid POLICY_SOURCE: ${policySource}`);
  const policyHmacKey = optionalKey(env, "POLICY_HMAC_KEY");
  return {
    issuer: trimSlash(required(env, "OIDC_ISSUER")),
    clientId: required(env, "CLIENT_ID"),
    clientSecret,
    redirectUri: required(env, "REDIRECT_URI"),
    scopes: env.SCOPES || "openid profile email",
    // Single, explicit source for group/role membership (H4). No silent
    // `groups || roles` fallback — only this claim is read, so an unexpected
    // claim can't grant access. Auth0 deployments set the namespaced claim.
    groupsClaim: env.GROUPS_CLAIM || "groups",
    sessionTtlSeconds: positiveInt(env.SESSION_TTL, "SESSION_TTL", "3600"),
    sessionKey,
    originHostname: required(env, "ORIGIN_HOSTNAME"),
    forwardedHost: required(env, "FORWARDED_HOST"),
    pushInvalidation: env.PUSH_INVALIDATION === "enabled",
    routes: parseJsonMemo(env.ROUTES || '{"callback":"/.auth/callback","logout":"/.auth/logout"}'),
    policy: parseJsonMemo(env.ACCESS_POLICY || '{"rules":[],"default_tier":"protected"}'),
    policySource,
    policySiteId: env.POLICY_SITE_ID || "",
    policyHmacKey,
    policyRefreshTtlSeconds: positiveInt(env.POLICY_REFRESH_TTL_SECONDS, "POLICY_REFRESH_TTL_SECONDS", "60"),
    policyStaleTtlSeconds: positiveInt(env.POLICY_STALE_TTL_SECONDS, "POLICY_STALE_TTL_SECONDS", "900"),
    audienceMap: parseJsonMemo(env.AUDIENCE_MAP || "{}"),
    workerManagedPaths: parseJsonMemo(env.WORKER_MANAGED_PATHS || JSON.stringify(DEFAULT_WORKER_MANAGED_PATHS)),
    kv: env.OIDC_CACHE || null,
  };
}

function required(env, key) {
  const v = env[key];
  if (!v) throw new Error(`Missing required binding: ${key}`);
  return v;
}

/** A required secret that must also be long enough to be a sound HMAC key (H6). */
function requiredKey(env, key) {
  const v = required(env, key);
  assertKeyLength(key, v);
  return v;
}

/** An optional secret; when present it must still meet the key-length floor (H6). */
function optionalKey(env, key) {
  const v = env[key] || "";
  if (v) assertKeyLength(key, v);
  return v;
}

function assertKeyLength(key, value) {
  if (encoder.encode(value).length < MIN_HMAC_KEY_BYTES) {
    throw new Error(`${key} must be at least ${MIN_HMAC_KEY_BYTES} bytes`);
  }
}

/** Parse a positive-integer config value; reject NaN/≤0 so a bad TTL can't
 *  produce `exp: NaN` and a silent login loop (H6). */
function positiveInt(raw, name, fallback) {
  const text = raw == null || raw === "" ? fallback : raw;
  const n = parseInt(text, 10);
  if (!Number.isInteger(n) || n <= 0) throw new Error(`${name} must be a positive integer, got: ${raw}`);
  return n;
}

function parseJsonMemo(text) {
  let obj = parsedJsonCache.get(text);
  if (obj === undefined) {
    obj = JSON.parse(text);
    parsedJsonCache.set(text, obj);
  }
  return obj;
}

function trimSlash(s) { return (s || "").replace(/\/$/, ""); }
