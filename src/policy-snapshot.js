import { base64UrlEncode, timingSafeEqual, utf8 } from "./encoding.js";

const SCHEMA_VERSION = 1;
const cache = new Map();
const loggedModes = new Set();

export function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;

  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

export async function signPolicyPayload(payload, secret) {
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, utf8(canonicalJson(payload)));
  return base64UrlEncode(sig);
}

export async function verifyPolicyEnvelope(envelope, config) {
  if (!isRecord(envelope)) throw new Error("policy envelope must be an object");
  const { payload, signature } = envelope;
  if (!isRecord(payload)) throw new Error("policy payload must be an object");
  if (typeof signature !== "string" || !signature) throw new Error("policy signature is required");
  if (payload.schema_version !== SCHEMA_VERSION) throw new Error("unsupported policy schema_version");
  if (payload.site_id !== config.policySiteId) throw new Error("policy site_id mismatch");
  if (!Array.isArray(payload.rules)) throw new Error("policy rules must be an array");
  if (payload.ignored_rules !== undefined && !Array.isArray(payload.ignored_rules))
    throw new Error("policy ignored_rules must be an array");

  const expected = await signPolicyPayload(payload, config.policyHmacKey);
  if (!timingSafeEqual(expected, signature)) throw new Error("policy signature mismatch");
  return payload;
}

export async function loadRuntimePolicy(config, nowMs = Date.now()) {
  if (config.policySource === "worker") {
    logPolicyMode(config, "worker");
    return { policy: config.policy, source: "worker", version: "static" };
  }

  if (!config.kv || !config.policySiteId || !config.policyHmacKey) {
    if (config.policySource === "required") {
      throw new PolicyUnavailableError("required policy configuration is incomplete");
    }
    logPolicyMode(config, "auto-static-fallback");
    return { policy: config.policy, source: "static-fallback", version: "static" };
  }

  const key = policyCacheKey(config.policySiteId);
  const cached = cache.get(key);
  if (cached?.payload && nowMs - cached.refreshedAt < config.policyRefreshTtlSeconds * 1000) {
    return policyFromPayload(cached.payload, config);
  }

  try {
    const raw = await config.kv.get(key);
    if (!raw) throw new Error("policy snapshot missing");
    const payload = await verifyPolicyEnvelope(JSON.parse(raw), config);
    cache.set(key, { payload, refreshedAt: nowMs });
    logPolicyRefresh(payload);
    return policyFromPayload(payload, config);
  } catch (err) {
    console.warn("policy refresh failed", { site_id: config.policySiteId, reason: err.message });
    if (cached?.payload && nowMs - cached.refreshedAt <= config.policyStaleTtlSeconds * 1000) {
      return { ...policyFromPayload(cached.payload, config), source: "last-known-good" };
    }
    if (config.policySource === "required") {
      throw new PolicyUnavailableError(err.message);
    }
    return { policy: config.policy, source: "static-fallback", version: "static" };
  }
}

export class PolicyUnavailableError extends Error {
  constructor(message) {
    super(message);
    this.name = "PolicyUnavailableError";
  }
}

export function policyCacheKey(siteId) {
  return `policy:current:${siteId}`;
}

function policyFromPayload(payload, config) {
  return {
    policy: { rules: payload.rules, default_tier: config.policy.default_tier },
    source: "kv",
    version: payload.version,
  };
}

function logPolicyRefresh(payload) {
  const ignored = payload.ignored_rules || [];
  console.info("policy refreshed", {
    site_id: payload.site_id,
    version: payload.version,
    published_at: payload.published_at,
    rules: payload.rules.length,
    ignored_rules: ignored.length,
  });
  for (const rule of ignored) console.warn("policy rule ignored", rule);
}

function logPolicyFallback(reason) {
  console.info("policy fallback", { reason });
}

function logPolicyMode(config, mode) {
  const key = `${config.policySiteId || "none"}:${mode}`;
  if (loggedModes.has(key)) return;
  loggedModes.add(key);
  logPolicyFallback(`POLICY_SOURCE=${config.policySource}; mode=${mode}`);
}

async function hmacKey(secret) {
  return crypto.subtle.importKey("raw", utf8(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
