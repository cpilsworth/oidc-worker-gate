/**
 * Shared KV expiry-wrapper helpers (S3). Values are stored as
 * `{ value, expires }` so freshness is enforced in code (independent of KV's
 * own lazy `expirationTtl` eviction). Both the JWT/discovery cache and the
 * single-use login-state marker go through these, so the wrapper logic lives in
 * one place instead of being reimplemented per call site.
 */

/**
 * Read a wrapped value, returning it only if still within its TTL.
 * @returns the stored value, or null when unbound / missing / stale.
 */
export async function kvGetFresh(kv, key, { now = Date.now() } = {}) {
  if (!kv) return null;
  const hit = await kv.get(key, "json");
  if (hit && typeof hit.expires === "number" && hit.expires > now) return hit.value;
  return null;
}

/** Write a value wrapped with an absolute expiry plus a KV `expirationTtl`. */
export async function kvPutWithTtl(kv, key, value, ttlSeconds, { now = Date.now() } = {}) {
  if (!kv) return;
  await kv.put(key, JSON.stringify({ value, expires: now + ttlSeconds * 1000 }), { expirationTtl: ttlSeconds });
}
