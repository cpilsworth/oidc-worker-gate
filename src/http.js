/**
 * Shared response helpers (S2). Every gate response routes through here so the
 * no-store cache policy and the baseline security headers (nosniff, and a
 * `WWW-Authenticate` challenge on 401s) live in exactly one place.
 *
 * Error bodies are deliberately generic (H7): we never echo an exception
 * message or a raw IdP `error` parameter back to the caller. Callers log the
 * real reason server-side and surface only a stable code plus a request id so
 * an operator can still correlate a report to a log line.
 */

const NO_STORE = "private, no-store";

/** Build a header bag with the gate's mandatory cache + hardening headers. */
export function securityHeaders(extra = {}) {
  return {
    "cache-control": NO_STORE,
    "x-content-type-options": "nosniff",
    ...extra,
  };
}

/** A correlation id for edge↔log↔report correlation; prefers Cloudflare's ray id. */
export function requestId(req) {
  const ray = req && req.headers && req.headers.get("cf-ray");
  return ray || crypto.randomUUID();
}

export function jsonResponse(body, status, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: securityHeaders({ "content-type": "application/json; charset=utf-8", ...extra }),
  });
}

/**
 * Generic error response. `code` is a stable, non-revealing token (e.g.
 * "unauthorized"); never pass user/IdP-derived text here.
 */
export function errorResponse(status, code, { requestId: id, wwwAuthenticate } = {}) {
  const extra = {};
  if (wwwAuthenticate) extra["www-authenticate"] = wwwAuthenticate;
  const body = { error: code };
  if (id) body.request_id = id;
  return jsonResponse(body, status, extra);
}

export { NO_STORE };
