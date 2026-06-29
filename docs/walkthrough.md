# oidc-worker-gate: a linear code walkthrough

*2026-06-29T21:40:57Z by Showboat 0.6.1*
<!-- showboat-id: cd62f614-ccd5-4825-b0bc-c8dd4884cb3b -->

## What this is

`oidc-worker-gate` is an **OpenID Connect authentication gateway** for AEM Edge
Delivery Services (EDS), implemented as a **Cloudflare Worker**. It sits on the
customer domain in front of the EDS origin (`main--<site>--<org>.aem.live`),
authenticates users against any standards-compliant OpenID Provider, and
enforces access **before** anything reaches the origin — the EDS project itself
knows nothing about OIDC.

The system is **two workers** that share code in `src/`:

- **Delivery worker** (`src/index.js` + helpers) — the request gate. Classifies
  every path into one of three tiers, runs the OIDC login flow, validates a
  locally-signed session cookie, and forwards authorized requests to origin.
- **Publisher worker** (`src/publisher-worker.js` + `src/policy-publisher.js`) —
  reads a DA-authored `access-control` sheet, validates and normalizes it, signs
  it with an HMAC key, and writes a signed policy snapshot into KV that the
  delivery worker consumes.

This walkthrough follows the **request lifecycle** through the delivery worker
first (entry point → config → path → policy → session → OIDC → origin), then
covers the publisher side. We trace `src/` only; the operational `scripts/`
(e.g. `npm run refresh-policy`, which manually triggers a publish) and the
`test/` suite are out of scope here.

Throughout the source you'll see comment tags like `H1`, `H4`, `N5`, `S4`. The
`H*` tags mark **hardening** decisions (defenses against a specific attack), the
`N*` tags mark **OIDC conformance** behaviors (the negative-test matrix), and
`S*` tags mark **shared-helper** refactors. This walkthrough explains the *why*
behind the important ones as we hit them.

> Every code block below is run by `showboat exec`, so the snippets are pulled
> live from the source. Run `cd oidc-worker-gate && showboat verify docs/walkthrough.md`
> to confirm the walkthrough still matches the code.

### The `src/` modules

Here is the full surface we'll walk through. The two `export default` entry
points are `index.js` (delivery) and `publisher-worker.js` (publisher);
everything else is a focused helper.

```bash
git ls-files src | sort

```

```output
src/config.js
src/cookies.js
src/encoding.js
src/http.js
src/index.js
src/jwt.js
src/kv.js
src/oidc.js
src/origin.js
src/path.js
src/pkce.js
src/policy-defaults.js
src/policy-publisher.js
src/policy-snapshot.js
src/policy.js
src/publisher-worker.js
src/session.js
```

## 1. `src/index.js` — the entry point and request lifecycle

This is the conductor. A Cloudflare Worker exports a `fetch(request, env)`
handler; every request to the gated domain lands here. The handler is short on
purpose — it orchestrates the helpers in a fixed order and each `return` is a
distinct outcome (forward, redirect, 401/403/400/503).

Read it top to bottom as the decision tree it is:

```bash
sed -n '10,74p' src/index.js

```

```output
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
```

The order is deliberate:

1. **Gate-owned routes first.** `/.auth/callback` and `/.auth/logout` are matched
   on the *raw* path and handled by the `OidcClient` before any policy logic —
   they are the gate's own endpoints, not origin content.
2. **Canonicalize the path (`H1`).** `normalizePath` collapses encoded
   separators, `..` segments, and duplicate slashes. The gate classifies *and*
   forwards the same canonical form, so an attacker can't smuggle
   `/blog/%2e%2e/members/secret` past a public `/blog/**` rule into protected
   `/members/`. A bad path is a generic `400` — the real reason is logged, not
   returned.
3. **Load the runtime policy.** `policyForPath` decides whether this path is
   worker-managed (static config) or content (signed KV snapshot). If a
   `required` policy is unavailable it throws `PolicyUnavailableError`, which
   becomes a fail-closed `503` rather than an accidental allow.
4. **Classify into a tier.** `classify` returns `{ tier, audience }`.
5. **Branch on tier.** `public` forwards immediately *without reading the
   cookie*. `protected`/`secured` read the local session; a missing session is a
   `302` to the IdP for `protected` (navigational) but a `401` JSON for
   `secured` (API/fetch). A present-but-wrong-audience session is `403`.

Every denial logs a structured `console.info` line carrying the policy version
and source — that is the edge↔log correlation trail.

The two small helpers below encode the policy-source split and the fail-closed
`503`. Note `isWorkerManagedPath` uses `matchesAny` against the static
worker-managed path list — infrastructure paths never depend on the DA policy:

```bash
sed -n '76,101p' src/index.js

```

```output
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
```

## 2. `src/config.js` — turning `env` into a validated `Config`

`loadConfig(env)` runs on **every request** (Cloudflare exposes bindings
synchronously on `env`, unlike the Fastly sibling's async stores). It reads
secrets and tunables, validates them, and returns the `Config` object every
other module depends on.

Two ideas dominate this file: **fail-fast validation** of anything that could
silently break auth, and a **stable-reference memoization** that keeps the hot
path cheap.

```bash
sed -n '18,50p' src/config.js

```

```output
export function loadConfig(env) {
  const sessionKey = requiredKey(env, "SESSION_HMAC_KEY");
  const clientSecret = required(env, "OIDC_CLIENT_SECRET");
  const policySource = env.POLICY_SOURCE || "auto";
  if (!["auto", "worker", "required"].includes(policySource)) throw new Error(`Invalid POLICY_SOURCE: ${policySource}`);
  const policyHmacKey = optionalKey(env, "POLICY_HMAC_KEY");
  return {
    issuer: trimSlash(env.OIDC_ISSUER),
    clientId: env.CLIENT_ID,
    clientSecret,
    redirectUri: env.REDIRECT_URI,
    scopes: env.SCOPES || "openid profile email",
    // Single, explicit source for group/role membership (H4). No silent
    // `groups || roles` fallback — only this claim is read, so an unexpected
    // claim can't grant access. Auth0 deployments set the namespaced claim.
    groupsClaim: env.GROUPS_CLAIM || "groups",
    sessionTtlSeconds: positiveInt(env.SESSION_TTL, "SESSION_TTL", "3600"),
    sessionKey,
    originHostname: env.ORIGIN_HOSTNAME,
    forwardedHost: env.FORWARDED_HOST,
    pushInvalidation: env.PUSH_INVALIDATION === "enabled",
    routes: JSON.parse(env.ROUTES || '{"callback":"/.auth/callback","logout":"/.auth/logout"}'),
    policy: parseJsonMemo(env.ACCESS_POLICY || '{"rules":[],"default_tier":"protected"}'),
    policySource,
    policySiteId: env.POLICY_SITE_ID || "",
    policyHmacKey,
    policyRefreshTtlSeconds: positiveInt(env.POLICY_REFRESH_TTL_SECONDS, "POLICY_REFRESH_TTL_SECONDS", "60"),
    policyStaleTtlSeconds: positiveInt(env.POLICY_STALE_TTL_SECONDS, "POLICY_STALE_TTL_SECONDS", "900"),
    audienceMap: JSON.parse(env.AUDIENCE_MAP || "{}"),
    workerManagedPaths: parseJsonMemo(env.WORKER_MANAGED_PATHS || JSON.stringify(DEFAULT_WORKER_MANAGED_PATHS)),
    kv: env.OIDC_CACHE || null,
  };
}
```

A few specifics worth calling out:

- **`groupsClaim` is a single source (`H4`).** Membership comes from exactly one
  configured claim — there is no `groups || roles` fallback that an unexpected
  token claim could exploit to grant access.
- **`default_tier` defaults to `protected`.** The fallback `ACCESS_POLICY` has no
  rules and a `protected` default — **deny-by-default**, so an unmatched path is
  never accidentally public.
- **`policySource`** is validated to one of `auto` / `worker` / `required` and
  drives the policy-loading strategy we'll see in §4.
- **`kv` is `null` when unbound** — downstream code treats "no KV" as a hard
  capability gap (single-use state, policy snapshots) rather than crashing.

Now the validation and memoization helpers. The key-length floor, the
positive-integer guard, and the parse memoization each prevent a specific
silent failure:

```bash
sed -n '52,96p' src/config.js

```

```output
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
```

- **`assertKeyLength` (`H6`)** enforces a 32-byte floor on HMAC secrets — a short
  key would weaken every signed cookie and policy snapshot.
- **`positiveInt` (`H6`)** rejects `NaN`/`≤0` TTLs. Without it a typo'd
  `SESSION_TTL` could produce `exp: NaN`, an instantly-invalid session, and a
  silent infinite login loop.
- **`parseJsonMemo` (`S4`)** is the subtle one. `loadConfig` runs per request, so
  parsing `ACCESS_POLICY`/`WORKER_MANAGED_PATHS` to a *fresh* object each time
  would defeat the compile-once matcher cache in `policy.js` (which is keyed on
  object identity via `WeakMap`). Memoizing by the raw string hands back the
  *same reference* on a warm isolate, so the regex matchers compile exactly once.

This object-identity-stability trick is the thread that connects `config.js`,
`policy.js`, and `policy-snapshot.js` — keep it in mind for §4 and §5.

## 3. `src/path.js` — canonicalization as a matcher-bypass defense (`H1`)

This is the single most security-critical helper in the gate. The policy matcher
classifies on a *literal* string. If the gate classified the raw request path but
the origin resolved a *different* path, the two could disagree about which
resource was requested — the classic glob-bypass. `normalizePath` derives one
canonical form that the gate **both classifies and forwards**, so the gate and
origin can never disagree.

```bash
sed -n '32,103p' src/path.js

```

```output
const MAX_DECODE_PASSES = 5;

export function normalizePath(rawPathname) {
  if (typeof rawPathname !== "string" || rawPathname.length === 0) {
    return { ok: false, reason: "empty path" };
  }

  let decoded = rawPathname;
  for (let pass = 0; ; pass++) {
    // Reject encoded separators on the STILL-ENCODED string, before decoding, so
    // a `%2f`/`%5c` (at any encoding depth) can never decode into a real separator
    // that silently changes segment structure.
    if (/%2f/i.test(decoded) || /%5c/i.test(decoded)) {
      return { ok: false, reason: "encoded path separator" };
    }
    if (!decoded.includes("%")) break; // fully decoded
    if (pass >= MAX_DECODE_PASSES) return { ok: false, reason: "excessive percent-encoding" };
    let next;
    try {
      next = decodeURIComponent(decoded);
    } catch {
      return { ok: false, reason: "malformed percent-encoding" };
    }
    if (next === decoded) break; // stable
    decoded = next;
  }

  // Many origins/browsers treat "\" as a separator; reject so the gate and
  // origin can never disagree about segment boundaries.
  if (decoded.includes("\\")) return { ok: false, reason: "backslash in path" };

  if (!decoded.startsWith("/")) decoded = "/" + decoded;
  const hadTrailingSlash = decoded.length > 1 && decoded.endsWith("/");

  const segments = [];
  for (const segment of decoded.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") { segments.pop(); continue; }
    segments.push(segment);
  }

  let path = "/" + segments.join("/");
  if (hadTrailingSlash && path !== "/") path += "/";

  // `?`/`#` would start a query/fragment when the origin re-parses the forwarded
  // URL (truncating the path to a different resource); ASCII control chars (incl.
  // tab/newline, which the URL parser strips outright) would likewise change the
  // resource. Reject these so the path we classify can't diverge from what we
  // forward. (Spaces and non-ASCII are fine — the parser percent-escapes them
  // without changing segment structure, so they're re-encoded below, not rejected.)
  if (hasUnsafePathChar(path)) return { ok: false, reason: "illegal character in path" };
  // Re-encode to the URL-parser canonical form — space / non-ASCII become
  // percent-escapes WITHOUT changing segment structure — so the classified value
  // is byte-identical to what `new Request(originUrl)` resolves to, and the result
  // is idempotent under re-parsing. (No `%` survives the fixpoint decode above, so
  // this can't double-encode.)
  try {
    path = new URL("https://x" + path).pathname;
  } catch {
    return { ok: false, reason: "non-canonical path" };
  }
  return { ok: true, path };
}

/** True if the path contains `?`, `#`, an ASCII C0 control (0x00–0x1F), or DEL (0x7F). */
function hasUnsafePathChar(path) {
  for (let i = 0; i < path.length; i++) {
    const c = path.charCodeAt(i);
    if (c === 0x23 /* # */ || c === 0x3f /* ? */ || c < 0x20 || c === 0x7f) return true;
  }
  return false;
}
```

The logic, in order, and why each step exists:

1. **Decode to a *fixpoint* (`C-1`), checking encoded separators every pass.**
   The loop refuses `%2f`/`%5c` on the *still-encoded* string, then
   `decodeURIComponent`s and repeats until the string is stable (no `%` left or
   no change), capped at `MAX_DECODE_PASSES` (`excessive percent-encoding`
   otherwise). Multi-pass is what defeats *double*-encoding: a single decode would
   leave `%252e%252e` as the literal segment `%2e%2e` — opaque to the glob matcher
   but collapsed to `..` by the WHATWG URL parser at the origin. Decoding until
   stable means the gate and origin resolve the same segments.
2. **Reject malformed percent-encoding** (`decodeURIComponent` throws) and
   **literal backslashes** (many origins treat `\` as `/`).
3. **Normalize segments**: drop empty (`//` → `/`) and `.` segments, and pop the
   parent on `..` — clamping at root so `..` can never escape above `/`. This is
   what neutralizes `/blog/%2e%2e/members/secret`: it decodes to
   `/blog/../members/secret`, and resolving `..` yields `/members/secret` — which
   is then classified as protected, exactly what the origin would serve. A
   meaningful trailing slash is preserved (EDS distinguishes `/foo` from `/foo/`),
   but never on the root.
4. **Reject `?`/`#` and ASCII control chars** (`hasUnsafePathChar`). When the
   origin re-parses the forwarded URL these would start a query/fragment
   (truncating the path) or be stripped — diverging from what we classified.
5. **Re-encode to the URL-parser canonical form** via `new URL("https://x" +
   path).pathname`. Spaces and non-ASCII are percent-escaped *without* changing
   segment structure, so the classified value is byte-identical to what
   `new Request(originUrl)` will resolve — and legitimate non-ASCII slugs are
   canonicalized rather than rejected.

The return is a tagged result `{ ok, path }` / `{ ok, reason }` — the caller in
`index.js` turns `!ok` into a generic `400` and logs the specific reason.

## 4. `src/policy-snapshot.js` — loading and verifying the signed policy

`policyForPath` (from §1) calls `loadRuntimePolicy` for content paths. This
module is the trust boundary between the **publisher worker** (which writes a
signed policy into KV) and the **delivery worker** (which must never trust KV
blindly). Three concerns live here: canonical signing, envelope verification,
and a layered cache with graceful fallback.

First, the signing primitives. `canonicalJson` produces a stable, key-sorted
serialization so the publisher and verifier compute the **same** bytes over the
same logical payload — signatures can't break on key-ordering differences:

```bash
sed -n '7,35p' src/policy-snapshot.js

```

```output
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
```

`verifyPolicyEnvelope` is defense-in-depth: it checks **shape** (envelope/payload
are objects, `rules` is an array), **schema version**, and crucially the
**`site_id` matches this deployment** — so a valid snapshot signed for a
*different* site can't be replayed here. Only then does it recompute the HMAC and
compare with `timingSafeEqual` (constant-time, so signature comparison doesn't
leak via timing). Any failure throws.

Now the loader. It encodes the `POLICY_SOURCE` strategy from §2 and a two-tier
TTL cache (fresh → stale → fallback):

```bash
sed -n '37,94p' src/policy-snapshot.js

```

```output
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
  if (cached?.policyObj && nowMs - cached.refreshedAt < config.policyRefreshTtlSeconds * 1000) {
    return { policy: cached.policyObj, source: "kv", version: cached.payload.version };
  }

  try {
    const raw = await config.kv.get(key);
    if (!raw) throw new Error("policy snapshot missing");
    const payload = await verifyPolicyEnvelope(JSON.parse(raw), config);
    // Derive the runtime policy once and cache the object reference so policy.js
    // compiles its matchers a single time across requests in a warm isolate (S4).
    const policyObj = derivePolicy(payload, config);
    cache.set(key, { payload, policyObj, refreshedAt: nowMs });
    logPolicyRefresh(payload);
    return { policy: policyObj, source: "kv", version: payload.version };
  } catch (err) {
    console.warn("policy refresh failed", { site_id: config.policySiteId, reason: err.message });
    if (cached?.policyObj && nowMs - cached.refreshedAt <= config.policyStaleTtlSeconds * 1000) {
      return { policy: cached.policyObj, source: "last-known-good", version: cached.payload.version };
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

function derivePolicy(payload, config) {
  // Author-controlled rules, but deny-by-default stays worker-owned: the DA
  // payload can never flip `default_tier`.
  return { rules: payload.rules, default_tier: config.policy.default_tier };
}
```

The decision tree, top to bottom:

- **`POLICY_SOURCE=worker`** → ignore KV entirely; use the static worker policy.
- **Incomplete config** (no KV / site-id / HMAC key) → if `required`, fail closed
  with `PolicyUnavailableError` (the `503` from §1); otherwise fall back to static.
- **Fresh cache hit** (within `policyRefreshTtlSeconds`, default 60s) → return the
  cached object *by reference* — no KV read, no re-verify, no re-compile.
- **Cache miss/stale** → read KV, `verifyPolicyEnvelope`, `derivePolicy`, cache.
- **On any failure** → serve **last-known-good** within the longer
  `policyStaleTtlSeconds` window (default 900s); past that, `required` fails
  closed and `auto` falls back to static.

Two things to underline:

- **`derivePolicy` keeps deny-by-default worker-owned.** The DA-authored payload
  supplies only `rules`; `default_tier` is always taken from the worker config. A
  DA author can never flip the whole site to a public default.
- **`policyObj` is cached and returned by reference (`S4`)** — the same identity
  trick from §2, so `policy.js` compiles each rule's matcher exactly once across
  requests on a warm isolate. The layered TTLs trade staleness for availability:
  the gate keeps enforcing the last good policy through a KV blip rather than
  failing open.

## 5. `src/policy.js` — classify by specificity, match globs, authorize

This module answers two questions: *which tier does this path fall into?*
(`classify`) and *is this session allowed?* (`isAuthorized`). It also owns the
compile-once matcher caches that §2 and §4 worked to feed with stable references.

`classify` walks rules pre-sorted by specificity and returns the first (= most
specific) match; `matchesAny` is the simpler any-match used for worker-managed
paths; `isAuthorized` does the audience↔groups intersection:

```bash
sed -n '20,53p' src/policy.js

```

```output
export function classify(pathname, policy) {
  // Rules are pre-sorted by specificity (desc), so the first match is the best.
  for (const rule of compilePolicy(policy)) {
    if (rule.match(pathname)) return { tier: rule.tier, audience: rule.audience };
  }
  return { tier: policy.default_tier, audience: undefined };
}

/** True if `path` matches any pattern in `patterns` (used for worker-managed paths). */
export function matchesAny(patterns, path) {
  for (const match of compileMatcherList(patterns)) {
    if (match(path)) return true;
  }
  return false;
}

/** Authenticated-session authorization: empty/absent audience = any session OK. */
export function isAuthorized(session, audience) {
  if (!audience || audience.length === 0) return true;
  const groups = Array.isArray(session.groups) ? session.groups : [];
  return audience.some((a) => groups.includes(a));
}

export function specificity(pattern) {
  const star = pattern.indexOf("*");
  if (star === -1) return 1000 + pattern.length;   // exact patterns rank above any glob
  return pattern.slice(0, star).length;            // else longest literal prefix wins
}

export function matchGlob(pattern, path) {
  if (typeof pattern !== "string" || typeof path !== "string") return false;
  if (!pattern.includes("*")) return pattern === path;
  return patternToRegExp(pattern).test(path);
}
```

**Specificity ordering** is what makes overlapping rules deterministic. An exact
(wildcard-free) pattern scores `1000 + length` — always above any glob. Among
globs, the one with the longest literal prefix before its first `*` wins. So
`/members/admin` beats `/members/*` beats `/**`. `classify` relies on the rules
being pre-sorted descending, so the first match is the best match; an unmatched
path falls to `default_tier` (deny-by-default).

**`isAuthorized`** treats an absent/empty audience as "any authenticated session
is fine"; otherwise the session's `groups` must intersect the required audience,
else `index.js` returns `403`.

Now the compilation/caching internals and the glob→regex translation. The
`WeakMap`s here are why the stable references from §2/§4 matter — compile once
per policy object, reuse across every request:

```bash
sed -n '55,109p' src/policy.js

```

```output
function compilePolicy(policy) {
  let compiled = compiledPolicies.get(policy);
  if (!compiled) {
    compiled = (policy.rules || [])
      .map((r) => ({ tier: r.tier, audience: r.audience, match: buildMatcher(r.path), _s: specificity(r.path) }))
      .sort((a, b) => b._s - a._s);
    compiledPolicies.set(policy, compiled);
  }
  return compiled;
}

function compileMatcherList(patterns) {
  if (!Array.isArray(patterns)) return [];
  let compiled = compiledMatcherLists.get(patterns);
  if (!compiled) {
    compiled = patterns.map(buildMatcher);
    compiledMatcherLists.set(patterns, compiled);
  }
  return compiled;
}

/** Precompile a single pattern into a `(path) => boolean` matcher. */
function buildMatcher(pattern) {
  if (typeof pattern !== "string") return () => false;
  if (!pattern.includes("*")) return (path) => path === pattern;
  const re = patternToRegExp(pattern);
  return (path) => typeof path === "string" && re.test(path);
}

function patternToRegExp(pattern) {
  if (pattern.endsWith("/**")) {
    const base = pattern.slice(0, -3);
    return new RegExp(`^${escapeRe(base)}(?:/.*)?/?$`);
  }

  let out = "^";
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch !== "*") {
      out += escapeRe(ch);
      continue;
    }

    if (pattern[i + 1] === "*") {
      out += ".*";
      i++;
    } else {
      out += "[^/]*";
    }
  }
  return new RegExp(out + "$");
}

function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
```

The glob grammar, as encoded in `patternToRegExp`:

- **`/foo/**`** (trailing) → matches the base itself *and* anything beneath it
  (`/foo`, `/foo/`, `/foo/bar/baz`).
- **`**`** (mid-pattern) → `.*` (crosses `/`).
- **`*`** → `[^/]*` (a single segment, does not cross `/`).
- No `*` → exact string equality (the fast path in `buildMatcher`).

All literal characters are regex-escaped, so a `.` in a path is a literal dot,
not "any char." Compilation is memoized in two `WeakMap`s keyed on the policy
object / pattern-array identity — this is the payoff for the stable references
from §2 and §4: matchers compile once and are reused for the life of the warm
isolate.

### `src/policy-defaults.js` — the worker-managed path list

`matchesAny` (above) is fed this static list when no `WORKER_MANAGED_PATHS`
override is configured. These are EDS infrastructure and gate-owned paths that
are classified from static worker config and never depend on the DA policy:

```bash
cat src/policy-defaults.js

```

```output
export const DEFAULT_WORKER_MANAGED_PATHS = [
  "/.auth/**",
  "/scripts/**",
  "/styles/**",
  "/blocks/**",
  "/icons/**",
  "/fonts/**",
  "/media_*",
  "/sitemap.xml",
  "/robots.txt",
  "/.well-known/**",
  "/nav.plain.html",
  "/footer.plain.html",
];
```

## 6. `src/session.js` — the local session cookie

After login the gate mints its **own** HMAC-signed session cookie. Every later
request is then validated *locally* — no IdP or backend round-trip — so the
authenticated hot path is a single origin `fetch()`. This module owns that cookie
plus the short-lived login-state cookie.

The cookie names use the **`__Host-` prefix (`H3`)**: browsers only accept these
when `Secure`, `Path=/`, and `Domain`-less, which blocks a sibling or non-secure
subdomain from overwriting them.

```bash
sed -n '6,56p' src/session.js

```

```output
// serializeCookie already emits Secure + Path=/ and never sets Domain.
export const SESSION_COOKIE = "__Host-gate_session";
export const STATE_COOKIE = "__Host-gate_login";

/** Cookie names the gate owns — stripped from any origin Set-Cookie response. */
export const GATE_COOKIE_NAMES = new Set([SESSION_COOKIE, STATE_COOKIE]);

// HKDF labels giving each cookie its own derived signing key (M-4). Bump the
// version suffix to force a key rotation (invalidates outstanding cookies).
export const SESSION_KEY_LABEL = "gate-session-v1";
export const STATE_KEY_LABEL = "gate-login-state-v1";

const sessionSigningKey = (config) => deriveCookieKey(config.sessionKey, SESSION_KEY_LABEL);
const stateSigningKey = (config) => deriveCookieKey(config.sessionKey, STATE_KEY_LABEL);

/** KV key under which the id_token for a session is stored (M-3). */
export const idTokenKey = (jti) => `idtoken:${jti}`;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isValidSession(session) {
  if (!isRecord(session)) return false;
  if (typeof session.sub !== "string" || !session.sub) return false;
  if (typeof session.iat !== "number" || !Number.isFinite(session.iat)) return false;
  if (typeof session.exp !== "number" || !Number.isFinite(session.exp)) return false;
  if (session.exp * 1000 <= Date.now()) return false;
  if (!Array.isArray(session.groups)) return false;
  // M-3: the cookie carries only an opaque session id; the id_token lives in KV.
  if (session.jti !== undefined && typeof session.jti !== "string") return false;
  return true;
}

function isValidLoginState(state) {
  if (!isRecord(state)) return false;
  if (typeof state.state !== "string" || !state.state) return false;
  if (typeof state.nonce !== "string" || !state.nonce) return false;
  if (typeof state.verifier !== "string" || !state.verifier) return false;
  if (typeof state.returnTo !== "string" || !state.returnTo) return false;
  return true;
}

/**
 * Shared reader for the gate's signed cookies (S1): parse → HMAC-verify →
 * JSON-parse → validate. Any failure (missing, tampered, malformed, invalid
 * shape) resolves to null so callers can treat the request as unauthenticated.
 */
async function readSignedCookie(req, name, key, isValid) {
  try {
    const token = parseCookies(req.headers.get("cookie"))[name];
```

**`readSignedCookie` (`S1`)** is the one place both signed cookies are read:
parse → HMAC-verify → JSON-parse → shape-validate. *Any* failure — missing,
tampered, malformed, expired, wrong shape — resolves to `null`, and the caller
simply treats the request as unauthenticated. There is no "partially valid"
session. Note `isValidSession` independently re-checks `exp` (defense in depth on
top of the cookie's own `Max-Age`) and requires `groups` to be an array.

Next, minting. The session stores only what the gate needs: `sub`, normalized
`groups`, `iat`/`exp`, and (optionally) the raw `id_token` — kept *solely* for
`id_token_hint` on logout and never forwarded to origin:

```bash
sed -n '58,112p' src/session.js

```

```output
    const payload = await unsign(token, key);
    if (!payload) return null;
    const value = JSON.parse(payload);
    return isValid(value) ? value : null;
  } catch {
    return null;
  }
}

export async function readSession(req, config) {
  return readSignedCookie(req, SESSION_COOKIE, await sessionSigningKey(config), isValidSession);
}

export async function mintSessionCookie(claims, config, idToken) {
  const now = Math.floor(Date.now() / 1000);
  const session = {
    sub: claims.sub,
    groups: normalizeAudiences(extractClaimGroups(claims, config.groupsClaim), config.audienceMap),
    iat: now, exp: now + config.sessionTtlSeconds,
  };
  // Keep the id_token server-side in KV keyed by an opaque session id (M-3): only
  // the jti — not PII or a 1–2 KB token — lives in the browser cookie. handleLogout
  // resolves the jti back to the id_token for `id_token_hint` (H9). The id_token is
  // never forwarded to origin (see origin.js, which only emits sub/groups).
  if (typeof idToken === "string" && idToken && config.kv) {
    const jti = crypto.randomUUID();
    await kvPutWithTtl(config.kv, idTokenKey(jti), idToken, config.sessionTtlSeconds);
    session.jti = jti;
  }
  const token = await sign(JSON.stringify(session), await sessionSigningKey(config));
  return serializeCookie(SESSION_COOKIE, token, { maxAge: config.sessionTtlSeconds });
}

export function clearSessionCookie() { return serializeCookie(SESSION_COOKIE, "", { maxAge: 0 }); }

/** Resolve (and delete) the id_token kept in KV for a session's logout hint (M-3). */
export async function takeSessionIdToken(session, config) {
  if (!session?.jti || !config.kv) return null;
  const idToken = await kvGetFresh(config.kv, idTokenKey(session.jti));
  await config.kv.delete(idTokenKey(session.jti)).catch(() => {});
  return idToken;
}

export async function mintStateCookie(state, config) {
  const token = await sign(JSON.stringify(state), await stateSigningKey(config));
  return serializeCookie(STATE_COOKIE, token, { maxAge: 600, sameSite: "Lax" });
}

export async function readStateCookie(req, config) {
  return readSignedCookie(req, STATE_COOKIE, await stateSigningKey(config), isValidLoginState);
}

export function clearStateCookie() { return serializeCookie(STATE_COOKIE, "", { maxAge: 0 }); }

/**
```

The mint path translates **IdP identity → gate session**:

- **`extractClaimGroups` (`H4`)** reads membership from exactly one configured
  claim and ignores non-array values — so a string-valued claim yields *no*
  groups rather than a malformed session (which would also cause a login loop).
- **`normalizeAudiences`** inverts the `audienceMap` (audience → raw IdP group
  values) into a reverse lookup, then maps the token's raw groups to the gate's
  internal audience labels. Unmapped values are logged as a "mapping miss" and
  dropped — the session carries audiences, not raw IdP group strings, which keeps
  policy authoring decoupled from IdP-specific group names.
- The **state cookie** is `SameSite=Lax` with a 600s `Max-Age` — long enough for
  a login round-trip, short enough to bound replay, and `Lax` so it survives the
  top-level redirect back from the IdP.

Both cookies are signed with the same `sessionKey`. The signing itself lives in
`cookies.js`.

### `src/cookies.js` — parse, serialize, sign, unsign

The cookie plumbing. `serializeCookie` always emits `HttpOnly` and `Secure` and
defaults `Path=/` with no `Domain` — exactly the constraints the `__Host-` prefix
requires. `sign`/`unsign` implement a compact `base64url(payload).base64url(sig)`
HMAC-SHA256 token, and `unsign` verifies in constant time:

```bash
sed -n '21,56p' src/cookies.js

```

```output
export function serializeCookie(name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${opts.path || "/"}`);
  if (opts.maxAge != null) parts.push(`Max-Age=${opts.maxAge}`);
  if (opts.domain) parts.push(`Domain=${opts.domain}`);
  parts.push(`SameSite=${opts.sameSite || "Lax"}`);
  if (opts.httpOnly !== false) parts.push("HttpOnly");
  if (opts.secure !== false) parts.push("Secure");
  return parts.join("; ");
}

// Per-purpose key cache (M-4). HKDF derivation is deterministic for a given
// (master secret, label), so derive once per isolate and reuse the CryptoKey
// rather than re-deriving on every sign/unsign.
const derivedKeyCache = new Map();

/**
 * Derive an independent HMAC-SHA-256 signing key from the master secret via
 * HKDF, scoped by `label` (M-4). This gives the session cookie and the
 * login-state cookie cryptographically separate keys — domain separation, so a
 * token minted for one purpose can never validate as the other — instead of
 * signing both with the same raw secret.
 * @returns {Promise<CryptoKey>}
 */
export function deriveCookieKey(masterSecret, label) {
  const cacheKey = `${masterSecret} ${label}`;
  let keyPromise = derivedKeyCache.get(cacheKey);
  if (!keyPromise) {
    keyPromise = (async () => {
      const ikm = await crypto.subtle.importKey("raw", utf8(masterSecret), "HKDF", false, ["deriveKey"]);
      return crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: utf8(label) },
        ikm,
        { name: "HMAC", hash: "SHA-256", length: 256 },
        false,
        ["sign", "verify"],
```

`unsign` recomputes the HMAC over the decoded payload and compares it against the
supplied signature with `timingSafeEqual`; on any mismatch or decode error it
returns `null`. Because the gate re-signs the payload it read (rather than
trusting the token's structure), a tampered payload simply fails the comparison.

### `src/encoding.js` — base64url + constant-time compare

The lowest layer: `TextEncoder`/`TextDecoder` wrappers, base64url encode/decode
(URL-safe alphabet, padding stripped), a JWT-segment JSON decoder, and the
constant-time string comparison used everywhere a secret or signature is checked:

```bash
cat src/encoding.js

```

```output
// Small base64url + text helpers shared by the JWT, PKCE and session modules.
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function utf8(str) { return encoder.encode(str); }
export function fromUtf8(bytes) { return decoder.decode(bytes); }

export function base64UrlEncode(bytes) {
  const arr = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes;
  let bin = "";
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlDecode(str) {
  const pad = str.length % 4 === 0 ? "" : "=".repeat(4 - (str.length % 4));
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function decodeJsonSegment(seg) { return JSON.parse(fromUtf8(base64UrlDecode(seg))); }

export function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
```

## 7. `src/oidc.js` — the OpenID Connect relying-party flow

This is the standards-conformant RP: authorization-code flow with **PKCE
(S256)**, `state`/`nonce` CSRF + replay protection, discovery-driven endpoints,
and RP-initiated logout. The `OidcClient` is constructed per request in
`index.js` and has three public methods — `startLogin`, `handleCallback`,
`handleLogout`.

### `startLogin` — kick off the redirect to the IdP

Called when a `protected` path has no valid session. It mints fresh `state`,
`nonce`, and a PKCE verifier/challenge, stashes them (plus the `returnTo` target)
in the short-lived signed state cookie, and 302s the browser to the IdP's
authorization endpoint:

```bash
sed -n '16,33p' src/oidc.js

```

```output
  async startLogin(req, url) {
    const discovery = await getDiscovery(this.config);
    const state = randomState();
    const nonce = randomNonce();
    const pkce = await createPkcePair();
    const authorize = new URL(discovery.authorization_endpoint);
    authorize.searchParams.set("response_type", "code");
    authorize.searchParams.set("client_id", this.config.clientId);
    authorize.searchParams.set("redirect_uri", this.config.redirectUri);
    authorize.searchParams.set("scope", this.config.scopes);
    authorize.searchParams.set("state", state);
    authorize.searchParams.set("nonce", nonce);
    authorize.searchParams.set("code_challenge", pkce.challenge);
    authorize.searchParams.set("code_challenge_method", pkce.method);
    const stateCookie = await mintStateCookie(
      { state, nonce, verifier: pkce.verifier, returnTo: url.pathname + url.search }, this.config);
    return new Response(null, { status: 302, headers: { location: authorize.toString(), "set-cookie": stateCookie } });
  }
```

The PKCE verifier stays *only* in the signed cookie on the user's browser; only
its SHA-256 `challenge` travels to the IdP. The matching `code_verifier` is sent
later in the token exchange, which is what binds the eventual callback to *this*
browser. `src/pkce.js` is the generator:

```bash
cat src/pkce.js

```

```output
import { base64UrlEncode, utf8 } from "./encoding.js";

function randomString(bytes = 32) {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return base64UrlEncode(buf);
}

export function randomState() { return randomString(16); }
export function randomNonce() { return randomString(16); }

export async function createPkcePair() {
  const verifier = randomString(32);
  const digest = await crypto.subtle.digest("SHA-256", utf8(verifier));
  return { verifier, challenge: base64UrlEncode(digest), method: "S256" };
}
```

`state`/`nonce` are 16 random bytes and the verifier 32, all from the CSPRNG
`crypto.getRandomValues`. `method: "S256"` declares the SHA-256 challenge — the
strong PKCE mode.

### `handleCallback` — the IdP redirects back

The most security-dense method. The IdP sends the browser back to
`/.auth/callback?code=…&state=…`. The gate must prove this callback belongs to a
login *it* started, exchange the code, and validate the resulting token before
trusting any identity:

```bash
sed -n '35,86p' src/oidc.js

```

```output
  async handleCallback(req, url) {
    const saved = await readStateCookie(req, this.config);
    if (!saved) return fail(req, 400, "invalid_login", "missing_or_expired_state");

    const returnedState = url.searchParams.get("state") || "";
    if (!timingSafeEqual(returnedState, saved.state)) return fail(req, 400, "invalid_login", "state_mismatch");

    // Single-use state requires a store to record consumption. Without KV we
    // cannot prevent replay, so we fail closed rather than silently skip (H5).
    if (!this.config.kv) return fail(req, 503, "login_unavailable", "state_store_unbound");

    // Best-effort single-use check (N9). CF KV is eventually consistent, so this
    // stops practical replays, not a perfectly-timed race. Marked consumed once
    // the state validates; a later failure still burns the state (user retries),
    // which is the safe direction.
    const usedKey = `state-used:${saved.state}`;
    if (await kvGetFresh(this.config.kv, usedKey)) return fail(req, 400, "invalid_login", "state_replayed");
    await kvPutWithTtl(this.config.kv, usedKey, true, STATE_TTL_SECONDS);

    const idpError = url.searchParams.get("error");
    if (idpError) return fail(req, 401, "login_failed", `idp_error:${idpError}`);

    const code = url.searchParams.get("code");
    if (!code) return fail(req, 400, "invalid_login", "missing_code");

    const discovery = await getDiscovery(this.config);
    const body = new URLSearchParams({
      grant_type: "authorization_code", code, redirect_uri: this.config.redirectUri,
      client_id: this.config.clientId, client_secret: this.config.clientSecret, code_verifier: saved.verifier,
    });
    const tokenRes = await fetch(discovery.token_endpoint, {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: body.toString(),
    });
    if (!tokenRes.ok) return fail(req, 401, "login_failed", `token_exchange_${tokenRes.status}`);

    const tokens = await tokenRes.json();
    if (!tokens.id_token) return fail(req, 401, "login_failed", "no_id_token");

    let claims;
    try {
      claims = await verifyIdToken(tokens.id_token, this.config, saved.nonce,
        { code, accessToken: tokens.access_token });
    } catch (e) {
      return fail(req, 400, "invalid_token", e.message);
    }

    const sessionCookie = await mintSessionCookie(claims, this.config, tokens.id_token);
    const headers = new Headers({ location: safeReturnTo(saved.returnTo, url.origin) });
    headers.append("set-cookie", sessionCookie);
    headers.append("set-cookie", clearStateCookie());
    return new Response(null, { status: 302, headers });
  }
```

The gauntlet, in order:

1. **State cookie present?** No signed state cookie → `400`. This cookie is the
   proof the gate started this login.
2. **`state` matches** (constant-time) → blocks CSRF / cross-login mixups.
3. **KV bound?** Single-use enforcement needs a store. No KV → `503`, **fail
   closed (`H5`)** rather than silently skipping replay protection.
4. **State not already used (`N9`)** → best-effort single-use via a
   `state-used:<state>` KV marker. CF KV is eventually consistent, so this stops
   practical replay (not a perfectly-timed race). The state is burned *before*
   the exchange, so even a later failure consumes it — the safe direction.
5. **IdP `error` param** → `401` (and note: the raw error is logged, never echoed).
6. **`code` present** → exchange it at the token endpoint with the PKCE
   `code_verifier` from the cookie. A non-2xx or missing `id_token` → `401`.
7. **`verifyIdToken`** validates the token (next section). Any failure → generic
   `400 invalid_token`.
8. **Success** → mint the session cookie, clear the state cookie, and 302 to
   `returnTo`.

Notice that a validation failure returns a generic error, **not** a re-redirect
into login — a rejection is observable rather than an infinite loop. And
`returnTo` is laundered through `safeReturnTo` (below) so it can only ever be a
same-origin path:

```bash
sed -n '113,131p' src/oidc.js

```

```output
}

function safeReturnTo(returnTo, origin) {
  if (typeof returnTo !== "string" || !returnTo.startsWith("/")) return "/";
  try {
    const resolved = new URL(returnTo, origin);
    if (resolved.origin !== origin) return "/";   // catches //evil.com and /\evil.com
    return resolved.pathname + resolved.search;
  } catch {
    return "/";
  }
}

/** Log the real reason server-side, return a generic body to the caller (H7). */
function fail(req, status, code, detail) {
  console.warn("callback rejected", { status, code, detail });
  return errorResponse(status, code, {
    requestId: requestId(req),
    wwwAuthenticate: status === 401 ? 'Bearer error="invalid_token"' : undefined,
```

**`safeReturnTo`** is an open-redirect guard: it requires a leading `/`, then
resolves against the real origin and rejects anything whose resolved origin
differs — which catches the `//evil.com` and `/\evil.com` protocol-relative
tricks. Anything suspicious collapses to `/`.

**`fail` (`H7`)** is the single choke point for callback errors: it logs the real
`detail` server-side (`state_mismatch`, `token_exchange_401`, …) but returns only
a generic stable `code` plus a `request_id`. The IdP `error` parameter and
exception messages are never reflected to the caller.

### `handleLogout` — RP-initiated logout

Logout is state-changing, so it requires `POST` — a cross-site `GET` can't force
a logout (`H9` / CSRF). It clears both gate cookies and, if the IdP advertises an
`end_session_endpoint`, redirects there with `id_token_hint` (the one place the
retained `id_token` is used):

```bash
sed -n '88,110p' src/oidc.js

```

```output
  async handleLogout(req, url) {
    // RP-initiated logout is state-changing; require POST so a cross-site GET
    // cannot force a logout (CSRF — H9).
    if (req.method !== "POST") {
      return errorResponse(405, "method_not_allowed", { requestId: requestId(req) });
    }

    const session = await readSession(req, this.config);
    // Resolve (and clean up) the server-side id_token kept for id_token_hint (M-3).
    const idTokenHint = await takeSessionIdToken(session, this.config);
    const discovery = await getDiscovery(this.config).catch(() => ({}));
    const headers = new Headers();
    headers.append("set-cookie", clearSessionCookie());
    headers.append("set-cookie", clearStateCookie());
    if (discovery.end_session_endpoint) {
      const logout = new URL(discovery.end_session_endpoint);
      logout.searchParams.set("client_id", this.config.clientId);
      logout.searchParams.set("post_logout_redirect_uri", `${url.origin}/`);
      if (idTokenHint) logout.searchParams.set("id_token_hint", idTokenHint);
      headers.set("location", logout.toString());
      return new Response(null, { status: 302, headers });
    }
    headers.set("location", "/");
```

The local cookies are always cleared first, and discovery is wrapped in
`.catch(() => ({}))` so a discovery outage still produces a clean local logout
(falling back to a redirect to `/`) rather than leaving the user logged in.

## 8. `src/jwt.js` — discovery, JWKS, and id_token validation

This is the cryptographic heart of the RP, and where most of the `N*`
conformance markers live. Three responsibilities: fetch and **validate**
discovery, fetch JWKS and pick the right key, and fully validate the `id_token`.

### Discovery — never trusted blindly (`H8`)

`getDiscovery` caches the OP's `/.well-known/openid-configuration`, but re-runs
`assertValidDiscovery` on *every* read — so even a poisoned cache entry can't slip
through. The issuer must match what we configured, and every endpoint we'll
redirect to or POST to must be HTTPS:

```bash
sed -n '6,47p' src/jwt.js

```

```output
export async function getDiscovery(config) {
  const doc = await cachedJson(config.kv, `discovery:${config.issuer}`, async () => {
    const res = await fetch(`${config.issuer}/.well-known/openid-configuration`);
    if (!res.ok) throw new Error(`discovery fetch failed: ${res.status}`);
    return res.json();
  });
  // Don't trust the discovery JSON blindly (H8): the issuer must match what we
  // were configured with, and the endpoints we will redirect/POST to must be
  // https. Validate on every read so a poisoned cache entry can't slip through.
  assertValidDiscovery(doc, config.issuer);
  return doc;
}

function assertValidDiscovery(doc, issuer) {
  if (!doc || typeof doc !== "object") throw new Error("discovery document malformed");
  if (typeof doc.issuer !== "string" || doc.issuer.replace(/\/$/, "") !== issuer) {
    throw new Error("discovery issuer mismatch");
  }
  // Endpoints must be https AND share the issuer's origin (M-1). The discovery
  // doc is cached in KV; a poisoned entry pointing token_endpoint at an attacker
  // host would exfiltrate client_secret + the auth code, and a poisoned jwks_uri
  // would let attacker-signed id_tokens verify. Pinning to the issuer origin
  // (host + scheme + port) closes both. Note: multi-host IdPs such as Google
  // serve endpoints off a different origin and would need a code-level allowlist.
  const issuerOrigin = originOf(issuer);
  for (const ep of ["authorization_endpoint", "token_endpoint", "jwks_uri"]) {
    if (!isHttpsUrl(doc[ep])) throw new Error(`discovery ${ep} must be an https URL`);
    if (originOf(doc[ep]) !== issuerOrigin) throw new Error(`discovery ${ep} must share the issuer origin`);
  }
  if (doc.end_session_endpoint !== undefined) {
    if (!isHttpsUrl(doc.end_session_endpoint)) throw new Error("discovery end_session_endpoint must be an https URL");
    if (originOf(doc.end_session_endpoint) !== issuerOrigin) throw new Error("discovery end_session_endpoint must share the issuer origin");
  }
}

/** URL origin (scheme://host:port), or null when the value isn't a parseable URL. */
function originOf(value) {
  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
```

### `verifyIdToken` — the full validation gauntlet

This is the function the callback depends on. It verifies the RS256 signature
against the JWKS, then checks every claim that matters. The inline `N*` tags map
each check to a conformance negative-test:

```bash
sed -n '56,96p' src/jwt.js

```

```output
  }
}

async function getJwks(config, jwksUri, { force = false } = {}) {
  return cachedJson(config.kv, `jwks:${jwksUri}`, async () => {
    const res = await fetch(jwksUri);
    if (!res.ok) throw new Error(`jwks fetch failed: ${res.status}`);
    return res.json();
  }, { force });
}

/**
 * Verify an id_token. Throws on any failure (caller converts to a 400/401).
 * @param {string} idToken
 * @param {import("./policy.js").Config} config
 * @param {string} expectedNonce
 * @param {{ code?: string, accessToken?: string }} [hashes] for c_hash/at_hash checks
 */
export async function verifyIdToken(idToken, config, expectedNonce, hashes = {}) {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("malformed JWT");
  const [headerB64, payloadB64, sigB64] = parts;
  const header = decodeJsonSegment(headerB64);
  const claims = decodeJsonSegment(payloadB64);

  if (header.alg !== "RS256") throw new Error(`unsupported alg: ${header.alg}`); // N2

  // --- signature, with single JWKS refetch on kid miss (N7) ---
  const discovery = await getDiscovery(config);
  const key = await importSigningKey(config, discovery.jwks_uri, header.kid);
  const signingInput = utf8(`${headerB64}.${payloadB64}`);
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5", key, base64UrlDecode(sigB64), signingInput);
  if (!valid) throw new Error("invalid token signature"); // N1

  // --- claims ---
  const now = Math.floor(Date.now() / 1000);
  const skew = 60;
  if (typeof claims.iss !== "string" || claims.iss.replace(/\/$/, "") !== config.issuer)
    throw new Error("iss mismatch"); // N3
  if (!audienceMatches(claims.aud, config.clientId)) throw new Error("aud mismatch"); // N4
```

Every check, mapped to its conformance marker:

- **`N2` — `alg` must be `RS256`.** The algorithm is pinned, so the `alg: "none"`
  and HS256-key-confusion attacks are rejected before any signature work.
- **`N1` — signature must verify** against the JWKS key using `RSASSA-PKCS1-v1_5`.
- **`N3` — `iss`** must equal the configured issuer (trailing slash tolerated).
- **`N4` / `N4b` — `aud`** must include our `client_id`; `azp` (when present) must
  be us; and a multi-valued `aud` *requires* an `azp` naming us.
- **`sub`** must be a non-empty string.
- **`N5` — `exp`** in the future and **`nbf`/`iat`** sane, all with a 60s clock
  skew allowance. `iat` is required; a future `iat` is rejected.
- **`N6` — `nonce`** must equal the one minted in `startLogin` (replay binding).
- **`N11` — `c_hash`/`at_hash`** validated *when present*, using the OIDC
  left-half-SHA-256 construction and a constant-time compare.

The key-selection logic handles rotation gracefully. `importSigningKey` matches
the token's `kid` against the JWKS; on a miss it refetches the JWKS **exactly
once** (`N7`) to pick up a rotated key before giving up:

```bash
sed -n '98,144p' src/jwt.js

```

```output
  if (Array.isArray(claims.aud) && claims.aud.length > 1 && claims.azp !== config.clientId)
    throw new Error("azp required for multi-valued aud");                            // N4b
  if (typeof claims.sub !== "string" || claims.sub.length === 0) throw new Error("sub required");
  if (typeof claims.exp !== "number" || claims.exp + skew < now) throw new Error("token expired"); // N5
  if (typeof claims.nbf === "number" && claims.nbf - skew > now) throw new Error("token not yet valid");
  if (typeof claims.iat !== "number") throw new Error("iat required");
  if (typeof claims.iat === "number" && claims.iat - skew > now) throw new Error("token iat in the future");
  if (expectedNonce && claims.nonce !== expectedNonce) throw new Error("nonce mismatch"); // N6

  // --- c_hash / at_hash when the corresponding artifact is present (N11) ---
  if (hashes.code && claims.c_hash && !timingSafeEqual(claims.c_hash, await leftHalfHash(hashes.code)))
    throw new Error("c_hash mismatch");
  if (hashes.accessToken && claims.at_hash && !timingSafeEqual(claims.at_hash, await leftHalfHash(hashes.accessToken)))
    throw new Error("at_hash mismatch");

  return claims;
}

async function importSigningKey(config, jwksUri, kid) {
  let jwk = selectSigningJwk(await getJwks(config, jwksUri), kid);
  if (!jwk) {                                  // kid miss / rotation → refetch JWKS exactly once
    jwk = selectSigningJwk(await getJwks(config, jwksUri, { force: true }), kid);
  }
  if (!jwk) throw new Error(`no JWKS key for kid ${kid ?? "(absent)"}`);
  return crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
}

/**
 * Pick the RSA verification key. Consider only keys usable for RS256 signature
 * verification: `kty:"RSA"`, not `use:"enc"`, and `alg` either absent or `RS256`
 * — so a JWKS that also serves an encryption RSA key can't have it chosen on the
 * kid-less single-key path. When the token header carries a `kid`, match it
 * exactly (a mismatch is a rotation → caller refetches once, then rejects). When
 * the header omits `kid`, the choice is only unambiguous if exactly one signing
 * key remains — OIDC permits omitting `kid` then; multiple → reject.
 */
function selectSigningJwk(jwks, kid) {
  const signing = (jwks.keys || []).filter(
    (k) => k.kty === "RSA" && k.use !== "enc" && (k.alg === undefined || k.alg === "RS256"),
  );
  if (kid) return signing.find((k) => k.kid === kid) || null;
```

`selectSigningJwk` is careful about the no-`kid` case: OIDC only permits omitting
`kid` when the JWKS has exactly one RSA key, so a `kid`-less token against a
multi-key JWKS is rejected rather than guessed. The imported key is restricted to
`["verify"]` and non-extractable.

`cachedJson` is the discovery/JWKS cache; its `force` flag is exactly what powers
the one-shot rotation refetch. It rides on the shared KV freshness wrapper, which
is the next module.

## 9. `src/kv.js` and `src/http.js` — shared infrastructure helpers

### `src/kv.js` — freshness-wrapped KV (`S3`)

Cloudflare KV's own `expirationTtl` is lazy, so the gate enforces freshness *in
code*: every value is stored as `{ value, expires }` and only returned if still
within its absolute TTL. Both the discovery/JWKS cache and the single-use
login-state marker go through these two functions, so the wrapper logic lives in
one place:

```bash
sed -n '13,24p' src/kv.js

```

```output
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
```

Both functions no-op safely when `kv` is `null` (unbound binding). The `now`
parameter is injected for deterministic testing. Writing also sets the native
`expirationTtl` so KV eventually evicts the key on its own — belt and braces.

### `src/http.js` — one place for response policy (`S2`)

Every gate response is built here, so the no-store cache policy and the baseline
hardening headers exist in exactly one place — and error bodies are *deliberately
generic* (`H7`): a stable code plus a `request_id`, never an exception message or
a raw IdP error:

```bash
sed -n '12,48p' src/http.js

```

```output
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
```

`requestId` prefers Cloudflare's `cf-ray` so an operator can join a user's report
to both the edge log and the origin log; `errorResponse` is the generic-body
helper every denial in `index.js` and `fail` in `oidc.js` route through.

## 10. `src/origin.js` — forwarding to the EDS origin

The terminal step for any allowed request. It rewrites the request for AEM's
BYO-CDN contract, injects trusted identity headers, and — for non-public tiers —
guarantees per-user content can never be cached or cross-served at the edge:

```bash
sed -n '14,67p' src/origin.js

```

```output
export async function forwardToOrigin(request, session, tier, config, pathname) {
  const inUrl = new URL(request.url);
  const path = pathname || inUrl.pathname;
  const originUrl = `https://${config.originHostname}${path}${inUrl.search}`;

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
  const out = new Response(res.body, res);
  stripGateSetCookies(out.headers);
  if (!cacheOff) return out;

  out.headers.set("cache-control", NO_STORE);
  out.headers.delete("age");
  return out;
}

function stripGateSetCookies(headers) {
  const setCookies = headers.getSetCookie ? headers.getSetCookie() : [headers.get("set-cookie")].filter(Boolean);
  if (setCookies.length === 0) return;

  headers.delete("set-cookie");
  for (const line of setCookies) {
    if (!GATE_COOKIE_NAMES.has(cookieName(line))) headers.append("set-cookie", line);
  }
}

function cookieName(setCookieLine) {
  return setCookieLine.slice(0, setCookieLine.indexOf("=")).trim();
}
```

The header hygiene is the crux:

- **`cookie` is deleted** — the gate session never leaks to origin.
- **Inbound `x-auth-*` headers are stripped before re-adding them.** A client
  can't spoof `x-auth-subject`/`x-auth-groups`; the origin only ever sees what
  *this* worker set from the verified session. Same for `x-push-invalidation`.
- **BYO-CDN headers**: `Host` and `X-Forwarded-Host` are set per AEM's contract,
  push-invalidation is opt-in.
- **Identity forwarding**: `x-auth-subject`/`x-auth-groups` carry the verified
  identity; `x-auth-request-id` (the `cf-ray`) lets the origin log correlate with
  the edge log.

The **cache carve-out** is the other half. For any non-public tier, the outbound
fetch sets `cf.cacheTtl: 0` / `cacheEverything: false`, and the response is
rewritten with `cache-control: private, no-store` and its `age` header stripped —
so per-user content can never be stored at the edge or cross-served to another
user. Public responses pass through with origin caching intact.

Finally, **`stripGateSetCookies`** scrubs any `Set-Cookie` from the origin whose
name collides with the gate's own cookies (`__Host-gate_session`/`_login`) — the
origin can never overwrite or forge the gate's session cookie. That closes the
loop on the delivery worker; on to the publisher side.

## 11. The publisher side — `policy-publisher.js` + `publisher-worker.js`

So far everything consumed a *signed policy snapshot* from KV. This is where that
snapshot is produced. A content author edits an `access-control` sheet in DA
(Document Authoring); the publisher worker fetches it, validates and normalizes
it into rules, signs the result, and writes it to KV. The delivery worker's
`verifyPolicyEnvelope` (§4) is the other end of this trust boundary.

### `src/policy-publisher.js` — compile sheet rows into a signed policy

`compilePolicyRows` is the validator. It turns author-facing rows
(`path`, `tier`, `audience`, `description`) into normalized rules, collecting
`errors` (block publish), `warnings` (surface but allow), and `ignored_rules`
(silently-reserved paths). Author-facing row numbers start at 2 (header is line 1):

```bash
sed -n '34,82p' src/policy-publisher.js

```

```output

    const path = stringValue(row.path).trim();
    const tier = stringValue(row.tier).trim().toLowerCase();
    const audience = parseAudience(row.audience);
    const hasAnyEnforcementValue = path || tier || audience.length > 0;

    if (!path || !tier) {
      if (hasAnyEnforcementValue) {
        errors.push({ row: rowNumber, field: !path ? "path" : "tier", message: "partial policy row" });
      }
      return;
    }

    if (!path.startsWith("/")) errors.push({ row: rowNumber, field: "path", message: "path must start with /" });
    if (path.includes("?") || path.includes("#"))
      errors.push({ row: rowNumber, field: "path", message: "path must not contain query or fragment" });
    if (!TIERS.has(tier)) errors.push({ row: rowNumber, field: "tier", message: `invalid tier: ${tier}` });
    if (tier === "public" && audience.length > 0)
      errors.push({ row: rowNumber, field: "audience", message: "public rows must not specify audience" });
    // Deny-by-default guard (H2): a DA author must not be able to silently make
    // the whole site public. A site-wide `/**` public rule is rejected outright;
    // a top-level `/*` public rule is allowed but surfaced as a warning so the
    // breadth is never silent.
    if (tier === "public" && path === "/**")
      errors.push({ row: rowNumber, field: "path", message: "public /** would expose the entire site; scope public paths explicitly" });
    else if (tier === "public" && path === "/*")
      warnings.push({ row: rowNumber, field: "path", message: "public /* exposes all top-level paths" });
    if ((tier === "protected" || tier === "secured") && audience.length === 0)
      warnings.push({ row: rowNumber, field: "audience", message: `${tier} row allows any authenticated user` });

    for (const value of audience) {
      if (!knownAudiences.has(value)) {
        errors.push({ row: rowNumber, field: "audience", message: `unknown audience: ${value}` });
      }
    }

    if (errors.some((err) => err.row === rowNumber)) return;

    const rule = { path, tier };
    if (audience.length > 0) rule.audience = audience;

    const reserved = workerManagedPaths.find((pattern) => patternsOverlap(path, pattern));
    if (reserved) {
      ignored_rules.push({ row: rowNumber, path, reason: "reserved_path", reserved_path: reserved });
      return;
    }

    rules.push({ ...rule, row: rowNumber });
  });
```

The author-protection rules, in order of severity:

- **Partial rows** (path xor tier) are an error — but a *fully blank* row is
  skipped, so trailing empty sheet rows don't break a publish.
- **Path hygiene**: must start with `/`, no query/fragment; **tier** must be one
  of the three; **public rows can't carry an audience** (nonsensical).
- **Deny-by-default guard (`H2`)** — the headline check: a DA author cannot
  silently expose the whole site. A public `/**` is rejected outright; a public
  `/*` (top-level only) is allowed but flagged as a warning so the breadth is
  never silent.
- **Unknown audiences are errors** — an audience that isn't in the site's
  `audience_map` would silently grant nothing, so it blocks publish instead.
- **Reserved-path collisions** — a rule overlapping a worker-managed path
  (`/scripts/**`, `/.auth/**`, …) is dropped into `ignored_rules`, never
  enforced. The worker owns infrastructure paths; DA can't reclassify them.

After per-row processing, `validateEqualSpecificityOverlaps` rejects two rules of
*equal* specificity that overlap — because then "most specific wins" (§5) would
be ambiguous and which rule applies would be non-deterministic:

```bash
sed -n '184,214p' src/policy-publisher.js

```

```output
function validateEqualSpecificityOverlaps(rules, errors) {
  for (let i = 0; i < rules.length; i++) {
    for (let j = i + 1; j < rules.length; j++) {
      if (specificity(rules[i].path) !== specificity(rules[j].path)) continue;
      if (!patternsOverlap(rules[i].path, rules[j].path)) continue;
      errors.push({
        row: rules[j].row,
        field: "path",
        message: `equal-specificity overlap with row ${rules[i].row}: ${rules[j].path}`,
      });
    }
  }
}

function patternsOverlap(a, b) {
  const samples = [...patternSamples(a), ...patternSamples(b)];
  return samples.some((sample) => matchGlob(a, sample) && matchGlob(b, sample));
}

function patternSamples(pattern) {
  const samples = new Set();
  samples.add(pattern.replaceAll("**", "x/y").replaceAll("*", "x"));
  samples.add(pattern.replaceAll("**", "x").replaceAll("*", "x"));
  if (pattern.endsWith("/**")) {
    const base = pattern.slice(0, -3);
    samples.add(base);
    samples.add(`${base}/`);
    samples.add(`${base}/x`);
  }
  return samples;
}
```

Overlap is detected by generating representative sample paths for each pattern
and testing whether both patterns match the same sample — reusing `matchGlob`
and `specificity` *imported from `policy.js`*. That shared import is deliberate:
the publisher validates with the exact same matching semantics the delivery
worker enforces, so validation can't drift from enforcement.

Then the payload is assembled (`schema_version`, `site_id`, `version`,
`published_at`, `rules`, `ignored_rules`) and signed. `publishPolicyRows` writes
three KV keys — `current`, a versioned archive, and a `status` record — but only
writes the policy when there are zero errors:

```bash
sed -n '98,145p' src/policy-publisher.js

```

```output
export async function buildSignedPolicyEnvelope(rows, options) {
  const result = compilePolicyRows(rows, options);
  if (result.errors.length > 0) return { ...result, envelope: null };
  return {
    ...result,
    envelope: {
      payload: result.payload,
      signature: await signPolicyPayload(result.payload, options.policyHmacKey),
    },
  };
}

export async function publishPolicyRows(rows, options) {
  const result = await buildSignedPolicyEnvelope(rows, options);
  const status = buildStatus(result, options);

  if (result.errors.length > 0) {
    await options.kv.put(policyStatusKey(options.siteId), JSON.stringify(status));
    return { ...result, status, wroteCurrent: false };
  }

  const currentKey = policyCacheKey(options.siteId);
  await options.kv.put(currentKey, JSON.stringify(result.envelope));
  await options.kv.put(policyVersionKey(options.siteId, result.payload.version), JSON.stringify(result.envelope));
  await options.kv.put(policyStatusKey(options.siteId), JSON.stringify(status));
  return { ...result, status, wroteCurrent: true };
}

export function extractRowsFromDaDocument(document) {
  if (Array.isArray(document)) return document;
  if (!isRecord(document)) throw new Error("DA policy document must be an object or array");

  const accessControl = document["access-control"];
  if (Array.isArray(accessControl)) return accessControl;
  if (isRecord(accessControl) && Array.isArray(accessControl.data)) return accessControl.data;
  if (isRecord(accessControl) && Array.isArray(accessControl.rows)) return accessControl.rows;

  if (Array.isArray(document.data)) return document.data;
  if (Array.isArray(document.rows)) return document.rows;

  for (const value of Object.values(document)) {
    if (Array.isArray(value)) return value;
    if (isRecord(value) && Array.isArray(value.data)) return value.data;
    if (isRecord(value) && Array.isArray(value.rows)) return value.rows;
  }

  throw new Error("No policy rows found in DA document");
}
```

On a validation failure only the **status** record is written — so an operator
can see *why* a publish failed — while the live `current` policy is left
untouched. The delivery worker keeps enforcing the last good snapshot; a bad edit
never takes down access. On success, `current` (what the delivery worker reads),
a `version:<id>` archive, and the `status` record are all written.

`extractRowsFromDaDocument` is forgiving about DA's document shape — it accepts a
bare array, an `access-control` sheet, or `{data}`/`{rows}` envelopes at several
nesting levels — because the exact JSON shape `admin.da.live` returns varies.

### `src/publisher-worker.js` — the HTTP front door

The publisher's `fetch` handler ties it together: CORS preflight, method/binding
guards, a DA bearer token, site allow-listing, fetch-from-DA, compile, publish:

```bash
sed -n '20,68p' src/publisher-worker.js

```

```output
export async function handlePublisherRequest(request, env) {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request) });
  if (request.method !== "POST") return json(request, { error: "method_not_allowed" }, 405);
  if (!env.OIDC_CACHE) return json(request, { error: "missing_kv_binding" }, 500);
  if (!env.POLICY_HMAC_KEY) return json(request, { error: "missing_policy_hmac_key" }, 500);

  const daToken = bearerToken(request.headers.get("authorization"));
  if (!daToken) return json(request, { error: "missing_da_token" }, 401);

  let event;
  try {
    event = await request.json();
  } catch {
    return json(request, { error: "invalid_json" }, 400);
  }

  let siteId;
  try {
    siteId = resolveSiteId(event);
  } catch (err) {
    return json(request, { error: "invalid_site", message: err.message }, 400);
  }

  const sites = loadSiteConfig(env);
  const siteConfig = sites[siteId];
  if (!siteConfig) return json(request, { error: "site_not_allowed", site_id: siteId }, 403);

  let document;
  try {
    document = await fetchDaPolicy(siteId, daToken, env.DA_BASE_URL);
  } catch (err) {
    return json(request, { error: "da_fetch_failed", site_id: siteId, da_url: err.daUrl || null, message: err.message }, 502);
  }

  let rows;
  try {
    rows = extractRowsFromDaDocument(document);
  } catch (err) {
    return json(request, { error: "invalid_da_policy_document", site_id: siteId, message: err.message }, 422);
  }

  const result = await publishPolicyRows(rows, {
    siteId,
    policyHmacKey: env.POLICY_HMAC_KEY,
    audienceMap: siteConfig.audience_map || {},
    workerManagedPaths: siteConfig.worker_managed_paths || DEFAULT_WORKER_MANAGED_PATHS,
    sourceVersion: event.source_version || document.source_version || document.version,
    kv: env.OIDC_CACHE,
  });
```

The request flow, with distinct status codes at each gate:

- **`OPTIONS`** → CORS preflight; **non-`POST`** → `405`.
- **Missing KV / HMAC binding** → `500` (deployment misconfiguration).
- **DA bearer token** required (`401` if absent) — the *caller's* DA credential
  is what authorizes reading the sheet; the publisher never holds DA creds itself.
- **`resolveSiteId`** accepts `site_id` or `org`+`site`; an unknown shape is `400`.
- **Site allow-list (`403`)** — the `siteId` must be present in the
  `PUBLISHER_SITES` config. The publisher only services explicitly-configured
  sites, and that config supplies each site's `audience_map` and
  `worker_managed_paths`.
- **`fetchDaPolicy`** calls `admin.da.live` with the caller's token; a non-2xx is
  surfaced as `502`. A malformed document is `422`.
- Then **`publishPolicyRows`** does the §11 compile/sign/write.

The remainder of the handler maps the result to a response — `422` with the
`errors`/`warnings`/`ignored_rules` on validation failure, or a `published`
summary on success — and CORS is locked to an explicit origin allow-list:

```bash
sed -n '9,12p;143,153p' src/publisher-worker.js

```

```output
const ALLOWED_CORS_ORIGINS = [
  /^https:\/\/([a-z0-9-]+--)?authz--cpilsworth\.aem\.(live|page)$/,
  /^https:\/\/da\.live$/,
];
function corsHeaders(request) {
  const origin = request.headers.get("origin") || "";
  const allowed = ALLOWED_CORS_ORIGINS.some((pattern) => pattern.test(origin));
  return {
    "access-control-allow-origin": allowed ? origin : "null",
    vary: "Origin",
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-headers": "Authorization, Content-Type, Accept",
    "access-control-max-age": "86400",
  };
}
```

CORS is reflected only for origins matching the explicit allow-list (the site's
`aem.live`/`aem.page` preview/live hosts and `da.live`); anything else gets the
literal `"null"` origin. `Vary: Origin` keeps that reflection from being cached
across origins.

## Putting it together

The two halves meet at one artifact — the **signed policy snapshot in KV**:

    DA access-control sheet
            |  (author edits rows)
            v
    publisher-worker.fetch --auth + allow-list--> fetchDaPolicy(admin.da.live)
            |
            v
    policy-publisher.compilePolicyRows --validate (H2, overlaps, audiences)--> sign (HMAC)
            |
            v
       KV: policy:current:{org/site}  <-----------------------+
                                                              | verifyPolicyEnvelope (section 4)
    Browser -> index.fetch -> normalizePath -> loadRuntimePolicy
            |                                       |
            v                                       v
       gate-owned routes                       classify -> tier
       (/.auth/callback, /.auth/logout)             |
            |                                       +- public     --> forwardToOrigin
            v                                       +- protected  --> readSession / startLogin
       OidcClient -> verifyIdToken                  +- secured    --> readSession / 401
            |                                       +- wrong aud  --> 403
            v
       mintSessionCookie -> 302 back to returnTo

The design's throughline: **deny-by-default at every layer**, a **single
canonical path** the gate both classifies and forwards, **identity verified once
then carried in a locally-signed session**, and a **signed, validated policy**
that an author can edit but can never use to silently widen access. The `H*`/`N*`
tags scattered through the source are the index to those guarantees.
