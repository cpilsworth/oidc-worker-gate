# oidc-worker-gate

> **Status: plan / design doc.** This folder currently contains the implementation
> plan only. No worker code is written yet — see [Milestones](#milestones).

A **Cloudflare Worker** that sits in front of an **AEM Edge Delivery Services (EDS)**
origin and acts as an OpenID Connect **relying party (RP)**. Unlike a blanket
"auth on every request" gate, this worker classifies each request path into one of
three tiers and behaves accordingly:

| Tier | Example paths | Unauthenticated behavior |
| --- | --- | --- |
| **public** | `/`, `/blog/*`, `/nav`, `/footer`, `*.css`, `/media/*` | Forward to origin, no auth, stays cacheable |
| **protected** (trigger auth) | `/members/*`, `/account/*` | **302 → IdP** authorization-code+PKCE login |
| **secured** (validate auth) | `/api/*`, `/secure-data/*` | **401 JSON**, no redirect (for `fetch`/XHR) |

This is the Cloudflare sibling of [`../oidc-edge-gate`](../oidc-edge-gate) (which
targets the AEM Edge Function / Fastly Compute runtime). The OIDC *mechanics* —
auth-code+PKCE, RS256 ID-token validation, HMAC-signed local session — are carried
over almost verbatim and port cleanly to Web Crypto. This doc focuses on the three
deltas: **Cloudflare runtime & bindings**, the **three-tier path policy**, and the
**RP standards-conformance testing** (see [`conformance-testing.md`](./conformance-testing.md)).

## Why a worker in front of EDS

AEM EDS already serves from a fast CDN-backed origin (`*.aem.live`). Putting auth
*inside* the site means every page/asset/API must remember to check it, and
unauthenticated requests still reach origin. A worker on the customer domain proxies
to the EDS origin and enforces access **before** anything is served — so nothing
protected reaches the origin without a valid session, public content stays fully
cacheable, and the EDS project itself stays oblivious to OIDC.

### Origin reachability precondition

The worker only protects requests that pass through the customer-domain route. If the
underlying `main--<site>--<org>.aem.live` origin remains directly reachable and serves the
same protected URLs, then those URLs are not confidential — callers can bypass the worker.
For protected content, either enforce origin access separately (shared secret/header,
network controls, or an origin-side check that only trusts worker-injected headers) or
treat the worker as protecting the customer-domain experience, not the raw EDS hostname.

## Tier behaviors (confirmed)

The request says *public for some paths, trigger authentication for others, validate
authentication for others* — three distinct tiers:

- **protected = "trigger authentication"** → for top-level / navigational HTML.
  A missing session yields an **interactive 302 redirect** into the IdP login flow,
  landing the user back where they started. *(Confirmed approach.)*
- **secured = "validate authentication"** → for API / data / `fetch` endpoints.
  A missing or invalid session yields **`401 Unauthorized` (JSON)** with no redirect,
  because redirecting an XHR/`fetch` to an HTML IdP page is useless to the caller.

Both tiers, once a session *is* present, additionally enforce any `audience` attached to
the matching policy row; authenticated-but-unauthorized → `403`.

**Precedence:** the most specific matching rule wins. **Unmatched paths** fall to a
configurable `default_tier` — recommend `protected` (deny-by-default) and enumerate
public paths explicitly, so a new route is never accidentally exposed.

> **Optional — content-negotiated response.** The *only* difference between
> `protected` and `secured` is the unauthenticated response (302 vs 401); the
> session/audience logic is identical. The 302-vs-401 choice *may* instead be derived per
> request from `Sec-Fetch-Mode: navigate` / `Accept: text/html`, collapsing the two
> lists to one. We **keep the explicit `secured` list as the default** because deriving
> behavior from client-controlled headers trades away the auditability/predictability a
> conformance reference is selling — but the negotiation is a supported variant for
> deployments that prefer it.

> **EDS reality vs deny-by-default.** Deny-by-default only works on EDS if the standard
> EDS **infrastructure namespace is enumerated as public**, or the whole site won't render:
> `/scripts/*`, `/styles/*`, `/blocks/*`, `/icons/*`, `/fonts/*`, hashed `/media_*` assets,
> `.plain.html` fragments, plus `/sitemap.xml`, `/robots.txt`, `/.well-known/*`. These are
> in the example `ACCESS_POLICY` below. (Verify the exact infra path set for your project
> against the EDS docs — block/asset conventions can vary.) `default_tier` then applies
> only to *content* routes.

## Architecture

```
                          ┌──────────────────────────────────────────────┐
   Browser ──▶ Cloudflare  │            oidc-worker-gate (Worker)           │
              edge (CF)    │                                                │
                           │  /.auth/callback , /.auth/logout  ── gate routes
                           │                                                │
                           │  classify(path) ─▶ tier                        │
                           │     public   ───────────────────────▶ forward ─┼──▶ EDS origin
                           │     protected─ session? yes ─▶ forward ────────┼──▶ main--site--org
                           │                 │      no  ─▶ 302 login         │      .aem.live
                           │     secured  ─ session? yes ─▶ forward ────────┼──▶
                           │                 │      no  ─▶ 401 JSON          │
                           └───────────────┬────────────────────────────────┘
                                           │ (login + callback only)
                                           ▼
                                OpenID Provider (Okta / Entra / Ping / Auth0)
                           authorize · token · jwks · end_session
```

### Request lifecycle

1. Every request hits the worker first (CF route `www.example.com/*`).
2. Gate-owned routes `/.auth/callback` and `/.auth/logout` are handled by the worker.
3. `classify(path)` resolves the tier (`public` / `protected` / `secured`).
4. **public** → forward to EDS origin immediately (no cookie read).
5. **protected / secured** → read and HMAC-verify the `__gate_session` cookie **locally,
   no backend call**. Valid + in-policy → forward to origin with `x-auth-*` headers.
6. No/expired session → **protected** mints `state`/`nonce`/PKCE (stashed in a short-lived
   signed cookie) and 302s to the IdP's `authorization_endpoint`; **secured** returns `401`.
7. IdP redirects to `/.auth/callback`: verify `state`, exchange `code` (PKCE) for tokens,
   validate `id_token` (RS256 vs JWKS, `iss`/`aud`/`exp`/`nonce`), mint session, bounce back.
   Any validation failure returns `400` (not a re-redirect into login) so rejection is observable.

## Project structure (planned)

```
oidc-worker-gate/
├── src/
│   ├── index.js     # Worker entry (fetch handler): route, classify tier, forward
│   ├── policy.js    # NEW — path→tier matcher + audience authorization
│   ├── origin.js    # NEW — forward to EDS origin (Host / X-Forwarded-Host / push-inval)
│   ├── oidc.js      # RP: auth-code+PKCE start, callback, RP-initiated logout
│   ├── jwt.js       # RS256 id_token validation vs JWKS (+ KV-cached discovery/JWKS)
│   ├── session.js   # Mint/verify HMAC session + transient login-state cookie
│   ├── pkce.js      # PKCE S256 verifier/challenge + random state/nonce
│   ├── cookies.js   # Cookie parse/serialize + HMAC sign/unsign (Web Crypto)
│   ├── config.js    # Read env bindings (vars + secrets + KV)
│   └── encoding.js  # base64url, UTF-8, constant-time compare
├── test/            # vitest + mock-OP harness (see conformance-testing.md)
├── wrangler.toml    # CF config: routes, vars, KV binding, secrets (refs)
└── package.json
```

`oidc.js`, `jwt.js`, `session.js`, `pkce.js`, `cookies.js`, `encoding.js` are direct
ports from `../oidc-edge-gate/src/` — the crypto is already Web Crypto
(`crypto.subtle`), so RS256 verify and HMAC sign/verify move over unchanged. The new
files are `policy.js`, `origin.js`, and the CF-flavored `config.js`/`index.js`.

## Cloudflare runtime notes

- **Subrequest budget is not the constraint it was on Fastly.** CF Workers Paid allows
  **10,000 subrequests/invocation** (Free: 50); KV allows **1,000 ops/invocation**.
  We still keep the authenticated hot path to a **single origin `fetch()`** (session is
  validated locally via HMAC) for latency, not quota — but there's headroom.
- **KV is eventually consistent**, so it is used **only** for write-once, staleness-tolerant
  data: OIDC **discovery doc + JWKS**, with a TTL and a "`kid` miss → refetch once" path
  for key rotation. **Transient login state** (`state`/`nonce`/PKCE verifier) lives in the
  short-lived **signed cookie**, never KV — it must be read-after-write consistent and
  bound to the browser.
- **Memoize KV reads in isolate memory (the main latency lever).** Discovery, JWKS,
  and the runtime ACL should sit in module-scope variables with a TTL so a *warm*
  isolate never round-trips to KV. KV is the cross-isolate cache; isolate memory is
  the hot-path cache. On a transient JWKS fetch failure, keep serving the
  **last-known-good keys within a staleness window** rather than failing all logins —
  and back off / negative-cache repeated unknown `kid`s so old tokens can't hammer the
  JWKS endpoint (mirrors the ACL's last-known-good design).
- **Web Crypto** (`crypto.subtle`) provides RS256 (`RSASSA-PKCS1-v1_5` / `RS256`) verify
  for the ID token and HMAC-SHA256 for cookie signing — no external JWT library needed.

## EDS origin contract

The worker forwards authenticated/public requests to the EDS origin following AEM's
[bring-your-own-CDN setup](https://www.aem.live/docs/byo-cdn-setup) and
[Cloudflare Worker setup](https://www.aem.live/docs/byo-cdn-cloudflare-worker-setup):

- Fetch `https://${ORIGIN_HOSTNAME}` where `ORIGIN_HOSTNAME` = `main--<site>--<org>.aem.live`,
  with the outbound **`Host` set to `ORIGIN_HOSTNAME`**.
- Send **`X-Forwarded-Host: <production domain>`** so EDS emits correct absolute URLs
  (canonicals, sitemaps, redirects).
- Set **`X-Push-Invalidation: enabled`** on the production worker (disabled for preview/
  non-prod CF environments) so content updates invalidate the CF cache.
- Preserve origin `Cache-Control`, gzip, and include query parameters in the cache key;
  suppress/zero the `Age` header — **for the `public` tier only** (see caching carve-out below).
- **Origin trust for identity:** strip the inbound `Cookie` before forwarding and inject
  `x-auth-subject` / `x-auth-email` / `x-auth-groups`. The EDS origin (or downstream
  app) must only trust these when reached *through* the worker — enforce with a shared
  secret header or network controls; never trust `x-auth-*` from arbitrary callers.

### Caching carve-out (must not leak authenticated content)

EDS sets `Cache-Control` on a response based on the *content*, not on whether this gate
considers the path protected. Under BYO-CDN, Cloudflare caches origin responses keyed by
URL — so without a carve-out, a `protected`/`secured` response could be stored at the CF
edge and **cross-served to a different (even authorized) user**, which is wrong for
per-user content. The worker always runs (the gate is never bypassed), but the *response*
must not be cached. Therefore:

- **`public` tier** → preserve EDS caching (passthrough `Cache-Control`, edge-cacheable).
- **`protected` / `secured` tiers** → fetch origin with caching disabled
  (`fetch(url, { cf: { cacheTtl: 0, cacheEverything: false } })` / `cache: "no-store"`)
  **and** rewrite the downstream response to `Cache-Control: private, no-store`.

This is verified by a test: a `protected` response must never carry a shared/cacheable
`Cache-Control`.

## Configuration (`wrangler.toml` + secrets + KV)

```toml
name = "oidc-worker-gate"
main = "src/index.js"
compatibility_date = "2025-06-01"

routes = [
  { pattern = "www.example.com/*", zone_name = "example.com" }
]

[[kv_namespaces]]
binding = "OIDC_CACHE"           # discovery + JWKS cache
id = "<kv-namespace-id>"

[vars]
OIDC_ISSUER      = "https://your-tenant.okta.com"
CLIENT_ID        = "0oaEXAMPLEclientid"
REDIRECT_URI     = "https://www.example.com/.auth/callback"
SCOPES           = "openid profile email groups"
SESSION_TTL      = "3600"
ORIGIN_HOSTNAME  = "main--mysite--myorg.aem.live"
FORWARDED_HOST   = "www.example.com"
PUSH_INVALIDATION = "enabled"
ROUTES           = '{"callback":"/.auth/callback","logout":"/.auth/logout"}'
ACCESS_POLICY    = '''{
  "rules": [
    { "path": "/",              "tier": "public" },
    { "path": "/blog/*",        "tier": "public" },
    { "path": "/nav",           "tier": "public" },
    { "path": "/footer",        "tier": "public" },
    { "path": "/favicon.ico",   "tier": "public" },
    { "path": "/scripts/*",     "tier": "public" },
    { "path": "/styles/*",      "tier": "public" },
    { "path": "/blocks/*",      "tier": "public" },
    { "path": "/icons/*",       "tier": "public" },
    { "path": "/fonts/*",       "tier": "public" },
    { "path": "/media_*",       "tier": "public" },
    { "path": "/*.plain.html",  "tier": "public" },
    { "path": "/sitemap.xml",   "tier": "public" },
    { "path": "/robots.txt",    "tier": "public" },
    { "path": "/.well-known/*", "tier": "public" },
    { "path": "/members/*",     "tier": "protected", "audience": ["site-readers"] },
    { "path": "/account/*",     "tier": "protected", "audience": ["site-readers"] },
    { "path": "/api/*",         "tier": "secured",   "audience": ["site-readers"] },
    { "path": "/secure-data/*", "tier": "secured",   "audience": ["site-readers"] }
  ],
  "default_tier": "protected"
}'''
```

> **One policy model.** The static `ACCESS_POLICY` above and the DA-sourced KV ACL in
> [`folder-authorization.md`](./folder-authorization.md) use the same normalized row:
> `{ path, tier (public|protected|secured), audience? }`. `tier` determines the
> unauthenticated response (`forward`, `302`, or `401`); `audience` determines whether an
> authenticated session is authorized. Static config is the Phase 1 source. The KV policy
> supersedes it in Phase 3, but the evaluator is the same.

Secrets via `wrangler secret put` (never in `wrangler.toml`):

| Secret | Purpose |
| --- | --- |
| `OIDC_CLIENT_SECRET` | confidential-client token-endpoint auth |
| `SESSION_HMAC_KEY` | HMAC-SHA256 session/state cookie signing (≥ 32 bytes) |

At the IdP: register `REDIRECT_URI` as an allowed callback and `https://www.example.com/`
as a post-logout redirect.

**If the OP is Adobe IMS**, the generic OIDC flow still applies, but IMS does not emit a
`groups` claim in the `id_token`. Entitlement lookup and product-profile/user-group
mapping are Phase 2 concerns; keep them out of the Phase 1 core gate. See
[`folder-authorization.md`](./folder-authorization.md) for the IMS-specific details and
open decision gates.

## Security model

- **Session cookie** `__gate_session`: `HttpOnly`, `Secure`, `SameSite=Lax`,
  `Path=/`, HMAC-SHA256 signed. Carries only what the worker needs for hot-path
  authorization, typically `sub`, minimal `entitlements`/`groups`, `iat`, and `exp`.
  Signing prevents tampering but does **not** hide the payload from the browser; if group
  names or profile data are sensitive, either keep them out of the cookie or encrypt the
  session payload.
- **CSRF / replay:** `state` compared in constant time; `nonce` bound into the ID token
  and checked at callback; PKCE S256 protects the code exchange.
- **Open redirect:** post-login `returnTo` restricted to same-origin relative paths.
- **Authorization:** the matching policy row may include an `audience`; if present, the
  session's entitlements/groups must intersect it or the worker returns `403`. For
  **per-folder, DA-administered** authorization (folder→group ACLs authored and delegated
  in DA, distributed to the worker) see [`folder-authorization.md`](./folder-authorization.md).
- **Revocation:** time-based only (cookie `exp`). Shortening `SESSION_TTL` is the main
  lever; a KV-backed `sub`/`jti` denylist is a natural extension.

## Observability

The gate is the component operators will watch, so it owns its telemetry (the
DA-ACL doc adds the authz-specific fields on top of this baseline).

- **One structured (JSON) log line per decision**, with: `tier`, `decision`
  (`forward` | `302` | `401` | `403` | `400`), `reason`, `sub` (or a salted hash —
  not the raw subject), `kid`, `policy_version`, origin-fetch latency, and `cf-ray`.
- **Outcome codes are metrics, not just responses.** The `400`-on-bad-callback that
  the conformance doc requires (so a rejection is *observable*, not a silent re-302)
  should also increment a counter. Track at minimum: login starts, callback
  success/fail **by reason**, JWKS refetch, ACL staleness-serve events, KV read errors.
- **Sink:** emit the decision stream to **Workers Analytics Engine** (cheap,
  high-cardinality) and/or **Logpush** — the CF-native way to make "observable" real.
- **Correlation:** propagate the request id to origin as `x-auth-request-id: <cf-ray>`
  so edge decisions and origin logs line up.

## Local development

```bash
cd oidc-worker-gate
npm install
npx wrangler dev          # local worker on http://127.0.0.1:8787
```

Point `OIDC_ISSUER` at a real IdP or the in-repo mock OP (see conformance doc).

## Phasing

The plan splits into three subsystems at very different risk levels. **Build them
in order** — Phase 1 is a complete, demonstrable RP that depends on **no open
questions**; Phases 2–3 carry the unresolved identity work and must not block it.

| Phase | Scope | Ships alone? | Blocked on |
| --- | --- | --- | --- |
| **1 — Core gate** | Generic IdP, static `ACCESS_POLICY`, three tiers, single origin `fetch()`, mock-OP tests (P1–P7, N1–N15) | **Yes** | nothing |
| **2 — IMS as OP** | Swap issuer to IMS, add `/ims/profile/v1` fetch at session-mint, map product-profiles → session entitlements | No (needs Phase 1) | [`folder-authorization.md`](./folder-authorization.md) Q3 |
| **3 — DA folder-authz** | Control-plane push → KV ACL, unified matcher, last-known-good | No (needs Phase 1) | Q3 + Q4 |

> Building the DA control-plane pipeline (Phase 3) or the IMS profile fetch
> (Phase 2) before the core gate works — and before Q3 resolves whether the DA ACL
> names product-profiles or user-groups — is the plan's main YAGNI/risk trap.
> Phase 1 first.

## Milestones (Phase 1)

1. **Scaffold** — `wrangler.toml`, `package.json`, `src/` skeleton; `wrangler dev` boots.
2. **Port OIDC core *and close the conformance gaps*** — port
   `jwt/session/pkce/cookies/encoding` from `oidc-edge-gate` (crypto is already Web
   Crypto), swap Fastly KV/config for CF KV binding + `env`. **This is not a verbatim
   copy:** the sibling `jwt.js` covers RS256-only/`kid`/`iss`/`aud`(array)/`exp`/`nbf`/
   `nonce`, but is **missing** three things the N-matrix and OIDF RP plans require —
   add them here as explicit tasks:
   - **`c_hash` / `at_hash` validation** (N11) — not implemented in the sibling.
   - **`azp` check when `aud` is multi-valued** — if multiple audiences are present,
     `azp` MUST exist and equal `client_id` (current `audienceMatches` only tests
     membership).
   - **"refetch JWKS once on `kid` miss"** (N7) — the sibling throws on an unknown
     `kid`; add the single-refetch-then-reject path for key rotation.
3. **Three-tier policy** — `policy.js` matcher + tests for precedence, default deny, EDS
   infra public allowlist, audience `403`s, and the three unauthenticated behaviors.
4. **EDS forwarding** — `origin.js` with Host / `X-Forwarded-Host` / push-invalidation,
   inbound cookie stripping, `x-auth-*` injection, request-id propagation, and
   protected/secured `no-store`; verify against a real EDS origin.
5. **End-to-end login** — callback + session mint + RP-initiated logout against a real IdP.
6. **Conformance CI** — mock-OP vitest harness for all P/N cases
   (see [`conformance-testing.md`](./conformance-testing.md)). Run the hosted OIDF RP
   suite as a release/certification gate before claiming formal conformance, not as a
   prerequisite for the Phase 1 build.

Phase 2 (IMS profile fetch) and Phase 3 (DA ACL) are milestoned in
[`folder-authorization.md`](./folder-authorization.md) once their open questions resolve.

## Limitations

Research / reference implementation, not a hardened product. Only the `id_token` is
validated (access/refresh tokens not persisted — add refresh handling for long-lived
sessions). Revocation is time-based. The `x-auth-*` origin-trust boundary must be
enforced operationally.
