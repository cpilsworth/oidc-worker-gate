# oidc-worker-gate

An **OpenID Connect authentication gateway** for [AEM Edge Delivery Services
(EDS)](https://www.aem.live/), implemented as a **Cloudflare Worker**. It sits on your
customer domain in front of the EDS origin (`main--<site>--<org>.aem.live`), authenticates
users against any standards-compliant OpenID Provider (Okta, Entra ID, Ping, Auth0, Adobe
IMS, …), and enforces access **before** anything reaches the origin — without the EDS
project itself knowing anything about OIDC.

> **Status: Phase 1 implemented** — 10 source modules, 11 test files, **72 tests passing**
> in the real `workerd` runtime. This is a research / reference implementation (see
> [Limitations](#limitations)). The multi-phase roadmap and the implementation record live
> in [`phase-1-plan.md`](./phase-1-plan.md); identity/folder-authz design is in
> [`folder-authorization.md`](./folder-authorization.md).
> Auth0 setup guide: [`auth0-setup.md`](./auth0-setup.md).

## What it does

- **Three-tier access gate.** Every request path is classified and handled by tier:

  | Tier | Example paths | Unauthenticated behavior |
  | --- | --- | --- |
  | **public** | `/`, `/blog/*`, `/scripts/*`, `/styles/*`, `/media_*` | Forward to origin, no auth, stays edge-cacheable |
  | **protected** | `/members/*`, `/account/*` | **302 → IdP** (interactive login) |
  | **secured** | `/api/*`, `/secure-data/*` | **401 JSON**, no redirect (for `fetch`/XHR) |

- **Standards-conformant OIDC relying party.** Authorization-code flow with **PKCE
  (S256)**, **RS256** `id_token` validation against the provider's JWKS, discovery-driven
  endpoints, `state`/`nonce` CSRF + replay protection, and RP-initiated logout.
- **Local, fast session enforcement.** After login the gate mints its own HMAC-signed
  session cookie; every subsequent request is validated locally (no IdP/backend round-trip),
  so the authenticated hot path is a **single origin `fetch()`**.
- **Audience authorization.** A policy row may require an `audience`; the session's
  groups/entitlements must intersect it or the gate returns `403`.
- **Deny-by-default.** Unmatched paths fall to a configurable `default_tier` (recommended:
  `protected`), so a new route is never accidentally exposed.
- **AEM BYO-CDN origin forwarding** with the correct `Host` / `X-Forwarded-Host` /
  push-invalidation headers, and a caching carve-out so per-user content can never be
  cross-served from the edge cache.
- **Conformance-tested.** The OpenID Foundation RP behaviors are encoded as an executable
  positive/negative matrix (P1–P7, N1–N15) — see [`conformance-testing.md`](./conformance-testing.md).

## How it works

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
                                OpenID Provider (Okta / Entra / Ping / Auth0 / IMS)
                           authorize · token · jwks · end_session
```

**Request lifecycle**

1. Every request hits the worker first (CF route `www.example.com/*`).
2. Gate-owned routes `/.auth/callback` and `/.auth/logout` are handled by the worker.
3. `classify(path)` resolves the tier (`public` / `protected` / `secured`) by most-specific
   rule match; unmatched → `default_tier`.
4. **public** → forward to the EDS origin immediately (no cookie read).
5. **protected / secured** → read and HMAC-verify the `__gate_session` cookie **locally**.
   Valid + in-policy → forward to origin with `x-auth-*` identity headers.
6. No/expired session → **protected** starts login (mints `state`/`nonce`/PKCE in a
   short-lived signed cookie, 302s to the IdP); **secured** returns `401` JSON.
7. The IdP redirects to `/.auth/callback`: the gate verifies `state`, exchanges `code`
   (with the PKCE verifier) for tokens, validates the `id_token` (RS256 vs JWKS, plus
   `iss`/`aud`/`azp`/`exp`/`iat`/`nonce` and `c_hash`/`at_hash` when present), mints the
   session, and bounces the user back to where they started. **Any validation failure
   returns `400`** (not a re-redirect into login), so a rejection is observable.

**Tier behaviors.** `protected` is "trigger authentication" — for navigational HTML, a
missing session yields an interactive **302** into the IdP. `secured` is "validate
authentication" — for API/`fetch` endpoints, a missing/invalid session yields **`401`
JSON** with no redirect (redirecting an XHR to an HTML login page is useless to the caller).
Once a session is present both tiers enforce the row's optional `audience`; authenticated
but unauthorized → **`403`**.

> The only difference between `protected` and `secured` is the *unauthenticated* response.
> The 302-vs-401 choice can optionally be content-negotiated per request
> (`Sec-Fetch-Mode: navigate` / `Accept: text/html`) instead of by explicit list; the
> explicit `secured` list is the default because it's more auditable than trusting
> client-controlled headers.

## Source layout

```
oidc-worker-gate/
├── src/
│   ├── index.js     # Worker entry: classify tier → dispatch (public/protected/secured + gate routes)
│   ├── policy.js    # ACCESS_POLICY matcher: classify(path)→{tier,audience} + isAuthorized()
│   ├── origin.js    # EDS origin forwarding (Host / X-Forwarded-Host / push-inval, cache carve-out)
│   ├── oidc.js      # RP flow: auth-code+PKCE start, callback, RP-initiated logout
│   ├── jwt.js       # RS256 id_token validation vs JWKS (+ KV-cached discovery/JWKS, kid-refetch)
│   ├── session.js   # Mint/verify HMAC session + transient login-state cookie
│   ├── pkce.js      # PKCE S256 verifier/challenge + random state/nonce
│   ├── cookies.js   # Cookie parse/serialize + HMAC sign/unsign (Web Crypto)
│   ├── config.js    # Load env bindings (vars + secrets + KV) into a Config
│   └── encoding.js  # base64url, UTF-8, constant-time compare
├── test/            # vitest + in-process mock-OP harness (see conformance-testing.md)
├── wrangler.toml    # CF config: route, vars, KV binding
└── package.json
```

No external runtime dependencies and no `nodejs_compat` — RS256 verification and HMAC
signing use the Workers-native Web Crypto (`crypto.subtle`).

## Prerequisites

- A **Cloudflare account** with the target zone (your customer domain) onboarded, and
  [`wrangler`](https://developers.cloudflare.com/workers/wrangler/) authenticated
  (`npx wrangler login`). Workers **Paid** is recommended (Free caps subrequests at 50/req).
- An **OpenID Provider** where you can register a confidential web client (client id +
  secret, authorization-code + PKCE, a redirect URI).
- An **AEM EDS site** reachable at `main--<site>--<org>.aem.live`, set up for
  [bring-your-own-CDN](https://www.aem.live/docs/byo-cdn-setup).
- Node.js 20+ for local development and tests.

## Deploy

```bash
cd oidc-worker-gate
npm install
```

**1. Create the KV namespace** (caches OIDC discovery + JWKS) and copy the returned id into
`wrangler.toml` under `[[kv_namespaces]]` `id`:

```bash
npx wrangler kv namespace create OIDC_CACHE
```

**2. Set non-secret config** in `wrangler.toml` `[vars]` — at minimum `OIDC_ISSUER`,
`CLIENT_ID`, `REDIRECT_URI`, `ORIGIN_HOSTNAME`, `FORWARDED_HOST`, and `ACCESS_POLICY` (see
[Configuration](#configuration)).

**3. Set secrets** (never put these in `wrangler.toml`):

```bash
npx wrangler secret put OIDC_CLIENT_SECRET      # from your IdP client registration
npx wrangler secret put SESSION_HMAC_KEY        # e.g. `openssl rand -base64 32`
```

**4. Register the client at your IdP:** allow `REDIRECT_URI`
(`https://www.example.com/.auth/callback`) as a redirect/callback URI, and
`https://www.example.com/` as a post-logout redirect URI. Enable authorization-code flow
with PKCE; use `client_secret_post` token-endpoint auth.

**5. Bind the route** in `wrangler.toml` so the worker fronts your domain:

```toml
routes = [{ pattern = "www.example.com/*", zone_name = "example.com" }]
```

**6. Deploy and verify:**

```bash
npx wrangler deploy
```

- A **public** path (e.g. `/`) returns the EDS page.
- A **protected** path (e.g. `/members/x`) with no session **302**s to your IdP; after login
  you land back on the original path.
- A **secured** path (e.g. `/api/...`) with no session returns **`401`** JSON, no redirect.

> **Multiple environments.** Use wrangler `[env.*]` blocks for preview vs production. Set
> `PUSH_INVALIDATION = "enabled"` **only** on the production worker (the one whose cache AEM
> push-invalidates); leave it off for preview/non-prod.

> **Origin reachability.** The gate only protects traffic that goes through the
> customer-domain route. If `main--<site>--<org>.aem.live` is independently reachable and
> serves the same protected URLs, those URLs are not actually confidential. For genuinely
> protected content, also restrict the EDS origin (shared-secret header, network controls,
> or an origin-side check that only trusts worker-injected headers).

## Configuration

All non-secret config is `wrangler.toml` `[vars]`; two values are secrets.

### Variables (`[vars]`)

| Variable | Example | Purpose |
| --- | --- | --- |
| `OIDC_ISSUER` | `https://your-tenant.okta.com` | OP issuer; discovery is fetched from `<issuer>/.well-known/openid-configuration`. Trailing slash trimmed. The worker also normalises a trailing slash in the `iss` claim of incoming tokens, so providers such as Auth0 that append a trailing slash to `iss` work without adjustment. |
| `CLIENT_ID` | `0oaEXAMPLEclientid` | Registered confidential-client id. |
| `REDIRECT_URI` | `https://www.example.com/.auth/callback` | Must match the gate's callback route and be allowlisted at the IdP. |
| `SCOPES` | `openid profile email groups` | Space-delimited scopes requested at authorize. |
| `SESSION_TTL` | `3600` | Session cookie lifetime in seconds (primary revocation lever). |
| `ORIGIN_HOSTNAME` | `main--mysite--myorg.aem.live` | EDS origin; sent as the outbound `Host`. |
| `FORWARDED_HOST` | `www.example.com` | Public domain; sent as `X-Forwarded-Host` so EDS emits correct absolute URLs. |
| `PUSH_INVALIDATION` | `enabled` | Set on production only → sends `X-Push-Invalidation: enabled`. |
| `ROUTES` | `{"callback":"/.auth/callback","logout":"/.auth/logout"}` | Gate-owned paths the worker handles itself. |
| `ACCESS_POLICY` | _(JSON, below)_ | The path→tier+audience rules. |

### Secrets (`wrangler secret put`)

| Secret | Purpose |
| --- | --- |
| `OIDC_CLIENT_SECRET` | Confidential-client token-endpoint authentication. |
| `SESSION_HMAC_KEY` | HMAC-SHA256 signing key for the session/state cookies (≥ 32 bytes). |

### `ACCESS_POLICY`

One normalized rule shape — `{ path, tier (public|protected|secured), audience? }` —
evaluated by **most-specific match** (exact path beats glob; longer literal prefix beats
shorter). `audience` (optional) is the set of groups/entitlements allowed once
authenticated. Unmatched paths fall to `default_tier`.

```toml
ACCESS_POLICY = '''{
  "rules": [
    { "path": "/",              "tier": "public" },
    { "path": "/blog/*",        "tier": "public" },
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

> **EDS infrastructure must be public, or the site won't render.** With deny-by-default
> (`default_tier: protected`), enumerate the EDS namespace as `public`: `/scripts/*`,
> `/styles/*`, `/blocks/*`, `/icons/*`, `/fonts/*`, hashed `/media_*`, `.plain.html`
> fragments, plus `/sitemap.xml`, `/robots.txt`, `/.well-known/*` (all included above).
> Verify the exact infra path set for your project against the EDS docs. `default_tier`
> then applies only to content routes.

> **Auth0** works as the OP via the generic flow. Auth0 silently drops non-namespaced custom
> claims from tokens, so roles must be injected under a namespaced key
> (`https://oidc.workers.dev/groups`) via a Post Login Action. The worker reads this
> namespaced claim first, then falls back to `groups` / `roles` for other providers. See
> [`auth0-setup.md`](./auth0-setup.md) for the full setup including the required Action code.

> **Adobe IMS** works as the OP via the generic flow, but IMS does **not** emit a `groups`
> claim in the `id_token` — entitlements require a post-login profile lookup and a
> product-profile↔group mapping. That is **Phase 2**, deliberately out of the core gate; see
> [`folder-authorization.md`](./folder-authorization.md).

## Local development

```bash
cd oidc-worker-gate
npm install
npx wrangler dev          # local worker on http://127.0.0.1:8787
npm test                  # full conformance suite in workerd (vitest-pool-workers)
```

Point `OIDC_ISSUER` at a real IdP, or run the tests — they spin up an in-process mock
OpenID Provider. Tests run in the real `workerd` runtime via
`@cloudflare/vitest-pool-workers` (0.16.x / vitest 4), so Web Crypto, KV, and bindings
behave as in production. See [`conformance-testing.md`](./conformance-testing.md) for the
positive/negative matrix.

## EDS origin contract

The worker forwards public/authenticated requests to the EDS origin per AEM's
[BYO-CDN setup](https://www.aem.live/docs/byo-cdn-setup) and
[Cloudflare Worker setup](https://www.aem.live/docs/byo-cdn-cloudflare-worker-setup):

- Fetch `https://${ORIGIN_HOSTNAME}…` with the outbound **`Host` set to `ORIGIN_HOSTNAME`**.
- Send **`X-Forwarded-Host: ${FORWARDED_HOST}`** so EDS emits correct canonicals/sitemaps/redirects.
- Send **`X-Push-Invalidation: enabled`** on production so content updates invalidate the CF cache.
- **Strip the inbound `Cookie`** before forwarding; inject `x-auth-subject` /
  `x-auth-groups` for the authenticated identity, plus `x-auth-request-id` for
  edge↔origin correlation. The gate **deletes any client-supplied `x-auth-*` and
  `x-push-invalidation` headers on every tier** before injecting its own, so a caller can't
  spoof identity. The origin must still only trust `x-auth-*` when reached *through* the
  worker (shared secret / network controls).

### Caching carve-out

EDS sets `Cache-Control` from content, not from this gate's tier. Under BYO-CDN, Cloudflare
caches origin responses by URL — so per-user content must not be edge-cached:

- **public** → preserve EDS caching (passthrough `Cache-Control`, edge-cacheable).
- **protected / secured** → fetch origin with caching disabled (`cf: { cacheTtl: 0,
  cacheEverything: false }`) **and** rewrite the response to `Cache-Control: private,
  no-store` with `Age` stripped. A test asserts a protected response never carries a
  shared/cacheable `Cache-Control`.

## Security model

- **Session cookie `__gate_session`:** `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`,
  HMAC-SHA256 signed; carries `sub`, minimal groups/entitlements, `iat`, `exp`. Signing
  prevents tampering but does **not** hide the payload from the browser — if group names are
  sensitive, keep them out of the cookie or encrypt the payload.
- **Token validation:** RS256 only (no `alg:none`/HS256 confusion); `iss`/`aud`/`exp`(required)/
  `iat`/`nbf`/`nonce` enforced; `azp` checked when present and required for multi-valued
  `aud`; `c_hash`/`at_hash` verified (constant-time) when present; JWKS refetched **once** on
  a `kid` miss for key rotation, then reject.
- **CSRF / replay:** `state` compared constant-time; `nonce` bound into the id_token;
  single-use state marker (KV, best-effort) rejects a replayed callback; PKCE S256 protects
  the code exchange.
- **Open redirect:** post-login `returnTo` validated to same-origin (origin-equality check).
- **Authorization:** policy-row `audience` intersected with session groups → `403` if empty.
  Per-folder, DA-administered authorization is in [`folder-authorization.md`](./folder-authorization.md).
- **Revocation:** time-based (cookie `exp`); shorten `SESSION_TTL` to tighten. A KV-backed
  `sub`/`jti` denylist is a natural extension.

## Observability

The gate owns its telemetry:

- **One structured (JSON) log line per decision:** `tier`, `decision`
  (`forward`|`302`|`401`|`403`|`400`), `reason`, `sub` (or salted hash), `kid`,
  `policy_version`, origin-fetch latency, `cf-ray`.
- **Outcome codes as metrics:** count login starts, callback success/fail **by reason**,
  JWKS refetch, KV read errors. The `400`-on-bad-callback is both a response and a counter.
- **Sink:** **Workers Analytics Engine** and/or **Logpush**.
- **Correlation:** `x-auth-request-id: <cf-ray>` is propagated to origin.

## Performance

The authenticated hot path is a single origin `fetch()` with local HMAC verification — no
IdP round-trip per request. Discovery/JWKS are cached in KV and memoized in isolate memory
so a warm isolate never round-trips to KV; on a transient JWKS failure the gate serves
last-known-good keys within a staleness window rather than failing all logins.

## Testing & conformance

`npm test` runs the full positive/negative matrix (P1–P7, N1–N15 + N4b) against an
in-process mock OpenID Provider. The negative cases fail closed — a token that fails any
check never yields a session. CI (`.github/workflows/oidc-worker-gate-ci.yml`) gates every
change to `oidc-worker-gate/**`. The hosted OpenID Foundation RP suite is a
release/certification gate, not a per-build requirement — see
[`conformance-testing.md`](./conformance-testing.md).

## Roadmap

Phase 1 (this gate) is implemented. Phase 2 adds Adobe IMS as the OP with a post-login
entitlement lookup; Phase 3 adds DA-authored, delegated folder-level authorization
distributed to the worker via KV. See the roadmap table and implementation record in
[`phase-1-plan.md`](./phase-1-plan.md) and the identity/authz design in
[`folder-authorization.md`](./folder-authorization.md).

## Limitations

Research / reference implementation, not a hardened product. Only the `id_token` is
validated (access/refresh tokens are not persisted — add refresh handling for long-lived
sessions). Revocation is time-based. Single-use state replay protection is best-effort (CF
KV is eventually consistent) — see [`state-replay-do.md`](./state-replay-do.md) for a
strict Durable Object design. The `x-auth-*` origin-trust boundary must be enforced
operationally at the EDS origin.
