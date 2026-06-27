# oidc-worker-gate

An **OpenID Connect authentication gateway** for [AEM Edge Delivery Services
(EDS)](https://www.aem.live/), implemented as a **Cloudflare Worker**. It sits on your
customer domain in front of the EDS origin (`main--<site>--<org>.aem.live`), authenticates
users against any standards-compliant OpenID Provider (Okta, Entra ID, Ping, Auth0, Adobe
IMS, …), and enforces access **before** anything reaches the origin — without the EDS
project itself knowing anything about OIDC.

> **Status:** delivery gate, DA policy compiler, manual publish, and publisher-worker
> refresh path are implemented and tested in the real `workerd` runtime. This is a research
> / reference implementation (see [Limitations](#limitations)). DA policy design lives in
> [`da-access-control-policy-spec.md`](./da-access-control-policy-spec.md), and operational
> deployment steps live in [`operations.md`](./operations.md).
> DA publish/change event wiring is intentionally deferred for now; use the manual
> `npm run refresh-policy` command to refresh the signed KV policy after DA sheet changes.
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
- **Audience authorization.** A policy row may require an `audience`; the session's mapped
  groups must intersect it or the gate returns `403`.
- **DA-authored policy support.** Content access rules can be authored in the
  `access-control` sheet of the DA site configuration, compiled by a separate publisher
  worker, signed with `POLICY_HMAC_KEY`, stored in KV, and enforced by the delivery worker.
- **Deny-by-default.** Unmatched paths fall to a configurable `default_tier` (recommended:
  `protected`), so a new route is never accidentally exposed.
- **AEM BYO-CDN origin forwarding** with the correct `Host` / `X-Forwarded-Host` /
  push-invalidation headers, and a caching carve-out so per-user content can never be
  cross-served from the edge cache.
- **Conformance-tested.** The OpenID Foundation RP behaviors are encoded as an executable
  positive/negative matrix (P1–P7, N1–N17) — see [`conformance-testing.md`](./conformance-testing.md).

## Outcome

The implemented plan separates delivery-time authorization from author-time policy
management:

- DA owns the full content policy in the site configuration sheet named `access-control`.
- A separate publisher worker reads that sheet from `admin.da.live`, validates it, signs
  the normalized policy, and stores it in Cloudflare KV.
- The delivery worker verifies the signed KV snapshot before enforcing content paths.
- Static worker policy remains responsible for worker-owned and public EDS infrastructure
  paths, plus fallback behavior when `POLICY_SOURCE=auto`.
- `POLICY_SOURCE=required` is available when operators want content paths to fail closed
  with `503` if no valid DA/KV policy is available.
- Automatic DA publish/change event integration is intentionally deferred; manual refresh
  is the current operational path.

## How it works

```
   DA config sheet                    Publisher Worker
   access-control ──manual refresh──▶ read admin.da.live/config/{org}/{site}/
                                      validate + normalize + sign
                                      write policy:current:{org/site} to KV

   Browser ──▶ Delivery Worker ──verify signed KV policy──▶ classify(path)
                  │                                            │
                  │ public                                     ├─▶ forward to EDS origin
                  │ protected + no session                     ├─▶ 302 to IdP
                  │ secured + no session                       ├─▶ 401 JSON
                  │ authenticated but wrong audience           └─▶ 403 JSON
                  ▼
          OpenID Provider
          authorize · token · jwks · end_session
```

**Request lifecycle**

1. Every request hits the worker first (CF route `www.example.com/*`).
2. Gate-owned routes `/.auth/callback` and `/.auth/logout` are handled by the worker.
3. The request path is **canonicalized** before any classification: percent-decoded,
   duplicate slashes collapsed, and `.`/`..` segments resolved. Paths carrying encoded
   separators (`%2F`/`%5C`), backslashes, or malformed escapes are rejected with a generic
   `400` — a glob like `/blog/**` can't be bypassed by `/blog/%2e%2e/members/secret`.
4. Worker-managed infrastructure paths are classified from static worker config.
5. Content paths load the latest signed DA policy snapshot from KV. The snapshot is signed
   with `POLICY_HMAC_KEY`; invalid or wrong-site snapshots are rejected.
6. `classify(path)` resolves the tier (`public` / `protected` / `secured`) by most-specific
   DA-style rule match; unmatched → worker-owned `default_tier`.
7. **public** → forward to the EDS origin immediately (no cookie read).
8. **protected / secured** → read and HMAC-verify the `__Host-gate_session` cookie **locally**.
   Valid + in-policy → forward to origin with `x-auth-*` identity headers.
9. No/expired session → **protected** starts login (mints `state`/`nonce`/PKCE in a
   short-lived signed cookie, 302s to the IdP); **secured** returns `401` JSON.
10. The IdP redirects to `/.auth/callback`: the gate verifies `state`, exchanges `code`
    (with the PKCE verifier) for tokens, validates the `id_token` (RS256 vs JWKS, plus
    `iss`/`aud`/`azp`/`exp`/`iat`/`nonce` and `c_hash`/`at_hash` when present), mints the
    session, and bounces the user back to where they started. **Any validation failure
    returns a generic `400`** (not a re-redirect into login), so a rejection is observable.
    The error body is a generic JSON code plus a `request_id` — it never echoes the IdP
    `error` parameter or an exception message.

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
│   ├── index.js             # Delivery worker entrypoint.
│   ├── publisher-worker.js  # Separate policy publisher worker.
│   ├── policy.js            # DA-style matcher + authorization helpers.
│   ├── policy-publisher.js  # Sheet extraction, validation, signing, KV publishing.
│   ├── policy-snapshot.js   # Signed snapshot verification + runtime loading.
│   ├── session.js           # HMAC session cookies + audience mapping.
│   ├── oidc.js / jwt.js     # OIDC RP flow and id_token validation.
│   ├── origin.js            # EDS origin forwarding and cache carve-out.
│   └── config.js            # Cloudflare binding config loader.
├── test/            # vitest + in-process mock-OP harness (see conformance-testing.md)
├── scripts/         # policy publish, refresh, and status inspection commands
├── wrangler.toml    # delivery worker config: route, vars, KV binding
├── wrangler.publisher.toml # policy publisher worker config
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
`CLIENT_ID`, `REDIRECT_URI`, `ORIGIN_HOSTNAME`, `FORWARDED_HOST`, `POLICY_SITE_ID`,
`POLICY_SOURCE`, `AUDIENCE_MAP`, and the static fallback/operator `ACCESS_POLICY` (see
[Configuration](#configuration)).

**3. Set secrets** (never put these in `wrangler.toml`):

```bash
npx wrangler secret put OIDC_CLIENT_SECRET      # from your IdP client registration
npx wrangler secret put SESSION_HMAC_KEY        # e.g. `openssl rand -base64 32`
npx wrangler secret put POLICY_HMAC_KEY         # same value as publisher worker
npx wrangler secret put POLICY_HMAC_KEY --config wrangler.publisher.toml
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
npm run deploy:publisher
cp .env.example .env
# fill DA_TOKEN and POLICY_PUBLISHER_URL
npm run refresh-policy -- --pretty
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

## DA Policy Authoring

Author content authorization in the DA site configuration sheet named `access-control`.
The publisher reads it from:

```text
https://admin.da.live/config/{org}/{site}/
```

For this test site, `POLICY_SITE_ID=cpilsworth/authz`, so the source is:

```text
https://admin.da.live/config/cpilsworth/authz/
```

Use one table with these columns:

| Column | Required | Meaning |
| --- | --- | --- |
| `path` | Yes | Case-sensitive pathname pattern. Query strings and fragments are not allowed. |
| `tier` | Yes | One of `public`, `protected`, `secured`. |
| `audience` | No | Comma-separated normalized audience names. Blank means any authenticated user for `protected`/`secured`. |
| `description` | No | Author-facing note, ignored by enforcement. |

DA-style path syntax:

- `*` matches within one path segment, for example `/api/*`.
- `**` matches across path segments, for example `/members/**`.
- A terminal `/**` also matches the folder itself.
- Equal-specificity overlapping rules are rejected at publish time.
- Rules that overlap worker-managed paths are ignored and logged.
- A site-wide `public` rule (`/**`) is rejected at publish time so a sheet edit can't
  silently disable the gate; a top-level `public /*` rule is allowed but emits a warning.
  (`default_tier` is worker-owned and cannot be changed from DA.)

Example sheet rows:

```tsv
path	tier	audience	description
/	public		Site root.
/blog/**	public		Public blog content.
/members/**	protected	medical	Members section requires medical audience.
/market/**	protected	market-access	Market content requires market access.
/api/*	secured	secure	API endpoints return 401 instead of redirecting.
```

`protected` and `secured` both require authentication. The only difference is the
unauthenticated response: `protected` redirects to login, while `secured` returns `401`
JSON.

## Policy Publishing

The publisher is a separate Cloudflare Worker. It receives a refresh request with a DA
Bearer token, reads the DA config document itself, validates the `access-control` sheet,
signs the normalized policy, and writes it to KV.

KV keys:

| Key | Purpose |
| --- | --- |
| `policy:current:<site-id>` | Active signed policy envelope used by the delivery worker. |
| `policy:version:<site-id>:<version>` | Versioned copy for audit/debugging. |
| `policy:status:<site-id>` | Last publish success/failure, warnings, and errors. |

Manual refresh is the current production path:

```bash
cp .env.example .env
# fill DA_TOKEN, POLICY_SITE_ID, and POLICY_PUBLISHER_URL
npm run refresh-policy -- --pretty
```

Successful output looks like:

```json
{
  "level": "info",
  "status": 200,
  "site_id": "cpilsworth/authz",
  "response": {
    "status": "published",
    "rules": 5,
    "ignored_rules": 0,
    "warnings": []
  }
}
```

Inspect the current publish status and active policy summary:

```bash
npm run policy-status -- --pretty
npm run policy-status -- --current --pretty
```

Automatic DA publish/change event wiring is intentionally deferred. When that integration
is added, it should call the same publisher endpoint after DA publishes the sheet.

## Configuration

All non-secret config is in `[vars]` in `wrangler.toml` or `wrangler.publisher.toml`.
Secrets are set with `wrangler secret put`.

### Variables (`[vars]`)

| Variable | Example | Purpose |
| --- | --- | --- |
| `OIDC_ISSUER` | `https://your-tenant.okta.com` | OP issuer; discovery is fetched from `<issuer>/.well-known/openid-configuration`. Trailing slash trimmed. The worker also normalises a trailing slash in the `iss` claim of incoming tokens, so providers such as Auth0 that append a trailing slash to `iss` work without adjustment. |
| `CLIENT_ID` | `0oaEXAMPLEclientid` | Registered confidential-client id. |
| `REDIRECT_URI` | `https://www.example.com/.auth/callback` | Must match the gate's callback route and be allowlisted at the IdP. |
| `SCOPES` | `openid profile email groups` | Space-delimited scopes requested at authorize. |
| `GROUPS_CLAIM` | `groups` | The single id_token claim the worker reads for membership (default `groups`). Set to `https://oidc.workers.dev/groups` for Auth0. No silent fallback to other claims. |
| `SESSION_TTL` | `3600` | Session cookie lifetime in seconds (primary revocation lever). Must be a positive integer — validated at startup, so a typo can't silently produce `exp: NaN` and a login loop. |
| `ORIGIN_HOSTNAME` | `main--mysite--myorg.aem.live` | EDS origin; sent as the outbound `Host`. |
| `FORWARDED_HOST` | `www.example.com` | Public domain; sent as `X-Forwarded-Host` so EDS emits correct absolute URLs. |
| `PUSH_INVALIDATION` | `enabled` | Set on production only → sends `X-Push-Invalidation: enabled`. |
| `ROUTES` | `{"callback":"/.auth/callback","logout":"/.auth/logout"}` | Gate-owned paths the worker handles itself. |
| `POLICY_SOURCE` | `auto` | `auto`, `worker`, or `required`; controls DA/KV policy availability behavior. |
| `POLICY_SITE_ID` | `cpilsworth/authz` | DA site id in `org/site` format. |
| `POLICY_REFRESH_TTL_SECONDS` | `60` | In-isolate policy cache freshness window. Positive integer, validated at startup. |
| `POLICY_STALE_TTL_SECONDS` | `900` | Last-known-good policy window after refresh failure. Positive integer, validated at startup. |
| `AUDIENCE_MAP` | `{"medical":["medical"],"market-access":["market-access"]}` | Maps raw IdP groups/roles to normalized policy audiences. Unmapped values are dropped. |
| `WORKER_MANAGED_PATHS` | _(JSON array)_ | Optional override for paths owned by the worker/static policy. |
| `ACCESS_POLICY` | _(JSON, below)_ | Static worker-managed rules plus emergency fallback policy. |

Publisher worker variables in `wrangler.publisher.toml`:

| Variable | Example | Purpose |
| --- | --- | --- |
| `DA_BASE_URL` | `https://admin.da.live/config` | Base URL used to read DA site config. |
| `PUBLISHER_SITES` | `{"cpilsworth/authz":{"audience_map":{"medical":["medical"]}}}` | Allow-listed sites and their audience maps. |

### Secrets (`wrangler secret put`)

| Secret | Purpose |
| --- | --- |
| `OIDC_CLIENT_SECRET` | Confidential-client token-endpoint authentication. |
| `SESSION_HMAC_KEY` | HMAC-SHA256 signing key for the session/state cookies. Must be ≥ 32 bytes — enforced at startup. |
| `POLICY_HMAC_KEY` | HMAC-SHA256 signing key for policy snapshots (≥ 32 bytes when set, enforced at startup). Set the same value on delivery and publisher workers. |

Generate and set the policy signing key:

```bash
openssl rand -base64 32
npx wrangler secret put POLICY_HMAC_KEY
npx wrangler secret put POLICY_HMAC_KEY --config wrangler.publisher.toml
```

### `POLICY_SOURCE`

| Mode | Behavior |
| --- | --- |
| `auto` | Use a valid signed DA/KV policy when available; otherwise fall back to `ACCESS_POLICY`. |
| `worker` | Disable DA/KV policy entirely; always use `ACCESS_POLICY`. |
| `required` | Require a valid signed DA/KV policy for content paths. If no valid or last-known-good policy is available, return `503`. |

### `ACCESS_POLICY`

`ACCESS_POLICY` is no longer the primary content authorization surface when
`POLICY_SOURCE=auto` or `required`. It remains important for:

- worker-managed paths such as auth routes and public EDS infrastructure
- emergency fallback when `POLICY_SOURCE=auto`
- `default_tier`, which is still operator configuration and is not authored in DA

One normalized rule shape is `{ path, tier (public|protected|secured), audience? }`.

```toml
ACCESS_POLICY = '''{
  "rules": [
    { "path": "/*",                  "tier": "public" },
    { "path": "/scripts/**",         "tier": "public" },
    { "path": "/styles/**",          "tier": "public" },
    { "path": "/blocks/**",          "tier": "public" },
    { "path": "/icons/**",           "tier": "public" },
    { "path": "/fonts/**",           "tier": "public" },
    { "path": "/media_*",            "tier": "public" },
    { "path": "/nav.plain.html",     "tier": "public" },
    { "path": "/footer.plain.html",  "tier": "public" },
    { "path": "/sitemap.xml",        "tier": "public" },
    { "path": "/robots.txt",         "tier": "public" },
    { "path": "/.well-known/**",     "tier": "public" }
  ],
  "default_tier": "protected"
}'''
```

> **EDS infrastructure must be public, or the site won't render.** With deny-by-default
> (`default_tier: protected`), enumerate the EDS namespace as `public`: `/scripts/**`,
> `/styles/**`, `/blocks/**`, `/icons/**`, `/fonts/**`, hashed `/media_*`, only the
> allowed `nav`/`footer` `.plain.html` fragments, plus `/sitemap.xml`, `/robots.txt`,
> `/.well-known/**` (all included above).
> Verify the exact infra path set for your project against the EDS docs. `default_tier`
> then applies only to content routes.

### Audience Mapping

The DA sheet uses normalized audience names. The worker maps raw IdP groups/roles into
those names with `AUDIENCE_MAP`; unmapped values are dropped before the session cookie is
minted.

```toml
AUDIENCE_MAP = '{"medical":["medical"],"secure":["secure"],"market-access":["market-access"]}'
```

The worker reads membership from exactly one claim, named by `GROUPS_CLAIM` (default
`groups`). There is no silent fallback to other claims, so an unexpected `groups`/`roles`
value can't grant access. Existing sessions keep their mapped audiences until their normal
session TTL expires.

> **Auth0** works as the OP via the generic flow. Auth0 silently drops non-namespaced custom
> claims from tokens, so roles must be injected under a namespaced key
> (`https://oidc.workers.dev/groups`) via a Post Login Action — then set
> `GROUPS_CLAIM = "https://oidc.workers.dev/groups"` so the worker reads exactly that claim.
> See [`auth0-setup.md`](./auth0-setup.md) for the full setup including the required Action code.

> **Adobe IMS** works as the OP via the generic flow, but IMS does **not** emit a `groups`
> claim in the `id_token` — entitlements require a post-login profile lookup and a
> product-profile↔group mapping. That extension is deliberately out of the core gate; see
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

- **Session cookie `__Host-gate_session`** (transient login state in `__Host-gate_login`):
  `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, HMAC-SHA256 signed; carries `sub`, minimal
  groups/entitlements, `iat`, `exp` (plus the `id_token` for `id_token_hint` on logout, never
  forwarded to origin). The `__Host-` prefix means a browser only accepts the cookie when
  `Secure`, `Path=/`, and Domain-less, so a sibling/non-secure subdomain can't overwrite it.
  Signing prevents tampering but does **not** hide the payload from the browser — if group
  names are sensitive, keep them out of the cookie or encrypt the payload.
- **Path canonicalization:** request paths are normalized (percent-decode, collapse `//`,
  resolve `.`/`..`) before policy matching, and encoded separators (`%2F`/`%5C`), backslashes,
  and malformed escapes are rejected with `400`, so the matcher and origin can never disagree
  about which resource was requested (e.g. `/blog/%2e%2e/members` can't be served as public).
- **Token validation:** RS256 only (no `alg:none`/HS256 confusion); `iss`/`aud`/`exp`(required)/
  `iat`/`nbf`/`nonce` enforced; `azp` checked when present and required for multi-valued
  `aud`; `c_hash`/`at_hash` verified (constant-time) when present; JWKS refetched **once** on
  a `kid` miss for key rotation, then reject. The discovery document is validated before use
  (its `issuer` must match `OIDC_ISSUER`; `authorization`/`token`/`jwks` endpoints must be
  `https`).
- **CSRF / replay:** `state` compared constant-time; `nonce` bound into the id_token;
  single-use state marker (KV, best-effort) rejects a replayed callback, and the callback
  **fails closed (`503`) if the KV store is unbound** rather than skipping the check; PKCE
  S256 protects the code exchange.
- **Logout:** RP-initiated logout is **POST-only** (a cross-site `GET` can't force a logout)
  and sends `id_token_hint` to the OP's `end_session_endpoint`.
- **Error responses:** generic JSON bodies (`{ error, request_id }`) with `nosniff` and, on
  `401`, a `WWW-Authenticate` challenge — no IdP/exception text is reflected to the caller.
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
- **Correlation:** `x-auth-request-id: <cf-ray>` is propagated to origin, and gate-generated
  error responses carry a matching `request_id` in their JSON body for log lookup.

## Performance

The authenticated hot path is a single origin `fetch()` with local HMAC verification — no
IdP round-trip per request. Discovery/JWKS are cached in KV and memoized in isolate memory
so a warm isolate never round-trips to KV; on a transient JWKS failure the gate serves
last-known-good keys within a staleness window rather than failing all logins.

## Testing & conformance

`npm test` runs the full positive/negative matrix (P1–P7, N1–N17 + N4b) against an
in-process mock OpenID Provider. The negative cases fail closed — a token that fails any
check never yields a session. CI (`.github/workflows/oidc-worker-gate-ci.yml`) gates every
change to `oidc-worker-gate/**`. The hosted OpenID Foundation RP suite is a
release/certification gate, not a per-build requirement — see
[`conformance-testing.md`](./conformance-testing.md).

## Roadmap

The delivery gate, DA-authored policy compiler, publisher worker, and manual refresh path
are implemented. Automatic DA publish/change event integration is deferred; until then,
refresh policy explicitly with `npm run refresh-policy` after publishing sheet changes.

`POLICY_SOURCE` controls policy availability behavior:

- `auto`: use signed DA/KV policy when available, otherwise static worker fallback.
- `worker`: ignore DA/KV policy and use only static worker policy.
- `required`: require signed DA/KV policy for content paths; if no valid policy or
  last-known-good policy is available, return `503`.

See the roadmap table and implementation record in [`phase-1-plan.md`](./phase-1-plan.md)
and the identity/authz design in [`folder-authorization.md`](./folder-authorization.md).

## Limitations

Research / reference implementation, not a hardened product. Only the `id_token` is
validated (access/refresh tokens are not persisted — add refresh handling for long-lived
sessions). Revocation is time-based. Single-use state replay protection is best-effort (CF
KV is eventually consistent) — see [`state-replay-do.md`](./state-replay-do.md) for a
strict Durable Object design. The `x-auth-*` origin-trust boundary must be enforced
operationally at the EDS origin.
