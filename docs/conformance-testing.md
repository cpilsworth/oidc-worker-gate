# Testing & RP standards conformance

How we test `oidc-worker-gate` and prove it behaves as a **conformant OpenID Connect
relying party**. Two layers, deliberately:

1. **Mock-OP harness (CI)** — a fake OpenID Provider running inside the test process
   asserts the worker *accepts* good tokens and *rejects* every malformed/forged one.
   Fast, deterministic, runs on every commit. This is where the conformance *substance*
   lives as code.
2. **Hosted OIDF conformance suite (certification gate)** — the OpenID Foundation's
   [conformance suite](https://www.certification.openid.net/) acts as a real OP and runs
   the official **RP test plans** against the deployed worker. This is not required for
   every Phase 1 build; run it before claiming formal conformance or certification.

## Specifications under test

| Spec | What the RP must do |
| --- | --- |
| **OpenID Connect Core 1.0** | auth-code flow, `id_token` validation (`iss`/`aud`/`exp`/`iat`/`nonce`), `c_hash`/`at_hash` when present |
| **OIDC Discovery 1.0** | fetch `/.well-known/openid-configuration`, use advertised endpoints + `jwks_uri` |
| **OAuth 2.0 — RFC 6749** | authorization-code grant, `state`, token endpoint, client auth |
| **PKCE — RFC 7636** | S256 challenge/verifier |
| **JWT/JWS/JWK/JWA — RFC 7519/7515/7517/7518** | RS256 verification against JWKS, `kid` selection, reject `alg:none` |
| **OAuth 2.0 Security BCP — RFC 9700** (and RFC 6819) | PKCE everywhere, exact redirect-URI match, no open redirect, `state`/`nonce` binding |

## Layer 1 — Mock-OP harness (CI)

**Tooling:** `vitest` + [`@cloudflare/vitest-pool-workers`](https://developers.cloudflare.com/workers/testing/vitest-integration/)
so tests execute inside the real `workerd` runtime (Web Crypto, KV, bindings behave as in
production). The mock OP is a small in-test module that:

- serves a canned **discovery doc** + **JWKS** (test RSA keypair),
- issues `id_token`s signed with the test key — and, per test case, *deliberately broken* ones,
- implements `token` endpoint responses (including PKCE `code_verifier` checks),

and is wired in by pointing `OIDC_ISSUER` at the mock and seeding `OIDC_CACHE` KV.

### Positive cases (happy paths)

| # | Scenario | Expected |
| --- | --- | --- |
| P1 | `protected` path, no session | 302 to `authorization_endpoint`; `state`+`nonce`+PKCE `code_challenge` present; transient signed cookie set |
| P2 | Valid callback (`code` + matching `state`) | `code`→token exchange w/ PKCE verifier; valid `id_token`; `__Host-gate_session` minted; 302 back to original path |
| P3 | Request with valid session | Forwarded to EDS origin; `x-auth-*` headers set; inbound `Cookie` stripped |
| P4 | `public` path, no session | Forwarded to origin, **no** auth attempted |
| P5 | `secured` path, valid session | Forwarded to origin |
| P6 | RP-initiated logout `/.auth/logout` (**POST**) | Session cookie cleared; redirect to `end_session_endpoint` with `id_token_hint` / post-logout URL |
| P7 | Required audience/entitlement present | `protected`/`secured` allowed |

### Negative cases — **the conformance substance**

The RP must reject every one of these (no session minted; surfaced as error, not pass-through).

> **Callback failure must be observable.** A failed callback validation returns a concrete
> error response — **`400 Bad Request` with a generic JSON body** (`{ "error": …,
> "request_id": … }`) — *distinct from* the start-login 302. The body is deliberately generic:
> it never reflects the IdP `error` parameter or an exception message back to the caller, but
> the real reason is logged server-side and correlatable via `request_id`. A worker that
> silently re-302s into login on a bad token reads to the OIDF suite (and to humans) as a
> redirect loop, not a rejection, and the negative test cannot pass.

| # | Tampered input | Expected RP behavior |
| --- | --- | --- |
| N1 | `id_token` with **invalid signature** | reject |
| N2 | `id_token` header **`alg: none`** (or `HS256` forged with pubkey) | reject — only configured RS256 accepted |
| N3 | Wrong **`iss`** | reject |
| N4 | Wrong/missing **`aud`** (not `client_id`) | reject |
| N4b | **Multi-valued `aud`** with missing or mismatched **`azp`** | reject — when `aud` has multiple values, `azp` MUST be present and equal `client_id` |
| N5 | **Expired** `exp` (and `iat`/`nbf` in future) | reject |
| N6 | Missing or mismatched **`nonce`** vs login | reject — replay protection |
| N7 | **`kid` mismatch** / key rotation / **`kid` absent** | match by `kid`, refetching JWKS **once** on a miss then rejecting; when the header omits `kid`, use the sole JWKS key, else reject (ambiguous) |
| N8 | Callback with **missing/mismatched `state`** | reject — CSRF |
| N9 | **Replayed `state`** (already consumed) | reject |
| N10 | Token exchange with **wrong PKCE `code_verifier`** | OP rejects; RP surfaces error, no session |
| N11 | **`c_hash` / `at_hash` mismatch** (when `code`/`access_token` present) | reject |
| N12 | OP returns **`error=` callback** (e.g. `access_denied`) | handled gracefully, no session, no 500 |
| N13 | `returnTo` set to an **absolute/cross-origin URL** | sanitized to same-origin relative — no open redirect |
| N14 | **`secured`** path, no/invalid session | **401**, no redirect; body is the origin `/error/401` page (forced to 401) or generic JSON if absent; carries `WWW-Authenticate`, `X-Content-Type-Options: nosniff`, `Cache-Control: private, no-store`, `x-request-id` |
| N15 | Valid session but missing the matched row's required **audience** | **403** (origin `/error/403` page forced to 403, or generic JSON if absent) |
| N16 | Logout via cross-site **`GET`** (CSRF) | **405**, session not cleared — only `POST` performs logout |
| N17 | Path-matcher bypass: encoded traversal under a public prefix (`/blog/%2e%2e/members/secret`) or an encoded separator (`%2F`/`%5C`) | canonicalized before classify → treated as the real (protected) path, or **`400`** for encoded separators/malformed escapes — never served as public |

### Run

```bash
npm test            # vitest run (mock-OP harness, all P* and N* cases)
npm run test:watch
```

Pass criteria: all P/N cases green; **N-series must fail closed** (a token that fails any
check never yields a session). These are CI gating.

## Layer 2 — Hosted OIDF conformance suite (certification gate)

The mock harness proves *our* assertions; the OIDF suite proves conformance against the
canonical, independently-maintained probes and yields a shareable result.

**Target RP test plans** (confidential client, code flow, PKCE, discovery):

- **Basic RP** — authorization-code flow (plan slug ≈ `oidcc-client-basic-certification-test-plan`;
  confirm the exact slug against the suite's current plan list when setting up).
- **Config RP** — verifies the RP correctly consumes the discovery document / `jwks_uri`.

(Form-Post RP and Dynamic RP are out of scope — we use the code response mode and static
client registration.)

**Practical requirements** (the suite drives a browser against a *reachable* RP):

1. Deploy the worker to a public hostname (`wrangler deploy` to a staging zone/`workers.dev`).
2. Create a test plan at <https://www.certification.openid.net/>; it provisions a test OP
   with its own `issuer` + credentials.
3. Point the worker's `OIDC_ISSUER` / `CLIENT_ID` / `OIDC_CLIENT_SECRET` / `REDIRECT_URI`
   at that test OP (a dedicated staging config).
4. For each test, the suite navigates the worker's **login-initiation URL** (hit any
   `protected` path) and drives the browser; some tests require re-running login.
5. Capture the suite's per-test results as the conformance report.

Self-hosting is possible via the suite's container
([`gitlab.com/openid/conformance-suite`](https://gitlab.com/openid/conformance-suite)) if
the worker can't be exposed publicly.

## Coverage summary

- **Layer 1** gates every commit and encodes the negative-case matrix as executable specs.
- **Layer 2** gates certification/release claims, especially after IdP or crypto changes,
  but it is not on the Phase 1 implementation critical path.
- Worker-specific behavior outside OIDC conformance — policy precedence, EDS infra public
  allowlist, cookie stripping, `x-auth-*` injection, request-id propagation, and
  protected/secured `no-store` caching — should be covered by focused unit/integration
  tests alongside the mock-OP suite.
- Hardening behaviors also covered by focused tests: **request-path canonicalization**
  (`path.test.js`, `gate-normalization.test.js`, N17), **discovery-document validation**
  (issuer match + https endpoints, `jwt.test.js` H8), **callback fail-closed when the state
  store is unbound** (`oidc.test.js` H5), **`__Host-` cookie prefix** (H3), **generic error
  bodies + `nosniff`/`WWW-Authenticate`/`request_id`** (H7), **config invariants** (≥32-byte
  HMAC keys, positive-integer TTLs — `config.test.js` H6), and the **DA publish breadth
  guard** (site-wide `public /**` rejected — `policy-publisher.test.js` H2).
