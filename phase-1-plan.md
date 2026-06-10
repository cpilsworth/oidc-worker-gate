# oidc-worker-gate Phase 1 — TDD Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Phase 1 "core gate" — a Cloudflare Worker that fronts an AEM EDS origin as an OIDC relying party, classifying each request into `public` / `protected` / `secured` and enforcing access locally via an HMAC session cookie.

**Architecture:** ES-module Worker (`export default { fetch(request, env, ctx) }`). The hot path reads + HMAC-verifies a `__gate_session` cookie with no backend call and forwards to the EDS origin with a single `fetch()`. Login (auth-code + PKCE) and `id_token` validation (RS256 vs JWKS) run only on the rare callback. Discovery/JWKS are cached in KV (`OIDC_CACHE`). Generic IdP only — no Adobe IMS profile fetch, no DA-sourced ACL, no User Management API (those are Phases 2–3).

**Tech Stack:** Cloudflare Workers + `wrangler`; `vitest` + `@cloudflare/vitest-pool-workers` (tests run in the real `workerd` runtime); Web Crypto (`crypto.subtle`) for RS256 verify + HMAC-SHA256; KV binding `OIDC_CACHE`. No runtime npm dependencies, no `nodejs_compat`.

> **Status: Phase 1 implemented.** All tasks below are complete — 10 `src/*.js` modules + 11
> vitest files, 59 tests green in `workerd`. See [`README.md`](./README.md) for what the
> gate does and how to deploy/configure it. This document is retained as the implementation
> record and the template for executing Phases 2–3.

---

## Roadmap (where Phase 1 sits)

The project splits into three subsystems at very different risk levels. **Build them in
order** — Phase 1 is a complete, demonstrable RP that depends on **no open questions**;
Phases 2–3 carry the unresolved identity work and must not block it.

| Phase | Scope | Ships alone? | Blocked on |
| --- | --- | --- | --- |
| **1 — Core gate** ✅ | Generic IdP, static `ACCESS_POLICY`, three tiers, single origin `fetch()`, mock-OP tests (P1–P7, N1–N15) | **Yes** | nothing |
| **2 — IMS as OP** | Swap issuer to IMS, add `/ims/profile/v1` fetch at session-mint, map product-profiles → session entitlements | No (needs Phase 1) | [`folder-authorization.md`](./folder-authorization.md) Q3 |
| **3 — DA folder-authz** | Control-plane push → KV ACL, unified matcher, last-known-good | No (needs Phase 1) | Q3 + Q4 |

> Building the DA control-plane pipeline (Phase 3) or the IMS profile fetch (Phase 2) before
> the core gate works — and before Q3 resolves whether the DA ACL names product-profiles or
> user-groups — is the project's main YAGNI/risk trap. Phase 1 first. Phases 2–3 are
> milestoned in [`folder-authorization.md`](./folder-authorization.md) once their open
> questions resolve.

---

## How to use this plan (TDD contract)

**Tests are written first, and a green `npm test` is the definition of done.** Every
task follows red→green→commit:

1. Write the failing test(s) — complete code, no stubs.
2. Run the named test and **confirm it fails** for the stated reason (the module/function
   doesn't exist yet, or the assertion is unmet). A test that passes before you've written
   the code is a broken test — fix the test.
3. Write the **minimal** implementation to make it pass.
4. Run the test and **confirm it passes**.
5. Commit.

A task is **done only when its tests are green and `npm test` (the whole suite) is still
green.** No task is "done" because the code "looks right." The conformance matrix in
[`conformance-testing.md`](./conformance-testing.md) (P1–P7, N1–N15) is the acceptance
spec; this plan turns each row into an executable test. The final gate (Task 11) is not
done until every P/N case is green.

**Ground truth for ports:** the OIDC crypto is ported from
[`../oidc-edge-gate/src/`](../oidc-edge-gate/src). It is already Web Crypto, so it moves
over almost unchanged. The **three Fastly→Cloudflare deltas** applied throughout:

| Fastly (sibling) | Cloudflare (this worker) |
| --- | --- |
| `import { KVStore } from "fastly:kv-store"; new KVStore("oidc_cache")` | `env.OIDC_CACHE` (KV binding), threaded through `config.kv` |
| `fetch(url, { backend: config.backends.idp })` | `fetch(url)` — Workers has no `backend` concept |
| `ConfigStore` / `SecretStore` (async) | plain `env.*` vars + secrets (sync `loadConfig(env)`) |
| `addEventListener("fetch", …)` | `export default { async fetch(request, env, ctx) }` |

Cookie names are renamed to match this project's README: `__gate_session` / `__gate_login`
(sibling uses `__edge_session` / `__edge_login`).

---

## File structure

```
oidc-worker-gate/
├── src/
│   ├── index.js      # NEW(CF)  entry: classify tier → dispatch (public/protected/secured + gate routes)
│   ├── policy.js     # NEW      ACCESS_POLICY parse, classify(path)→{tier,audience}, isAuthorized()
│   ├── origin.js     # NEW      forwardToOrigin: Host/X-Forwarded-Host/push-inval, cookie strip, x-auth-*, cache carve-out
│   ├── oidc.js       # PORT     OidcClient: startLogin / handleCallback / handleLogout
│   ├── jwt.js        # PORT+    verifyIdToken: RS256/JWKS, iss/aud/azp/exp/nbf/nonce, c_hash/at_hash, kid-refetch-once; KV cache
│   ├── session.js    # PORT     readSession / mintSessionCookie / state-cookie helpers (renamed cookies)
│   ├── pkce.js       # PORT     createPkcePair / randomState / randomNonce
│   ├── cookies.js    # PORT     parseCookies / serializeCookie / sign / unsign
│   ├── config.js     # NEW(CF)  loadConfig(env) → Config (vars + secrets + KV binding)
│   └── encoding.js   # PORT     base64url / utf8 / timingSafeEqual / decodeJsonSegment
├── test/
│   ├── mock-op.js    # mock OpenID Provider: discovery + JWKS + token endpoint; mints good + deliberately-broken id_tokens
│   ├── helpers.js    # RSA keygen, KV seeding, request builders, cookie extraction
│   ├── encoding.test.js
│   ├── cookies.test.js
│   ├── pkce.test.js
│   ├── session.test.js
│   ├── config.test.js
│   ├── policy.test.js      # tier precedence, default_tier, isAuthorized (the three-tier substance)
│   ├── jwt.test.js         # N1–N7, N11, azp
│   ├── oidc.test.js        # N8–N13, P2, P6
│   ├── origin.test.js      # P3, caching carve-out
│   └── gate.test.js        # end-to-end via worker fetch: P1,P4,P5,P7, N14,N15
├── wrangler.toml
├── vitest.config.js
└── package.json
```

The `Config` object (returned by `loadConfig(env)`, consumed everywhere):

```js
/**
 * @typedef {Object} Config
 * @property {string}   issuer
 * @property {string}   clientId
 * @property {string}   clientSecret
 * @property {string}   redirectUri
 * @property {string}   scopes
 * @property {number}   sessionTtlSeconds
 * @property {string}   sessionKey            // HMAC secret
 * @property {string}   originHostname        // main--site--org.aem.live
 * @property {string}   forwardedHost         // public production domain
 * @property {boolean}  pushInvalidation
 * @property {{callback:string, logout:string}} routes
 * @property {{rules:{path:string,tier:string,audience?:string[]}[], default_tier:string}} policy
 * @property {KVNamespace|null} kv             // env.OIDC_CACHE
 */
```

---

## Task 1: Scaffold + test harness (mock OP)

This task has no production code; its "test" is that the harness boots and a smoke test
runs in `workerd`. Everything after it is real TDD.

**Files:**
- Create: `oidc-worker-gate/package.json`
- Create: `oidc-worker-gate/wrangler.toml`
- Create: `oidc-worker-gate/vitest.config.js`
- Create: `oidc-worker-gate/test/helpers.js`
- Create: `oidc-worker-gate/test/mock-op.js`
- Create: `oidc-worker-gate/test/smoke.test.js`

- [ ] **Step 1: `package.json`**

```json
{
  "name": "oidc-worker-gate",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "wrangler dev",
    "deploy": "wrangler deploy",
    "test": "vitest run",
    "test:watch": "vitest"
  },
  "devDependencies": {
    "@cloudflare/vitest-pool-workers": "^0.16.0",
    "vitest": "^4.1.0",
    "wrangler": "^4.99.0"
  }
}
```

- [ ] **Step 2: `wrangler.toml`** (test/dev config; production routes are set at deploy time)

```toml
name = "oidc-worker-gate"
main = "src/index.js"
compatibility_date = "2025-06-01"

[[kv_namespaces]]
binding = "OIDC_CACHE"
id = "oidc_cache_placeholder"          # real id set per environment at deploy time

[vars]
OIDC_ISSUER       = "https://op.test"
CLIENT_ID         = "test-client"
REDIRECT_URI      = "https://www.example.com/.auth/callback"
SCOPES            = "openid profile email groups"
SESSION_TTL       = "3600"
ORIGIN_HOSTNAME   = "main--mysite--myorg.aem.live"
FORWARDED_HOST    = "www.example.com"
PUSH_INVALIDATION = "enabled"
ROUTES            = '{"callback":"/.auth/callback","logout":"/.auth/logout"}'
ACCESS_POLICY     = '''{
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

Secrets are **not** in `wrangler.toml`. In tests they are injected via the pool's
`miniflare.bindings`. In production: `wrangler secret put OIDC_CLIENT_SECRET` and
`wrangler secret put SESSION_HMAC_KEY`.

- [ ] **Step 3: `vitest.config.js`** — run tests inside `workerd`, inject secret bindings

```js
import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

// vitest-pool-workers 0.16.x (the vitest-4 era) uses a PLUGIN API: pass the worker config
// straight into cloudflareTest(...). The older `defineWorkersConfig()` / the
// `@cloudflare/vitest-pool-workers/config` subpath / the `test.poolOptions.workers` nesting
// were all removed in this major — confirmed against the installed package's exports map and
// its `codemods/vitest-v3-to-v4` transform. Keep the worker config (wrangler + miniflare)
// exactly as below; only the wrapper changed.
export default defineConfig({
  plugins: [
    cloudflareTest({
        wrangler: { configPath: "./wrangler.toml" },
        miniflare: {
          // Secrets aren't in wrangler.toml; provide them to the test runtime.
          bindings: {
            OIDC_CLIENT_SECRET: "test-client-secret",
            SESSION_HMAC_KEY: "test-hmac-key-at-least-32-bytes-long!!",
          },
          // Intercept the worker's OUTBOUND subrequests when it runs under SELF.fetch
          // (gate.test.js). The only outbound in the Phase 1 gate cases is the EDS origin
          // forward — discovery/JWKS are seeded into KV, so no live OP call happens there.
          // Module-level tests (jwt/oidc) call functions directly in the test realm and use
          // their own `globalThis.fetch` override instead; this only affects SELF dispatch.
          outboundService(request) {
            const url = new URL(request.url);
            if (url.hostname.endsWith("aem.live")) {
              return new Response("origin-body", { headers: { "cache-control": "public, max-age=60" } });
            }
            return new Response(`unexpected outbound: ${request.url}`, { status: 502 });
          },
        },
    }),
  ],
});
```

- [ ] **Step 4: `test/helpers.js`** — RSA keygen, JWT minting, KV seeding, request/cookie utils

```js
// Test utilities shared by the mock OP and the worker tests.
// All crypto uses Web Crypto so it runs identically in workerd.

import { env } from "cloudflare:test";

const enc = new TextEncoder();

export function b64url(bytes) {
  const arr = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes;
  let bin = "";
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlJson(obj) {
  return b64url(enc.encode(JSON.stringify(obj)));
}

/** Generate an RSA-256 signing keypair and export the public half as a JWK with a kid. */
export async function makeRsaKey(kid = "test-key-1") {
  const pair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  jwk.kid = kid;
  jwk.alg = "RS256";
  jwk.use = "sig";
  return { privateKey: pair.privateKey, publicJwk: jwk, kid };
}

/** Sign a JWT (RS256) from header+claims using a private key. */
export async function signJwt(header, claims, privateKey) {
  const h = b64urlJson(header);
  const p = b64urlJson(claims);
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    enc.encode(`${h}.${p}`),
  );
  return `${h}.${p}.${b64url(sig)}`;
}

/** at_hash / c_hash: base64url(left-128-bits(SHA-256(ascii(token)))). */
export async function tokenHash(token) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(token)));
  return b64url(digest.slice(0, digest.length / 2));
}

/** Seed the discovery doc + JWKS into the worker's KV exactly as jwt.js caches them. */
export async function seedDiscovery(issuer, discovery, jwks) {
  const ttl = Date.now() + 3600_000;
  await env.OIDC_CACHE.put(`discovery:${issuer}`, JSON.stringify({ value: discovery, expires: ttl }));
  await env.OIDC_CACHE.put(`jwks:${discovery.jwks_uri}`, JSON.stringify({ value: jwks, expires: ttl }));
}

/** Build a Request with an optional cookie header. */
export function reqFor(path, { cookie, method = "GET", headers = {} } = {}) {
  const h = new Headers(headers);
  if (cookie) h.set("cookie", cookie);
  return new Request(`https://www.example.com${path}`, { method, headers: h });
}

/** Pull a named cookie value out of a Response's Set-Cookie header(s). */
export function getSetCookie(res, name) {
  const all = res.headers.getSetCookie ? res.headers.getSetCookie() : [res.headers.get("set-cookie")];
  for (const line of all.filter(Boolean)) {
    const m = line.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
    if (m) return decodeURIComponent(m[1]);
  }
  return null;
}
```

- [ ] **Step 5: `test/mock-op.js`** — a fake OpenID Provider as a `fetch` handler

```js
// In-test OpenID Provider. Serves discovery + JWKS, exchanges codes for tokens,
// and mints id_tokens — including, per the `broken` flag, deliberately invalid ones.
// Install it as the global fetch so the worker's discovery/JWKS/token calls hit it.

import { makeRsaKey, signJwt, tokenHash, b64urlJson, b64url } from "./helpers.js";

export async function createMockOp({ issuer = "https://op.test", clientId = "test-client" } = {}) {
  const key = await makeRsaKey();
  const discovery = {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks`,
    end_session_endpoint: `${issuer}/logout`,
  };
  const jwks = { keys: [key.publicJwk] };

  // code -> { claims override, nonce, verifierExpected }
  const codes = new Map();

  /** Register a code the token endpoint will accept; returns the code string. */
  function issueCode(code, { claims = {}, codeChallenge, accessToken = "access-token-xyz" } = {}) {
    codes.set(code, { claims, codeChallenge, accessToken });
    return code;
  }

  /** Build an id_token. `broken` mutates header/claims/signature to exercise N-cases. */
  async function mintIdToken({ nonce, claims = {}, accessToken, code, broken } = {}) {
    const now = Math.floor(Date.now() / 1000);
    let header = { alg: "RS256", kid: key.kid, typ: "JWT" };
    let body = {
      iss: issuer, aud: clientId, sub: "user-123", email: "u@example.com",
      groups: ["site-readers"], iat: now, exp: now + 3600, nonce, ...claims,
    };
    if (accessToken) body.at_hash = await tokenHash(accessToken);
    if (code) body.c_hash = await tokenHash(code);

    let signKey = key.privateKey;
    switch (broken) {
      case "alg-none": {
        const h = b64urlJson({ ...header, alg: "none" });
        const p = b64urlJson(body);
        return `${h}.${p}.`;
      }
      case "bad-sig": {
        const other = await makeRsaKey("rogue"); signKey = other.privateKey; break;
      }
      case "wrong-iss":  body.iss = "https://evil.test"; break;
      case "wrong-aud":  body.aud = "someone-else"; break;
      case "multi-aud-no-azp": body.aud = [clientId, "other"]; delete body.azp; break;
      case "expired":    body.exp = now - 7200; break;   // well past the 60s skew window
      case "bad-nonce":  body.nonce = "not-the-login-nonce"; break;
      case "bad-at-hash": body.at_hash = "AAAAAAAAAAAAAAAAAAAAAA"; break;
      // N7 (kid rotation) is exercised in jwt.test.js with signJwt + a custom kid,
      // not via a broken-mode here, so the refetch-count spy can assert "exactly once".
    }
    return signJwt(header, body, signKey);
  }

  async function handle(request) {
    const url = new URL(request.url);
    if (url.pathname === "/.well-known/openid-configuration")
      return Response.json(discovery);
    if (url.pathname === "/jwks") return Response.json(jwks);
    if (url.pathname === "/token" && request.method === "POST") {
      const form = new URLSearchParams(await request.text());
      const rec = codes.get(form.get("code"));
      if (!rec) return new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400 });
      // PKCE check: S256(code_verifier) must equal the registered challenge.
      if (rec.codeChallenge) {
        const v = form.get("code_verifier") || "";
        const dg = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(v)));
        const challenge = b64url(dg);
        if (challenge !== rec.codeChallenge)
          return new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400 });
      }
      const id_token = await mintIdToken({
        nonce: rec.claims.nonce, claims: rec.claims, accessToken: rec.accessToken,
        code: form.get("code"), broken: rec.broken,
      });
      return Response.json({ access_token: rec.accessToken, id_token, token_type: "Bearer" });
    }
    return new Response("not found", { status: 404 });
  }

  return { discovery, jwks, key, issueCode, mintIdToken, handle, codes,
    setBrokenForCode(code, broken) { codes.get(code).broken = broken; } };
}
```

- [ ] **Step 5b: Create a stub `src/index.js`** (required for the test runtime to boot)

`wrangler.toml` sets `main = "src/index.js"`, and `@cloudflare/vitest-pool-workers`
resolves that entry on startup **even for module-level unit tests** — without it the suite
errors with `Cannot find module '.../src/index.js'`. Task 11 replaces this with the real
worker.

```js
// Task 1 stub — replaced by the real worker in Task 11.
export default {
  async fetch(request, env, ctx) {
    return new Response("not implemented", { status: 501 });
  },
};
```

- [ ] **Step 6: Write the smoke test `test/smoke.test.js`**

```js
import { describe, it, expect } from "vitest";
import { env } from "cloudflare:test";

describe("harness", () => {
  it("runs in workerd with Web Crypto + KV bindings", async () => {
    expect(typeof crypto.subtle.digest).toBe("function");
    await env.OIDC_CACHE.put("k", "v");
    expect(await env.OIDC_CACHE.get("k")).toBe("v");
  });
});
```

- [ ] **Step 7: Install + run the smoke test**

Run: `cd oidc-worker-gate && npm install && npm test`
Expected: `smoke.test.js` PASS (1 test). It proves Web Crypto and the `OIDC_CACHE` KV
binding are live inside `workerd`. Other test files don't exist yet.

- [ ] **Step 8: Commit**

```bash
git add oidc-worker-gate/package.json oidc-worker-gate/wrangler.toml \
  oidc-worker-gate/vitest.config.js oidc-worker-gate/src/index.js oidc-worker-gate/test/
git commit -m "test: scaffold oidc-worker-gate + mock-OP harness (workerd/vitest)"
```

---

## Task 2: `encoding.js` (verbatim port)

**Files:**
- Create: `oidc-worker-gate/src/encoding.js`
- Test: `oidc-worker-gate/test/encoding.test.js`

- [ ] **Step 1: Write the failing test**

```js
import { describe, it, expect } from "vitest";
import { base64UrlEncode, base64UrlDecode, decodeJsonSegment, timingSafeEqual, utf8, fromUtf8 } from "../src/encoding.js";

describe("encoding", () => {
  it("round-trips base64url without padding", () => {
    const bytes = new Uint8Array([255, 0, 128, 64, 1]);
    const s = base64UrlEncode(bytes);
    expect(s).not.toMatch(/[+/=]/);
    expect([...base64UrlDecode(s)]).toEqual([...bytes]);
  });
  it("decodes a base64url JSON segment", () => {
    const seg = base64UrlEncode(utf8(JSON.stringify({ a: 1 })));
    expect(decodeJsonSegment(seg)).toEqual({ a: 1 });
  });
  it("timingSafeEqual is true only for equal strings", () => {
    expect(timingSafeEqual("abc", "abc")).toBe(true);
    expect(timingSafeEqual("abc", "abd")).toBe(false);
    expect(timingSafeEqual("abc", "abcd")).toBe(false);
  });
  it("utf8 round-trips", () => { expect(fromUtf8(utf8("héllo"))).toBe("héllo"); });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npm test -- encoding`
Expected: FAIL — `Cannot find module '../src/encoding.js'`.

- [ ] **Step 3: Implement (port from sibling, no Fastly deps to change)**

```js
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

- [ ] **Step 4: Run to verify it passes** — `npm test -- encoding` → PASS (4 tests).
- [ ] **Step 5: Commit** — `git add src/encoding.js test/encoding.test.js && git commit -m "feat: port encoding helpers"`

---

## Task 3: `cookies.js` (verbatim port)

**Files:**
- Create: `oidc-worker-gate/src/cookies.js`
- Test: `oidc-worker-gate/test/cookies.test.js`

- [ ] **Step 1: Write the failing test**

```js
import { describe, it, expect } from "vitest";
import { parseCookies, serializeCookie, sign, unsign } from "../src/cookies.js";

const KEY = "test-hmac-key-at-least-32-bytes-long!!";

describe("cookies", () => {
  it("parses a cookie header into a map", () => {
    expect(parseCookies("a=1; b=two%20words")).toEqual({ a: "1", b: "two words" });
    expect(parseCookies(null)).toEqual({});
  });
  it("serializes with security attributes by default", () => {
    const c = serializeCookie("__gate_session", "v", { maxAge: 60 });
    expect(c).toContain("__gate_session=v");
    expect(c).toContain("HttpOnly");
    expect(c).toContain("Secure");
    expect(c).toContain("SameSite=Lax");
    expect(c).toContain("Max-Age=60");
  });
  it("sign/unsign round-trips and rejects tampering", async () => {
    const token = await sign(JSON.stringify({ sub: "x" }), KEY);
    expect(await unsign(token, KEY)).toBe('{"sub":"x"}');
    expect(await unsign(token + "x", KEY)).toBeNull();
    expect(await unsign(token, "wrong-key")).toBeNull();
  });
});
```

- [ ] **Step 2: Run to verify it fails** — `npm test -- cookies` → FAIL (module missing).

- [ ] **Step 3: Implement (port verbatim)**

```js
import { base64UrlEncode, base64UrlDecode, fromUtf8, timingSafeEqual, utf8 } from "./encoding.js";

export function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const name = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (name) out[name] = decodeURIComponent(value);
  }
  return out;
}

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

async function hmacKey(secret) {
  return crypto.subtle.importKey("raw", utf8(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

export async function sign(payload, secret) {
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, utf8(payload));
  return `${base64UrlEncode(utf8(payload))}.${base64UrlEncode(sig)}`;
}

export async function unsign(token, secret) {
  const dot = token.lastIndexOf(".");
  if (dot === -1) return null;
  const payloadB64 = token.slice(0, dot);
  const sigB64 = token.slice(dot + 1);
  const payload = fromUtf8(base64UrlDecode(payloadB64));
  const key = await hmacKey(secret);
  const expected = base64UrlEncode(await crypto.subtle.sign("HMAC", key, utf8(payload)));
  return timingSafeEqual(expected, sigB64) ? payload : null;
}
```

- [ ] **Step 4: Run to verify it passes** — `npm test -- cookies` → PASS (3 tests).
- [ ] **Step 5: Commit** — `git commit -am "feat: port signed-cookie helpers"`

---

## Task 4: `pkce.js` (verbatim port)

**Files:**
- Create: `oidc-worker-gate/src/pkce.js`
- Test: `oidc-worker-gate/test/pkce.test.js`

- [ ] **Step 1: Write the failing test**

```js
import { describe, it, expect } from "vitest";
import { createPkcePair, randomState, randomNonce } from "../src/pkce.js";
import { base64UrlEncode } from "../src/encoding.js";

describe("pkce", () => {
  it("creates an S256 verifier/challenge pair", async () => {
    const { verifier, challenge, method } = await createPkcePair();
    expect(method).toBe("S256");
    expect(verifier).not.toMatch(/[+/=]/);
    const dg = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    expect(challenge).toBe(base64UrlEncode(dg));
  });
  it("state and nonce are unique random strings", () => {
    expect(randomState()).not.toBe(randomState());
    expect(randomNonce()).not.toBe(randomNonce());
  });
});
```

- [ ] **Step 2: Run to verify it fails** — `npm test -- pkce` → FAIL (module missing).

- [ ] **Step 3: Implement (port verbatim)**

```js
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

- [ ] **Step 4: Run to verify it passes** — `npm test -- pkce` → PASS (2 tests).
- [ ] **Step 5: Commit** — `git commit -am "feat: port PKCE + state/nonce generation"`

---

## Task 5: `session.js` (port, renamed cookies)

**Files:**
- Create: `oidc-worker-gate/src/session.js`
- Test: `oidc-worker-gate/test/session.test.js`

- [ ] **Step 1: Write the failing test**

```js
import { describe, it, expect } from "vitest";
import { SESSION_COOKIE, mintSessionCookie, readSession, clearSessionCookie,
         mintStateCookie, readStateCookie, clearStateCookie } from "../src/session.js";
import { reqFor, getSetCookie } from "./helpers.js";

const config = { sessionKey: "test-hmac-key-at-least-32-bytes-long!!", sessionTtlSeconds: 3600 };

describe("session", () => {
  it("uses the project cookie name", () => { expect(SESSION_COOKIE).toBe("__gate_session"); });

  it("mints then reads a valid session", async () => {
    const setCookie = await mintSessionCookie(
      { sub: "user-123", email: "u@example.com", groups: ["site-readers"] }, config);
    const value = setCookie.match(/__gate_session=([^;]*)/)[1];
    const req = reqFor("/members/x", { cookie: `__gate_session=${value}` });
    const s = await readSession(req, config);
    expect(s.sub).toBe("user-123");
    expect(s.groups).toEqual(["site-readers"]);
  });

  it("returns null for an expired session", async () => {
    const expired = { ...config, sessionTtlSeconds: -10 };
    const setCookie = await mintSessionCookie({ sub: "x" }, expired);
    const value = setCookie.match(/__gate_session=([^;]*)/)[1];
    const s = await readSession(reqFor("/m", { cookie: `__gate_session=${value}` }), config);
    expect(s).toBeNull();
  });

  it("returns null for a tampered session", async () => {
    const setCookie = await mintSessionCookie({ sub: "x" }, config);
    const value = setCookie.match(/__gate_session=([^;]*)/)[1];
    const tampered = value.slice(0, -2) + (value.endsWith("aa") ? "bb" : "aa");
    expect(await readSession(reqFor("/m", { cookie: `__gate_session=${tampered}` }), config)).toBeNull();
  });

  it("state cookie round-trips and clears", async () => {
    const setCookie = await mintStateCookie({ state: "s", nonce: "n", verifier: "v", returnTo: "/members/x" }, config);
    expect(setCookie).toContain("__gate_login=");
    const value = setCookie.match(/__gate_login=([^;]*)/)[1];
    const saved = await readStateCookie(reqFor("/.auth/callback", { cookie: `__gate_login=${value}` }), config);
    expect(saved.returnTo).toBe("/members/x");
    expect(clearStateCookie()).toContain("Max-Age=0");
    expect(clearSessionCookie()).toContain("Max-Age=0");
  });
});
```

- [ ] **Step 2: Run to verify it fails** — `npm test -- session` → FAIL (module missing).

- [ ] **Step 3: Implement (port; cookie names changed to `__gate_*`)**

```js
import { parseCookies, serializeCookie, sign, unsign } from "./cookies.js";

export const SESSION_COOKIE = "__gate_session";
const STATE_COOKIE = "__gate_login";

export async function readSession(req, config) {
  const token = parseCookies(req.headers.get("cookie"))[SESSION_COOKIE];
  if (!token) return null;
  const payload = await unsign(token, config.sessionKey);
  if (!payload) return null;
  try {
    const session = JSON.parse(payload);
    if (typeof session.exp !== "number" || session.exp * 1000 <= Date.now()) return null;
    return session;
  } catch { return null; }
}

export async function mintSessionCookie(claims, config) {
  const now = Math.floor(Date.now() / 1000);
  const session = {
    sub: claims.sub, email: claims.email, name: claims.name,
    groups: claims.groups || claims.roles || [],
    iat: now, exp: now + config.sessionTtlSeconds,
  };
  const token = await sign(JSON.stringify(session), config.sessionKey);
  return serializeCookie(SESSION_COOKIE, token, { maxAge: config.sessionTtlSeconds });
}

export function clearSessionCookie() { return serializeCookie(SESSION_COOKIE, "", { maxAge: 0 }); }

export async function mintStateCookie(state, config) {
  const token = await sign(JSON.stringify(state), config.sessionKey);
  return serializeCookie(STATE_COOKIE, token, { maxAge: 600, sameSite: "Lax" });
}

export async function readStateCookie(req, config) {
  const token = parseCookies(req.headers.get("cookie"))[STATE_COOKIE];
  if (!token) return null;
  const payload = await unsign(token, config.sessionKey);
  if (!payload) return null;
  try { return JSON.parse(payload); } catch { return null; }
}

export function clearStateCookie() { return serializeCookie(STATE_COOKIE, "", { maxAge: 0 }); }
```

- [ ] **Step 4: Run to verify it passes** — `npm test -- session` → PASS (5 tests).
- [ ] **Step 5: Commit** — `git commit -am "feat: port HMAC session + transient state cookies (gate-named)"`

---

## Task 6: `config.js` (new — CF env loader)

**Files:**
- Create: `oidc-worker-gate/src/config.js`
- Test: `oidc-worker-gate/test/config.test.js`

- [ ] **Step 1: Write the failing test**

```js
import { describe, it, expect } from "vitest";
import { loadConfig } from "../src/config.js";

const env = {
  OIDC_ISSUER: "https://op.test/",       // trailing slash must be trimmed
  CLIENT_ID: "test-client",
  OIDC_CLIENT_SECRET: "secret",
  REDIRECT_URI: "https://www.example.com/.auth/callback",
  SCOPES: "openid profile email groups",
  SESSION_TTL: "3600",
  ORIGIN_HOSTNAME: "main--mysite--myorg.aem.live",
  FORWARDED_HOST: "www.example.com",
  PUSH_INVALIDATION: "enabled",
  SESSION_HMAC_KEY: "test-hmac-key-at-least-32-bytes-long!!",
  ROUTES: '{"callback":"/.auth/callback","logout":"/.auth/logout"}',
  ACCESS_POLICY: '{"rules":[{"path":"/","tier":"public"}],"default_tier":"protected"}',
  OIDC_CACHE: { fake: "kv" },
};

describe("loadConfig", () => {
  it("maps env vars + secrets into a Config", () => {
    const c = loadConfig(env);
    expect(c.issuer).toBe("https://op.test");            // trimmed
    expect(c.clientId).toBe("test-client");
    expect(c.clientSecret).toBe("secret");
    expect(c.sessionTtlSeconds).toBe(3600);
    expect(c.pushInvalidation).toBe(true);
    expect(c.routes.callback).toBe("/.auth/callback");
    expect(c.policy.default_tier).toBe("protected");
    expect(c.policy.rules[0]).toEqual({ path: "/", tier: "public" });
    expect(c.kv).toBe(env.OIDC_CACHE);
  });
  it("throws if a required secret is missing", () => {
    expect(() => loadConfig({ ...env, SESSION_HMAC_KEY: undefined })).toThrow(/SESSION_HMAC_KEY/);
  });
});
```

- [ ] **Step 2: Run to verify it fails** — `npm test -- config` → FAIL (module missing).

- [ ] **Step 3: Implement**

```js
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
```

- [ ] **Step 4: Run to verify it passes** — `npm test -- config` → PASS (2 tests).
- [ ] **Step 5: Commit** — `git commit -am "feat: CF env/secret/KV config loader"`

---

## Task 7: `policy.js` (new — the three-tier substance)

Implements **tier precedence**, **`default_tier`**, and **audience authorization** — the
core conceptual contribution of this worker. Tests encode the precedence rules.

**Files:**
- Create: `oidc-worker-gate/src/policy.js`
- Test: `oidc-worker-gate/test/policy.test.js`

- [ ] **Step 1: Write the failing test**

```js
import { describe, it, expect } from "vitest";
import { classify, isAuthorized } from "../src/policy.js";

const policy = {
  rules: [
    { path: "/", tier: "public" },
    { path: "/blog/*", tier: "public" },
    { path: "/media_*", tier: "public" },
    { path: "/*.plain.html", tier: "public" },
    { path: "/members/*", tier: "protected", audience: ["site-readers"] },
    { path: "/members/admin/*", tier: "protected", audience: ["admins"] },
    { path: "/api/*", tier: "secured", audience: ["site-readers"] },
  ],
  default_tier: "protected",
};

describe("classify", () => {
  it("exact root match is public", () => {
    expect(classify("/", policy)).toEqual({ tier: "public", audience: undefined });
  });
  it("prefix globs match", () => {
    expect(classify("/blog/2026/post", policy).tier).toBe("public");
    expect(classify("/media_abc123.png", policy).tier).toBe("public");
    expect(classify("/foo.plain.html", policy).tier).toBe("public");
  });
  it("most-specific rule wins (longer literal prefix)", () => {
    expect(classify("/members/x", policy)).toEqual({ tier: "protected", audience: ["site-readers"] });
    expect(classify("/members/admin/y", policy)).toEqual({ tier: "protected", audience: ["admins"] });
  });
  it("secured tier carries its audience", () => {
    expect(classify("/api/orders", policy)).toEqual({ tier: "secured", audience: ["site-readers"] });
  });
  it("unmatched path falls to default_tier with no audience", () => {
    expect(classify("/totally/new/route", policy)).toEqual({ tier: "protected", audience: undefined });
  });
});

describe("isAuthorized", () => {
  it("no audience required → any authenticated session passes", () => {
    expect(isAuthorized({ groups: [] }, undefined)).toBe(true);
    expect(isAuthorized({ groups: ["x"] }, [])).toBe(true);
  });
  it("group intersection decides authorization", () => {
    expect(isAuthorized({ groups: ["site-readers"] }, ["site-readers"])).toBe(true);
    expect(isAuthorized({ groups: ["other"] }, ["site-readers"])).toBe(false);
    expect(isAuthorized({}, ["site-readers"])).toBe(false);
  });
});
```

- [ ] **Step 2: Run to verify it fails** — `npm test -- policy` → FAIL (module missing).

- [ ] **Step 3: Implement**

```js
/**
 * @typedef {Object} Config — see config.js loadConfig() for the full shape.
 */

/**
 * Resolve a request path to its tier and (optional) required audience using the
 * most-specific matching rule. "Most specific" = the rule whose pattern has the
 * longest literal prefix before any `*`; an exact (wildcard-free) pattern always
 * wins over a glob. Unmatched paths fall to `policy.default_tier`.
 * @returns {{ tier: string, audience: (string[]|undefined) }}
 */
export function classify(pathname, policy) {
  const matches = (policy.rules || []).filter((r) => matchGlob(r.path, pathname));
  if (matches.length === 0) return { tier: policy.default_tier, audience: undefined };
  matches.sort((a, b) => specificity(b.path) - specificity(a.path));
  const best = matches[0];
  return { tier: best.tier, audience: best.audience };
}

/** Authenticated-session authorization: empty/absent audience = any session OK. */
export function isAuthorized(session, audience) {
  if (!audience || audience.length === 0) return true;
  const groups = Array.isArray(session.groups) ? session.groups : [];
  return audience.some((a) => groups.includes(a));
}

function specificity(pattern) {
  const star = pattern.indexOf("*");
  if (star === -1) return 1000 + pattern.length;   // exact patterns rank above any glob
  return pattern.slice(0, star).length;            // else longest literal prefix wins
}

function matchGlob(pattern, path) {
  const re = new RegExp("^" + pattern.split("*").map(escapeRe).join(".*") + "$");
  return re.test(path);
}

function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
```

- [ ] **Step 4: Run to verify it passes** — `npm test -- policy` → PASS (7 tests).
- [ ] **Step 5: Commit** — `git commit -am "feat: three-tier path policy matcher + audience authz"`

---

## Task 8: `jwt.js` (port + close the conformance gaps)

Covers **N1, N2, N3, N4, N4b (azp), N5, N6, N7, N11**. This is the part the review
flagged as *not* a verbatim port: the sibling lacks `c_hash`/`at_hash`, the multi-`aud`
`azp` rule, and refetch-JWKS-once on `kid` miss. Add all three here, test-first.

**Files:**
- Create: `oidc-worker-gate/src/jwt.js`
- Test: `oidc-worker-gate/test/jwt.test.js`

- [ ] **Step 1: Write the failing test** (drives the whole N-matrix for token validation)

```js
import { describe, it, expect, beforeEach } from "vitest";
import { env } from "cloudflare:test";
import { verifyIdToken } from "../src/jwt.js";
import { createMockOp } from "./mock-op.js";
import { signJwt, seedDiscovery, tokenHash, makeRsaKey } from "./helpers.js";

let op, config;

async function tokenFromMock(opts) {
  // Register a code and run the OP's token endpoint to get a realistic id_token.
  return op.mintIdToken(opts);
}

beforeEach(async () => {
  op = await createMockOp();
  config = { issuer: op.discovery.issuer, clientId: "test-client", kv: env.OIDC_CACHE };
  await seedDiscovery(config.issuer, op.discovery, op.jwks);
  // Route the worker's discovery/JWKS fetches to the mock OP.
  globalThis.fetch = (input, init) => op.handle(new Request(input, init));
});

describe("verifyIdToken — happy path", () => {
  it("accepts a valid token and returns claims", async () => {
    const t = await tokenFromMock({ nonce: "n1" });
    const claims = await verifyIdToken(t, config, "n1");
    expect(claims.sub).toBe("user-123");
    expect(claims.groups).toEqual(["site-readers"]);
  });
  it("validates at_hash/c_hash when present (N11 positive)", async () => {
    const t = await tokenFromMock({ nonce: "n1", accessToken: "atk", code: "code-1" });
    const claims = await verifyIdToken(t, config, "n1", { accessToken: "atk", code: "code-1" });
    expect(claims.sub).toBe("user-123");
  });
});

describe("verifyIdToken — negative matrix", () => {
  it("N1 invalid signature", async () => {
    await expect(verifyIdToken(await tokenFromMock({ nonce: "n1", broken: "bad-sig" }), config, "n1"))
      .rejects.toThrow(/signature/);
  });
  it("N2 alg:none", async () => {
    await expect(verifyIdToken(await tokenFromMock({ nonce: "n1", broken: "alg-none" }), config, "n1"))
      .rejects.toThrow(/alg/);
  });
  it("N3 wrong iss", async () => {
    await expect(verifyIdToken(await tokenFromMock({ nonce: "n1", broken: "wrong-iss" }), config, "n1"))
      .rejects.toThrow(/iss/);
  });
  it("N4 wrong aud", async () => {
    await expect(verifyIdToken(await tokenFromMock({ nonce: "n1", broken: "wrong-aud" }), config, "n1"))
      .rejects.toThrow(/aud/);
  });
  it("N4b multi-aud without azp", async () => {
    await expect(verifyIdToken(await tokenFromMock({ nonce: "n1", broken: "multi-aud-no-azp" }), config, "n1"))
      .rejects.toThrow(/azp/);
  });
  it("N5 expired", async () => {
    await expect(verifyIdToken(await tokenFromMock({ nonce: "n1", broken: "expired" }), config, "n1"))
      .rejects.toThrow(/expired/);
  });
  it("N6 nonce mismatch", async () => {
    await expect(verifyIdToken(await tokenFromMock({ nonce: "n1", broken: "bad-nonce" }), config, "n1"))
      .rejects.toThrow(/nonce/);
  });
  it("N11 at_hash mismatch", async () => {
    const t = await tokenFromMock({ nonce: "n1", accessToken: "atk", code: "code-1", broken: "bad-at-hash" });
    await expect(verifyIdToken(t, config, "n1", { accessToken: "atk", code: "code-1" }))
      .rejects.toThrow(/at_hash/);
  });
});

describe("verifyIdToken — N7 kid rotation (refetch JWKS exactly once)", () => {
  // The cache (seeded in beforeEach) holds only the original "test-key-1". A fetch spy
  // counts live /jwks hits to prove the refetch happens EXACTLY once — an implementation
  // that loops would fail the count assertion even though the resolve/reject is correct.
  function spyJwks() {
    let n = 0;
    globalThis.fetch = (input, init) => {
      const r = new Request(input, init);
      if (new URL(r.url).pathname === "/jwks") n++;
      return op.handle(r);
    };
    return () => n;
  }

  it("refetches once and accepts a key present only in the FRESH JWKS", async () => {
    const rotated = await makeRsaKey("key-B");
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { alg: "RS256", kid: "key-B", typ: "JWT" },
      { iss: config.issuer, aud: "test-client", sub: "user-123", groups: ["site-readers"],
        iat: now, exp: now + 3600, nonce: "n1" },
      rotated.privateKey,
    );
    op.jwks.keys = [op.key.publicJwk, rotated.publicJwk]; // live JWKS rotated; cache still stale
    const count = spyJwks();
    const claims = await verifyIdToken(token, config, "n1");
    expect(claims.sub).toBe("user-123");
    expect(count()).toBe(1); // exactly one forced refetch
  });

  it("refetches once then rejects a kid present NOWHERE", async () => {
    const ghost = await makeRsaKey("ghost-key");
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { alg: "RS256", kid: "ghost-key", typ: "JWT" },
      { iss: config.issuer, aud: "test-client", sub: "x", iat: now, exp: now + 3600, nonce: "n1" },
      ghost.privateKey,
    );
    const count = spyJwks(); // live JWKS unchanged → ghost-key absent everywhere
    await expect(verifyIdToken(token, config, "n1")).rejects.toThrow(/no JWKS key/);
    expect(count()).toBe(1); // refetched exactly once before giving up — not a loop
  });
});
```

- [ ] **Step 2: Run to verify it fails** — `npm test -- jwt` → FAIL (module missing).

- [ ] **Step 3: Implement (port + the three gap closures)**

```js
import { base64UrlDecode, decodeJsonSegment, base64UrlEncode, utf8, timingSafeEqual } from "./encoding.js";

const CACHE_TTL_SECONDS = 3600;

export async function getDiscovery(config) {
  return cachedJson(config.kv, `discovery:${config.issuer}`, async () => {
    const res = await fetch(`${config.issuer}/.well-known/openid-configuration`);
    if (!res.ok) throw new Error(`discovery fetch failed: ${res.status}`);
    return res.json();
  });
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
  if (claims.iss !== config.issuer) throw new Error("iss mismatch");                 // N3
  if (!audienceMatches(claims.aud, config.clientId)) throw new Error("aud mismatch"); // N4
  if (claims.azp !== undefined && claims.azp !== config.clientId) throw new Error("azp mismatch"); // if present, must match
  if (Array.isArray(claims.aud) && claims.aud.length > 1 && claims.azp !== config.clientId)
    throw new Error("azp required for multi-valued aud");                            // N4b
  if (typeof claims.exp !== "number" || claims.exp + skew < now) throw new Error("token expired"); // N5 — exp is REQUIRED
  if (typeof claims.nbf === "number" && claims.nbf - skew > now) throw new Error("token not yet valid");
  if (typeof claims.iat === "number" && claims.iat - skew > now) throw new Error("token iat in the future");
  if (expectedNonce && claims.nonce !== expectedNonce) throw new Error("nonce mismatch"); // N6

  // --- c_hash / at_hash when the corresponding artifact is present (N11) — constant-time ---
  if (hashes.code && claims.c_hash && !timingSafeEqual(claims.c_hash, await leftHalfHash(hashes.code)))
    throw new Error("c_hash mismatch");
  if (hashes.accessToken && claims.at_hash && !timingSafeEqual(claims.at_hash, await leftHalfHash(hashes.accessToken)))
    throw new Error("at_hash mismatch");

  return claims;
}

async function importSigningKey(config, jwksUri, kid) {
  let jwks = await getJwks(config, jwksUri);
  let jwk = jwks.keys.find((k) => k.kid === kid && k.kty === "RSA");
  if (!jwk) {                                  // kid miss → refetch JWKS exactly once
    jwks = await getJwks(config, jwksUri, { force: true });
    jwk = jwks.keys.find((k) => k.kid === kid && k.kty === "RSA");
  }
  if (!jwk) throw new Error(`no JWKS key for kid ${kid}`);
  return crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
}

function audienceMatches(aud, clientId) {
  return Array.isArray(aud) ? aud.includes(clientId) : aud === clientId;
}

/** OIDC hash claim: base64url(left-128-bits(SHA-256(ascii(value)))). */
async function leftHalfHash(value) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(value)));
  return base64UrlEncode(digest.slice(0, digest.length / 2));
}

/** KV-backed JSON cache. `force` bypasses the read (used for kid-rotation refetch). */
async function cachedJson(kv, key, fetcher, { force = false } = {}) {
  if (kv && !force) {
    const hit = await kv.get(key, "json");
    if (hit && hit.expires > Date.now()) return hit.value;
  }
  const value = await fetcher();
  if (kv) {
    await kv.put(key, JSON.stringify({ value, expires: Date.now() + CACHE_TTL_SECONDS * 1000 }),
      { expirationTtl: CACHE_TTL_SECONDS });
  }
  return value;
}
```

- [ ] **Step 4: Run to verify it passes** — `npm test -- jwt` → PASS (all happy + N1–N7, N11).
- [ ] **Step 5: Commit** — `git commit -am "feat: id_token validation + close N-matrix gaps (azp, c/at_hash, kid refetch)"`

---

## Task 9: `oidc.js` (port — login / callback / logout)

Covers **N8 (state mismatch), N9 (replayed state), N10 (PKCE mismatch), N12 (OP error),
N13 (open redirect)** plus **P2 (valid callback), P6 (logout)**. Callback failures return
**`400`/`401` with an error body**, never a silent re-302 (so rejection is observable).

**Files:**
- Create: `oidc-worker-gate/src/oidc.js`
- Test: `oidc-worker-gate/test/oidc.test.js`

- [ ] **Step 1: Write the failing test**

```js
import { describe, it, expect, beforeEach } from "vitest";
import { env } from "cloudflare:test";
import { OidcClient } from "../src/oidc.js";
import { readStateCookie, SESSION_COOKIE } from "../src/session.js";
import { createMockOp } from "./mock-op.js";
import { seedDiscovery, reqFor, getSetCookie } from "./helpers.js";

let op, config, oidc;

beforeEach(async () => {
  op = await createMockOp();
  config = {
    issuer: op.discovery.issuer, clientId: "test-client", clientSecret: "test-client-secret",
    redirectUri: "https://www.example.com/.auth/callback",
    scopes: "openid profile email groups", sessionTtlSeconds: 3600,
    sessionKey: "test-hmac-key-at-least-32-bytes-long!!", kv: env.OIDC_CACHE,
  };
  await seedDiscovery(config.issuer, op.discovery, op.jwks);
  globalThis.fetch = (input, init) => op.handle(new Request(input, init));
  oidc = new OidcClient(config);
});

/** Run startLogin from `startPath`, then drive a callback with whatever we choose. */
async function startThenCallback({ startPath = "/members/x", tamperState = false, brokenToken,
                                   errorParam, dropCode = false, wrongPkce = false } = {}) {
  const start = await oidc.startLogin(reqFor(startPath), new URL(`https://www.example.com${startPath}`));
  const loginCookie = getSetCookie(start, "__gate_login");
  const saved = await readStateCookie(reqFor("/.auth/callback", { cookie: `__gate_login=${loginCookie}` }), config);
  const authUrl = new URL(start.headers.get("location"));
  const code = "code-1";
  // Register the code at the OP. With wrongPkce, register a challenge the real verifier
  // can't satisfy, so the OP's /token returns invalid_grant (N10).
  op.issueCode(code, {
    claims: { nonce: saved.nonce }, accessToken: "atk",
    codeChallenge: wrongPkce ? "a-challenge-the-verifier-cannot-match" : authUrl.searchParams.get("code_challenge"),
  });
  if (brokenToken) op.setBrokenForCode(code, brokenToken);
  const cbUrl = new URL("https://www.example.com/.auth/callback");
  cbUrl.searchParams.set("state", tamperState ? "WRONG" : saved.state);
  if (errorParam) cbUrl.searchParams.set("error", errorParam);
  else if (!dropCode) cbUrl.searchParams.set("code", code);
  const cbReq = reqFor(cbUrl.pathname + cbUrl.search, { cookie: `__gate_login=${loginCookie}` });
  return { start, saved, loginCookie, res: await oidc.handleCallback(cbReq, cbUrl) };
}

describe("startLogin (P1 building block)", () => {
  it("302s to authorize with state+nonce+PKCE and sets the login cookie", async () => {
    const res = await oidc.startLogin(reqFor("/members/x"), new URL("https://www.example.com/members/x"));
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("location"));
    expect(loc.searchParams.get("response_type")).toBe("code");
    expect(loc.searchParams.get("state")).toBeTruthy();
    expect(loc.searchParams.get("nonce")).toBeTruthy();
    expect(loc.searchParams.get("code_challenge_method")).toBe("S256");
    expect(getSetCookie(res, "__gate_login")).toBeTruthy();
  });
});

describe("handleCallback", () => {
  it("P2 valid callback mints a session and 302s back to returnTo", async () => {
    const { res } = await startThenCallback();
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/members/x");
    expect(getSetCookie(res, SESSION_COOKIE)).toBeTruthy();
  });
  it("N8 state mismatch → 400, no session", async () => {
    const { res } = await startThenCallback({ tamperState: true });
    expect(res.status).toBe(400);
    expect(getSetCookie(res, SESSION_COOKIE)).toBeNull();
  });
  it("N12 OP error callback → handled, no session, no 500", async () => {
    const { res } = await startThenCallback({ errorParam: "access_denied" });
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
    expect(getSetCookie(res, SESSION_COOKIE)).toBeNull();
  });
  it("missing code → 400", async () => {
    const { res } = await startThenCallback({ dropCode: true });
    expect(res.status).toBe(400);
  });
  it("N10 wrong PKCE verifier → OP rejects, RP surfaces 401, no session", async () => {
    const { res } = await startThenCallback({ wrongPkce: true });
    expect(res.status).toBe(401);
    expect(getSetCookie(res, SESSION_COOKIE)).toBeNull();
  });
  it("N13 protocol-relative returnTo is sanitized to '/' (no open redirect)", async () => {
    // Login from a path that yields a protocol-relative returnTo ("//evil.com").
    const { res } = await startThenCallback({ startPath: "//evil.com" });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/"); // NOT //evil.com
  });
  it("N9 replayed callback (consumed state) → 400, no second session", async () => {
    // Build one callback, submit it twice with the same login cookie + state + code.
    const start = await oidc.startLogin(reqFor("/members/x"), new URL("https://www.example.com/members/x"));
    const loginCookie = getSetCookie(start, "__gate_login");
    const saved = await readStateCookie(reqFor("/.auth/callback", { cookie: `__gate_login=${loginCookie}` }), config);
    const authUrl = new URL(start.headers.get("location"));
    op.issueCode("code-1", { claims: { nonce: saved.nonce }, accessToken: "atk",
      codeChallenge: authUrl.searchParams.get("code_challenge") });
    const cbUrl = new URL("https://www.example.com/.auth/callback");
    cbUrl.searchParams.set("state", saved.state);
    cbUrl.searchParams.set("code", "code-1");
    const mk = () => reqFor(cbUrl.pathname + cbUrl.search, { cookie: `__gate_login=${loginCookie}` });
    const first = await oidc.handleCallback(mk(), cbUrl);
    expect(first.status).toBe(302);
    expect(getSetCookie(first, SESSION_COOKIE)).toBeTruthy();
    const second = await oidc.handleCallback(mk(), cbUrl);
    expect(second.status).toBe(400);
    expect(getSetCookie(second, SESSION_COOKIE)).toBeNull();
  });
});

describe("handleLogout (P6)", () => {
  it("clears the session and redirects to end_session_endpoint", async () => {
    const res = await oidc.handleLogout(reqFor("/.auth/logout"), new URL("https://www.example.com/.auth/logout"));
    expect(res.status).toBe(302);
    expect(getSetCookie(res, SESSION_COOKIE)).toBe("");
    expect(res.headers.get("location")).toContain(op.discovery.end_session_endpoint);
  });
});
```

> N9 and N10 are now explicit cases above. N10 relies on the mock OP's `/token` returning
> `invalid_grant` for a `code_verifier` that doesn't match the registered challenge. N9
> relies on the **single-use state marker** added to `handleCallback` in Step 3 — without
> it, replaying the same callback URL + login cookie would re-mint a session.

- [ ] **Step 2: Run to verify it fails** — `npm test -- oidc` → FAIL (module missing).

- [ ] **Step 3: Implement (port; drop Fastly `backend`, keep client_secret_post; pass hashes to verify)**

```js
import { getDiscovery, verifyIdToken } from "./jwt.js";
import { createPkcePair, randomNonce, randomState } from "./pkce.js";
import { clearSessionCookie, clearStateCookie, mintSessionCookie, mintStateCookie, readStateCookie } from "./session.js";
import { timingSafeEqual } from "./encoding.js";

export class OidcClient {
  constructor(config) { this.config = config; }

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

  async handleCallback(req, url) {
    const saved = await readStateCookie(req, this.config);
    if (!saved) return errorResponse(400, "Login session expired — please retry.");

    const returnedState = url.searchParams.get("state") || "";
    if (!timingSafeEqual(returnedState, saved.state)) return errorResponse(400, "State mismatch — possible CSRF.");

    // Single-use state: reject a replayed callback (N9). Best-effort via KV — CF KV is
    // eventually consistent, so this stops practical replays, not a perfectly-timed race.
    // Marked consumed once the state is validated; a later token-exchange failure still
    // burns the state (user re-initiates login), which is the safe direction.
    if (this.config.kv) {
      const usedKey = `state-used:${saved.state}`;
      if (await this.config.kv.get(usedKey)) return errorResponse(400, "State already used — possible replay.");
      await this.config.kv.put(usedKey, "1", { expirationTtl: 600 });
    }

    const idpError = url.searchParams.get("error");
    if (idpError) return errorResponse(401, `Authorization failed: ${idpError}`);

    const code = url.searchParams.get("code");
    if (!code) return errorResponse(400, "Missing authorization code.");

    const discovery = await getDiscovery(this.config);
    const body = new URLSearchParams({
      grant_type: "authorization_code", code, redirect_uri: this.config.redirectUri,
      client_id: this.config.clientId, client_secret: this.config.clientSecret, code_verifier: saved.verifier,
    });
    const tokenRes = await fetch(discovery.token_endpoint, {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: body.toString(),
    });
    if (!tokenRes.ok) return errorResponse(401, `Token exchange failed: ${tokenRes.status}`);

    const tokens = await tokenRes.json();
    if (!tokens.id_token) return errorResponse(401, "No id_token in token response.");

    let claims;
    try {
      claims = await verifyIdToken(tokens.id_token, this.config, saved.nonce,
        { code, accessToken: tokens.access_token });
    } catch (e) {
      return errorResponse(400, `ID token validation failed: ${e.message}`);
    }

    const sessionCookie = await mintSessionCookie(claims, this.config);
    const headers = new Headers({ location: safeReturnTo(saved.returnTo, url.origin) });
    headers.append("set-cookie", sessionCookie);
    headers.append("set-cookie", clearStateCookie());
    return new Response(null, { status: 302, headers });
  }

  async handleLogout(req, url) {
    const discovery = await getDiscovery(this.config).catch(() => ({}));
    const headers = new Headers();
    headers.append("set-cookie", clearSessionCookie());
    if (discovery.end_session_endpoint) {
      const logout = new URL(discovery.end_session_endpoint);
      logout.searchParams.set("client_id", this.config.clientId);
      logout.searchParams.set("post_logout_redirect_uri", `${url.origin}/`);
      headers.set("location", logout.toString());
      return new Response(null, { status: 302, headers });
    }
    headers.set("location", "/");
    return new Response(null, { status: 302, headers });
  }
}

function safeReturnTo(returnTo, origin) {
  if (typeof returnTo !== "string" || !returnTo.startsWith("/")) return "/";
  try {
    const resolved = new URL(returnTo, origin);          // catches //evil.com and /\evil.com
    if (resolved.origin !== origin) return "/";
    return resolved.pathname + resolved.search;
  } catch {
    return "/";
  }
}

function errorResponse(status, message) {
  return new Response(`${status} — ${message}\n`, { status, headers: { "content-type": "text/plain; charset=utf-8" } });
}
```

> **Conformance note (N7→callback):** the sibling returns `401` on id_token validation
> failure; this plan changes that to **`400`** to match
> [`conformance-testing.md`](./conformance-testing.md)'s "callback failure must be
> observable as a distinct 400, not a re-302." Keep the 400.

- [ ] **Step 4: Run to verify it passes** — `npm test -- oidc` → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat: OIDC RP login/callback/logout (400 on callback failure)"`

---

## Task 10: `origin.js` (new — EDS forwarding + caching carve-out)

Covers **P3 (forward with `x-auth-*`, cookie stripped)** and the **caching carve-out**
(protected/secured responses must never be edge-cacheable).

**Files:**
- Create: `oidc-worker-gate/src/origin.js`
- Test: `oidc-worker-gate/test/origin.test.js`

- [ ] **Step 1: Write the failing test**

```js
import { describe, it, expect, beforeEach } from "vitest";
import { forwardToOrigin } from "../src/origin.js";
import { reqFor } from "./helpers.js";

let seen; // capture what the worker sent to origin
const config = {
  originHostname: "main--mysite--myorg.aem.live",
  forwardedHost: "www.example.com",
  pushInvalidation: true,
};

beforeEach(() => {
  seen = null;
  globalThis.fetch = async (input, init) => {
    const r = input instanceof Request ? input : new Request(input, init);
    seen = { url: r.url, headers: r.headers };
    // Origin replies with a publicly-cacheable header to test the carve-out.
    return new Response("body", { headers: { "cache-control": "public, max-age=3600", "age": "120" } });
  };
});

describe("forwardToOrigin", () => {
  it("P3 forwards to the EDS origin with x-auth-* and strips the cookie", async () => {
    const session = { sub: "user-123", email: "u@example.com", groups: ["site-readers"] };
    await forwardToOrigin(reqFor("/members/x", { cookie: "__gate_session=abc" }), session, "protected", config);
    expect(new URL(seen.url).hostname).toBe("main--mysite--myorg.aem.live");
    expect(seen.headers.get("cookie")).toBeNull();
    expect(seen.headers.get("x-auth-subject")).toBe("user-123");
    expect(seen.headers.get("x-auth-email")).toBe("u@example.com");
    expect(seen.headers.get("x-auth-groups")).toBe("site-readers");
    expect(seen.headers.get("x-forwarded-host")).toBe("www.example.com");
    expect(seen.headers.get("x-push-invalidation")).toBe("enabled");
  });

  it("protected/secured responses are rewritten to private, no-store", async () => {
    const res = await forwardToOrigin(reqFor("/api/orders"), { sub: "x", groups: [] }, "secured", config);
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    expect(res.headers.get("age")).toBeNull();
  });

  it("public responses preserve origin caching and inject no identity", async () => {
    const res = await forwardToOrigin(reqFor("/blog/post"), null, "public", config);
    expect(res.headers.get("cache-control")).toBe("public, max-age=3600");
    expect(seen.headers.get("x-auth-subject")).toBeNull();
  });
});
```

- [ ] **Step 2: Run to verify it fails** — `npm test -- origin` → FAIL (module missing).

- [ ] **Step 3: Implement**

```js
/**
 * Forward a request to the EDS origin per AEM BYO-CDN rules. For protected/secured
 * tiers, disable edge caching and rewrite the response so per-user content can never
 * be stored or cross-served. Public responses pass through with origin caching intact.
 * @param {Request} request
 * @param {object|null} session  null for the public tier
 * @param {string} tier          "public" | "protected" | "secured"
 * @param {import("./policy.js").Config} config
 */
export async function forwardToOrigin(request, session, tier, config) {
  const inUrl = new URL(request.url);
  const originUrl = `https://${config.originHostname}${inUrl.pathname}${inUrl.search}`;

  const headers = new Headers(request.headers);
  headers.delete("cookie"); // never leak the gate session to origin
  // Strip any client-supplied trusted headers so a caller can't spoof identity to the
  // origin (critical on the public tier, where no session block overwrites them).
  for (const name of [...headers.keys()]) {
    if (name.toLowerCase().startsWith("x-auth-")) headers.delete(name);
  }
  headers.delete("x-push-invalidation");
  headers.set("host", config.originHostname);
  headers.set("x-forwarded-host", config.forwardedHost);
  if (config.pushInvalidation) headers.set("x-push-invalidation", "enabled");

  if (session) {
    headers.set("x-auth-subject", session.sub || "");
    headers.set("x-auth-email", session.email || "");
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
  if (!cacheOff) return res;

  const out = new Response(res.body, res);
  out.headers.set("cache-control", "private, no-store");
  out.headers.delete("age");
  return out;
}
```

- [ ] **Step 4: Run to verify it passes** — `npm test -- origin` → PASS (3 tests).
- [ ] **Step 5: Commit** — `git commit -am "feat: EDS origin forwarding + protected/secured cache carve-out"`

---

## Task 11: `index.js` + end-to-end gate test

Wires everything together and proves the three unauthenticated behaviors end-to-end:
**P1 (protected→302), P4 (public→forward), P5 (secured+session→forward), P7 (authorized),
N14 (secured no session→401 JSON), N15 (authenticated but wrong audience→403).**

**Files:**
- Create: `oidc-worker-gate/src/index.js`
- Test: `oidc-worker-gate/test/gate.test.js`

- [ ] **Step 1: Write the failing test** (drives the deployed worker via `SELF.fetch`)

```js
import { describe, it, expect, beforeEach } from "vitest";
import { env, SELF } from "cloudflare:test";
import { createMockOp } from "./mock-op.js";
import { mintSessionCookie } from "../src/session.js";
import { seedDiscovery } from "./helpers.js";

const config = { sessionKey: "test-hmac-key-at-least-32-bytes-long!!", sessionTtlSeconds: 3600 };

async function sessionCookie(groups) {
  const sc = await mintSessionCookie({ sub: "user-123", email: "u@example.com", groups }, config);
  return sc.match(/__gate_session=([^;]*)/)[1];
}

beforeEach(async () => {
  // Seed discovery/JWKS so startLogin (P1) builds the authorize URL without a live OP call.
  // The worker's origin forward is stubbed by the outboundService in vitest.config.js.
  const op = await createMockOp();
  await seedDiscovery(op.discovery.issuer, op.discovery, op.jwks);
});

describe("gate end-to-end", () => {
  it("P4 public path forwards without auth", async () => {
    const res = await SELF.fetch("https://www.example.com/blog/post");
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("origin-body");
  });
  it("P1 protected path with no session → 302 to IdP", async () => {
    const res = await SELF.fetch("https://www.example.com/members/x", { redirect: "manual" });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain("/authorize");
  });
  it("N14 secured path with no session → 401 JSON, no redirect", async () => {
    const res = await SELF.fetch("https://www.example.com/api/orders");
    expect(res.status).toBe(401);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(res.headers.get("location")).toBeNull();
  });
  it("P5/P7 secured path with authorized session → forward", async () => {
    const cookie = `__gate_session=${await sessionCookie(["site-readers"])}`;
    const res = await SELF.fetch("https://www.example.com/api/orders", { headers: { cookie } });
    expect(res.status).toBe(200);
  });
  it("N15 authenticated but wrong audience → 403", async () => {
    const cookie = `__gate_session=${await sessionCookie(["other-group"])}`;
    const res = await SELF.fetch("https://www.example.com/members/x", { headers: { cookie } });
    expect(res.status).toBe(403);
  });
});
```

> **Why no `globalThis.fetch` override here:** under `SELF`, the worker runs in the runtime
> and its outbound subrequests do **not** go through the test realm's `globalThis.fetch` —
> they go through Miniflare's `outboundService`, which is configured in `vitest.config.js`
> (Task 1) to stub the EDS origin. That's why the origin stub lives in config, not in this
> `beforeEach`. (Module-level tests like `jwt.test.js` call functions directly in the test
> realm, so *they* override `globalThis.fetch` — different mechanism, same idea.)

- [ ] **Step 2: Run to verify it fails** — `npm test -- gate` → FAIL (no `src/index.js` default export).

- [ ] **Step 3: Implement the worker entry**

```js
import { loadConfig } from "./config.js";
import { OidcClient } from "./oidc.js";
import { readSession } from "./session.js";
import { classify, isAuthorized } from "./policy.js";
import { forwardToOrigin } from "./origin.js";

export default {
  /**
   * @param {Request} request
   * @param {Record<string, any>} env
   */
  async fetch(request, env) {
    const url = new URL(request.url);
    const config = loadConfig(env);
    const oidc = new OidcClient(config);

    // Gate-owned routes first.
    if (url.pathname === config.routes.callback) return oidc.handleCallback(request, url);
    if (url.pathname === config.routes.logout) return oidc.handleLogout(request, url);

    const { tier, audience } = classify(url.pathname, config.policy);

    // public: forward before touching the cookie.
    if (tier === "public") return forwardToOrigin(request, null, "public", config);

    // protected / secured: validate the local session.
    const session = await readSession(request, config);
    if (!session) {
      return tier === "secured" ? unauthorizedJson() : oidc.startLogin(request, url);
    }
    if (!isAuthorized(session, audience)) return forbidden();

    return forwardToOrigin(request, session, tier, config);
  },
};

function unauthorizedJson() {
  return new Response(JSON.stringify({ error: "unauthorized" }), {
    status: 401,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "private, no-store" },
  });
}

function forbidden() {
  return new Response(JSON.stringify({ error: "forbidden" }), {
    status: 403,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "private, no-store" },
  });
}
```

- [ ] **Step 4: Run the full suite** — `npm test`
Expected: **all** files green — `encoding`, `cookies`, `pkce`, `session`, `config`,
`policy`, `jwt` (N1–N7, N11, azp), `oidc` (N8, N12, N13, P2, P6), `origin` (P3 + carve-out),
`gate` (P1, P4, P5, P7, N14, N15). This green suite is Phase 1's definition of done.

- [ ] **Step 5: Commit** — `git commit -am "feat: worker entry — three-tier classify + dispatch (Phase 1 complete)"`

---

## Task 12: CI gate

**Files:**
- Create: `.github/workflows/oidc-worker-gate-ci.yml` (or add a job to the repo's existing workflow)

- [ ] **Step 1: Add the workflow**

```yaml
name: oidc-worker-gate CI
on:
  pull_request:
    paths: ["oidc-worker-gate/**"]
  push:
    branches: [main]
    paths: ["oidc-worker-gate/**"]
jobs:
  test:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: oidc-worker-gate
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
      - run: npm ci
      - run: npm test
```

> **`npm ci` needs the lockfile.** Commit `oidc-worker-gate/package-lock.json` (Task 1
> generates it on `npm install` but its commit step doesn't stage it). Without the lockfile
> in the repo, the CI `npm ci` step fails. Stage both here.

- [ ] **Step 2: Commit** — stage `.github/workflows/oidc-worker-gate-ci.yml` and
  `oidc-worker-gate/package-lock.json`, then
  `git commit -m "ci: gate oidc-worker-gate on the mock-OP conformance suite"`

The CI job failing on any P/N regression is the enforcement of "test passing = done."

---

## Definition of done (Phase 1)

- [ ] `npm test` is green: every module test **and** the end-to-end gate test.
- [ ] The negative matrix fails closed — each of **N1, N2, N3, N4, N4b, N5, N6, N7, N8,
      N9, N10, N11, N12, N13, N14, N15** has a green test and none mints a session
      (N15 is the authenticated-but-wrong-audience 403). Every P-case (P1–P7) is green too.
- [ ] No `nodejs_compat`; no runtime npm dependencies (Web Crypto only).
- [ ] `wrangler dev` boots and a public path forwards to a real EDS origin (manual check
      against `ORIGIN_HOSTNAME`).
- [ ] CI runs the suite on every PR touching `oidc-worker-gate/**`.

**Explicitly out of scope (Phase 2–3):** Adobe IMS `/ims/profile/v1` entitlement fetch,
DA-sourced KV ACL + control-plane push, User Management API group lookup, refresh tokens,
`jti`/`sub` denylist. Do not build these in Phase 1.

---

## Self-review (run against `conformance-testing.md` + `README.md`)

**Spec coverage — every P/N case maps to a task:**

| Spec row | Task |
| --- | --- |
| P1 protected→302 | 9 (startLogin) + 11 (gate) |
| P2 valid callback | 9 |
| P3 forward + x-auth-* + cookie strip | 10 |
| P4 public→forward | 11 |
| P5 secured+session→forward | 11 |
| P6 logout | 9 |
| P7 authorized | 7 (isAuthorized) + 11 |
| N1 bad signature | 8 |
| N2 alg:none | 8 |
| N3 wrong iss | 8 |
| N4 wrong aud | 8 |
| N4b multi-aud/azp | 8 |
| N5 expired | 8 |
| N6 nonce | 8 |
| N7 kid refetch-once | 8 |
| N8 state mismatch | 9 |
| N9 replayed state | 9 (single-use KV marker) |
| N10 PKCE mismatch | 9 (OP returns invalid_grant) |
| N11 c_hash/at_hash | 8 |
| N12 OP error | 9 |
| N13 open redirect | 9 (safeReturnTo, protocol-relative) |
| N14 secured no session→401 | 11 |
| N15 wrong audience→403 | 7 + 11 |
| Caching carve-out | 10 |
| EDS Host/X-Forwarded-Host/push-inval | 10 |
| Observability x-auth-request-id | 10 |

**Type consistency check (locked names):** `loadConfig(env)→Config`; `classify(path,policy)
→{tier,audience}`; `isAuthorized(session,audience)`; `verifyIdToken(idToken,config,nonce,
{code,accessToken})`; `forwardToOrigin(request,session,tier,config)`; cookies
`__gate_session`/`__gate_login`; KV cache keys `discovery:<issuer>` / `jwks:<jwksUri>`
wrapping `{value,expires}`. These are identical everywhere they appear above.

**Gaps to watch during execution (not placeholders — known integration risks):**
- Origin forwards under `SELF` are stubbed by `outboundService` in `vitest.config.js` (the
  default). If a future gate case needs the worker to actually reach the mock OP (e.g. an
  end-to-end callback through `SELF`), extend `outboundService` to route OP paths to the
  mock too, rather than relying on a `globalThis.fetch` override (which `SELF` bypasses).
- N9's single-use marker is **best-effort** (CF KV is eventually consistent). The test
  passes because Miniflare KV is read-after-write consistent locally; in production a
  perfectly-timed concurrent replay across PoPs could slip through. If strict single-use is
  required, move the marker to a Durable Object — out of scope for Phase 1.
