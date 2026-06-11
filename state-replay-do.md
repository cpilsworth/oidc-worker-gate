# Strict single-use `state` via Durable Objects

Design for closing the **N9 state-replay race** in `oidc-worker-gate`. Today the callback
path marks OAuth `state` as consumed in **Worker KV**; that is good enough for sequential
replays but not strictly linearizable. This doc describes the problem, trade-offs, and a
**Durable Object (DO)**-based consume-once design.

Builds on [`README.md`](./README.md) (OIDC callback flow) and
[`conformance-testing.md`](./conformance-testing.md) (N9 in the negative matrix).

---

## Problem

During the authorization-code flow the worker:

1. Mints random `state` at login start and stores it in the signed `__gate_login` cookie.
2. Redirects the browser to the IdP.
3. On `/.auth/callback`, compares the returned `state` query param to the cookie value.
4. Exchanges the `code` for tokens and mints `__gate_session`.

**N9** requires that the same callback (same `state` + `code` + login cookie) cannot be
processed twice. A replay could otherwise mint a second session or amplify a stolen
callback URL.

### Current implementation (KV, best-effort)

```js
// src/oidc.js — simplified
const usedKey = `state-used:${saved.state}`;
if (await kv.get(usedKey)) return 400;
await kv.put(usedKey, "1", { expirationTtl: 600 });
```

### Why KV is insufficient for *strict* single-use

| Property | Worker KV | What N9 needs |
| --- | --- | --- |
| Consistency | Eventually consistent across PoPs | **Linearizable** read-modify-write |
| Atomicity | `get` then `put` is two ops | **Consume once** atomically |
| Optional today | Skipped if `OIDC_CACHE` unbound | Should fail closed in production |

**Sequential replay** is already mitigated in practice:

- Second callback sees `state-used:*` in KV (usually), **or**
- IdP rejects the reused authorization `code` (one-time credential).

**Concurrent replay** is the gap: two in-flight callbacks can both pass `kv.get()` before
either `kv.put()` is visible, especially across edge PoPs. The window is narrow but real.

The codebase and README already label this **best-effort**; Miniflare tests pass because
local KV behaves like read-after-write consistent storage, which production KV does not
guarantee for this pattern.

---

## Threat model

| Scenario | Risk without strict consume | Current mitigation |
| --- | --- | --- |
| User double-clicks callback / browser retries | Low — sequential | KV marker + IdP code reuse |
| Attacker replays captured callback URL quickly | Medium — depends on timing | KV + IdP code; race possible |
| Attacker replays concurrent duplicate requests | Medium — race window | IdP code only (if exchange is serial) |
| No KV binding in deployment | High — no worker-side N9 | IdP code only |

**Out of scope for this design:** stealing the `__gate_login` cookie before first use
(that is a broader session-fixation / XSS problem). This design only ensures **one successful
consume per `state` value** at the worker.

---

## Design goals

1. **Atomic consume-once** per `state` — no concurrent double-success.
2. **Fail closed** — if the consume store is unavailable, reject the callback (do not mint
   a session).
3. **Low hot-path cost** — callback is rare; a single DO RPC per login is acceptable.
4. **No cross-login contention** — logins for different users must not serialize on one lock.
5. **TTL hygiene** — consumed markers must expire (login state is short-lived; 10 min matches
   the login cookie).

Non-goals:

- Replacing the signed `__gate_login` cookie (still carries `nonce`, PKCE verifier, `returnTo`).
- Moving discovery/JWKS cache off KV (`OIDC_CACHE` stays KV).
- Solving refresh-token or `jti` denylist revocation (separate concern).

---

## Recommended solution: one Durable Object per `state`

Route each `state` value to its own DO instance via `idFromName(state)`. That object owns
exactly one consume decision for that login attempt.

```
startLogin                    handleCallback
    │                              │
    ├─ mint state (random)         ├─ read __gate_login cookie
    ├─ sign cookie                 ├─ verify state param == cookie
    └─ 302 → IdP                   │
                                   ├─ DO.consume(state)  ──▶  LoginState DO
                                   │       atomic: first OK, rest 409
                                   ├─ token exchange + id_token verify
                                   └─ mint __gate_session
```

### Why per-state DO (not one global DO)

| Approach | Pros | Cons |
| --- | --- | --- |
| **Global single DO** | Simple | Serializes *all* logins; hotspot |
| **Per-state DO** ✓ | Linearizable per login; parallel across users | One DO stub call per callback |
| **KV (current)** | Cheap, already bound | Not atomic / not linearizable |

### DO class sketch

```js
// src/login-state-do.js
export class LoginState {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    if (request.method !== "POST") return new Response("method not allowed", { status: 405 });

    const key = "consumed";
    if (await this.state.storage.get(key)) {
      return new Response(JSON.stringify({ consumed: true }), {
        status: 409,
        headers: { "content-type": "application/json" },
      });
    }

    // First consumer wins. TTL matches login cookie / state lifetime.
    await this.state.storage.put(key, 1, { expirationTtl: 600 });
    return new Response(JSON.stringify({ consumed: false }), {
      headers: { "content-type": "application/json" },
    });
  }
}
```

Storage inside a single DO is **strongly consistent** — concurrent `fetch` handlers for
the same object are processed serially, so the check-then-set is safe.

### Worker integration

```js
// src/oidc.js — replace KV block in handleCallback
async function consumeState(config, state) {
  const id = config.loginState.idFromName(state);
  const stub = config.loginState.get(id);
  const res = await stub.fetch("https://login-state/consume", { method: "POST" });
  return res.ok; // 409 → false
}

// after state param matches cookie:
if (!(await consumeState(this.config, saved.state))) {
  return errorResponse(400, "State already used — possible replay.");
}
```

`config.loginState` is a new binding — **separate from** `OIDC_CACHE`. Discovery/JWKS stay
on KV; only the consume-once marker moves to DO.

### When to consume

**Consume before token exchange** (recommended — matches current KV placement):

- Pro: attacker cannot hammer the IdP with replays after first attempt.
- Con: token-exchange failure still burns `state` (user must restart login — safe direction).

**Consume after successful token exchange**:

- Pro: better UX on transient IdP errors.
- Con: widens replay window; attacker can retry exchange until one succeeds.

Keep **consume-before-exchange** unless product explicitly prefers UX over stricter replay
bounds.

---

## Infrastructure

### `wrangler.toml` additions

```toml
[[durable_objects.bindings]]
name = "LOGIN_STATE"
class_name = "LoginState"

[[migrations]]
tag = "v1"
new_classes = ["LoginState"]
```

Worker export must include the DO class (Wrangler pattern):

```js
// src/index.js
export { LoginState } from "./login-state-do.js";
export default { fetch(request, env) { /* existing */ } };
```

### `config.js`

```js
loginState: env.LOGIN_STATE,  // required in production
```

**Fail closed:** if `LOGIN_STATE` is missing at callback time, return `500` or `400` with a
clear operator-facing reason — do not silently skip consume (today's KV path is optional).

### Cost / scale

- **One DO invocation per successful callback** (negligible vs human login rate).
- **One DO instance per login attempt** — short-lived; storage entry TTL 600s.
- No ongoing hot-path DO traffic (session validation stays local HMAC).

---

## Testing

### What Phase 1 tests prove today

| Test | What it shows | Production fidelity |
| --- | --- | --- |
| `N9 replayed callback` (sequential) | Second submit → 400 | Good |
| `N9 concurrent duplicate callbacks` | ≤1 session minted | **Optimistic** — Miniflare KV is consistent |

### What to add with DO

1. **Unit/integration:** mock `LOGIN_STATE` stub that simulates 409 on second consume.
2. **Concurrent:** `Promise.all([callback, callback])` — exactly one `302` + session cookie,
   one `400` state-already-used.
3. **Fail closed:** callback with `LOGIN_STATE` unset → error, no session.
4. **Optional:** vitest-pool-workers DO binding per Cloudflare docs (heavier setup).

Update [`conformance-testing.md`](./conformance-testing.md) N9 row to distinguish
**sequential** (CI today) vs **strict concurrent** (DO gate).

---

## Alternatives considered

| Option | Verdict |
| --- | --- |
| **KV `put` only (no get)** | Still eventually consistent; does not fix cross-PoP race |
| **D1 `INSERT` with unique key on `state`** | Atomic, but extra service + latency for a 10-minute ephemeral flag |
| **IdP one-time code only** | Necessary but not sufficient for worker-enforced N9; IdP may allow parallel exchange races |
| **Encrypt state into cookie, drop server store** | Doesn't prevent replay of the same cookie+URL bundle |
| **Global DO mutex** | Correct but unnecessary contention |

---

## Rollout / phasing

| Phase | Deliverable |
| --- | --- |
| **1 (current)** | KV best-effort; document limitation |
| **1.5 (this design)** | Add `LoginState` DO; require binding in production; keep KV for JWKS only |
| **2+** | No change to DO consume path unless adding multi-region custom semantics |

Implementation checklist:

- [ ] `src/login-state-do.js`
- [ ] `wrangler.toml` binding + migration
- [ ] `config.js` + fail-closed if unbound
- [ ] Replace KV `state-used:*` in `oidc.js`
- [ ] Tests (sequential + concurrent + missing binding)
- [ ] README Limitations — link here; remove "best-effort" once shipped

---

## Relationship to other docs

- [`README.md`](./README.md) — callback flow, security model, limitations.
- [`conformance-testing.md`](./conformance-testing.md) — N9 negative case.
- [`phase-1-plan.md`](./phase-1-plan.md) — implementation record; notes KV N9 is best-effort.
- [`folder-authorization.md`](./folder-authorization.md) — unrelated (Phase 3 authz); same
  "KV for cache, not for linearizable security" lesson applies.
