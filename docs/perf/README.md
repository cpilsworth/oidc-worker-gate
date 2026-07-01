# OIDC Worker Gate — Performance Report

_Generated 2026-06-30. Reproduce with `npm run bench -- --disable-console-intercept`._
_Raw data: [results.json](results.json). Harness: [`test/perf/`](../../test/perf), instrumentation: [`src/perf.js`](../../src/perf.js)._

## TL;DR

- **Worker CPU is ~40 µs/request = 0.08 % of Cloudflare's 50 ms CPU limit.**
  This is an assumption-free, measured-vs-platform-limit fact: there is no CPU
  scaling concern, now or at any plausible scale.
- **The bottleneck is the origin subrequest, not the worker.** Against a modeled
  35 ms origin, worker CPU is ~0.1 % of request wall-time. (This share rides on
  the origin-latency assumption — but it's robust: even at a 1 ms origin the
  worker is still only ~4 % of wall.)
- **Steady-state authorization makes zero KV reads and one origin fetch.** The
  in-isolate caches (policy snapshot, derived HMAC keys, compiled matchers) do
  their job: a warm isolate touches KV on *none* of the public/protected/secured
  paths. Weighted across traffic: **0.96 origin fetches and 0.026 KV reads per
  request**.
- **The only I/O-heavy path is the login callback** (~6 sequential KV ops + 1
  token-exchange fetch ≈ **~85 ms modeled wall**), and it's ~0.1 % of traffic and
  user-interactive. The headline crypto cost everyone worries about — RSA id_token
  verification — is just **~17 µs**.
- **Optimization guidance:** spend effort on the origin (edge caching, origin
  proximity/keep-alive), not on the worker. The one worth-doing worker change is
  an isolate-level cache for the OIDC discovery + JWKS documents (callback path).

---

## How this was measured

The benchmark runs **inside workerd** via `@cloudflare/vitest-pool-workers`, so
every number comes from the same V8 engine, **BoringSSL** crypto backend and
**miniflare KV** that production uses — not a Node.js approximation (Node's
OpenSSL crypto would mis-rank the crypto costs).

The worker's [`fetch`](../../src/index.js) handler is instrumented with a
zero-overhead tracer ([`src/perf.js`](../../src/perf.js)): production passes no
tracer and falls back to a frozen `NOOP` (empty methods, no clock reads). The
tracer marks phase boundaries and decomposes each phase into **on-CPU compute**
vs **off-CPU I/O wait**.

**Two measurement quirks shaped the method:**

1. **workerd coarsens `performance.now()` to ~1 ms** (a Spectre mitigation —
   the clock *advances* but is quantized). A single request's tens of microseconds
   are invisible at that resolution. So everything is measured by **amortisation**:
   run a unit of work N times in a tight loop, time the whole batch at ms
   resolution, divide. Mean precision is sub-microsecond.
2. **Local I/O is not representative.** miniflare KV and the stubbed origin
   resolve in ~200 µs locally; production KV/origin are network round-trips
   (milliseconds). So I/O is reported as a **deterministic op count** (KV reads,
   origin subrequests) and a production wall-time **model** multiplies those by
   assumed latencies. Counts are measured; latencies are assumptions (labelled).

Per-scenario worker CPU is measured in a **CPU-isolation batch**: the origin
subrequest is stubbed to resolve instantly, so the batch wall is the worker's own
compute with no network variance. (Caveat: this stub does not zero KV, so the
302/callback CPU figures still include local KV-read time — see notes below.)

Config: 4 000 iterations/scenario (400 for callback), 300-iteration warm-up,
serial (concurrency 1, so crypto on the libuv-equivalent threadpool isn't
contended). Modeled latencies: **origin = 35 ms, KV read = 8 ms**.

---

## Part 1 — Per-operation CPU cost (micro-benchmarks)

Pure on-CPU cost of each hot operation, amortised over 4k–100k calls.

| Operation | CPU (µs/op) | When it runs |
|---|--:|---|
| `loadConfig` | **1.88** | every request |
| `normalizePath` (`/styles/styles.css`) | 0.89 | every non-route request |
| `normalizePath` (`/blog/post-123`) | 0.89 | every non-route request |
| `normalizePath` (dot-segment resolve) | 0.81 | every non-route request |
| `normalizePath` (reject `%2f`) | 0.08 | malicious paths (fast-fail) |
| `matchesAny` worker-managed (hit) | 0.11 | every request |
| `matchesAny` worker-managed (miss) | 0.23 | every request |
| `classify` public hit | 0.29 | every classified request |
| `classify` protected hit | 0.18 | every classified request |
| `classify` default-tier fallthrough | 0.33 | unmatched paths |
| `canonicalJson(policy payload)` | 9.70 | policy refresh only (≤1/60 s) |
| HMAC sign (cookie) | 3.75 | session/state mint |
| `readSession` (parse + HMAC verify + validate) | **6.45** | protected/secured |
| `mintSessionCookie` (HMAC sign) | 6.50 | callback only |
| `verifyPolicyEnvelope` (HMAC over canonical JSON) | 17.65 | policy refresh only |
| **RSA-2048 verify (raw)** | **17.50** | callback only |
| `verifyIdToken` (RSA + 2 KV reads + claims) | 436.75 | callback only |

**Reading it:** the per-request hot path is *cheap* — config + path + policy +
classify is **~3 µs** combined; adding a session HMAC verify is **~6 µs** more.
RSA verification (the scary one) is **17 µs**. The big `verifyIdToken` number is
dominated by its two KV reads (discovery + JWKS), not by crypto — see Finding 2.

---

## Part 2 — Per-request CPU vs wait, by scenario

`CPU` is the worker's own compute (CPU-isolation batch). `KV` / `origin` are
measured op counts. `wall (modeled)` = CPU + KV×8 ms + origin×35 ms. `weight` is
an assumed EDS-typical traffic mix (see Caveats), used only for the weighted means.

| Scenario | weight | CPU (µs) | KV reads | origin | wall (modeled) | CPU share of wall |
|---|--:|--:|--:|--:|--:|--:|
| public-asset (`/styles`, worker-managed) | 55 % | 41 | 0 | 1 | ~35 ms | 0.12 % |
| public-page (`/blog`, KV policy) | 30 % | 34 | 0 | 1 | ~35 ms | 0.10 % |
| protected-authorized (`/members`) | 8 % | 47 | 0 | 1 | ~35 ms | 0.13 % |
| secured-authorized (`/api`) | 3 % | 48 | 0 | 1 | ~35 ms | 0.14 % |
| protected-denied → login (302) | 2 % | ~64 † | 1 | 0 | ~8 ms | 0.8 % |
| secured-denied (401) | 1 % | 33 | 0 | 0 | ~0 ms | 100 % |
| audience-denied (403) | 0.5 % | 44 | 0 | 0 | ~0 ms | 100 % |
| bad-path rejected (400) | 0.2 % | 26 | 0 | 0 | ~0 ms | 100 % |
| login-callback | 0.1 % | ~60 ‡ | 6 | 1 | ~85 ms | <0.1 % |

† 302 CPU includes one local KV read (~210 µs locally) that the isolation stub
doesn't zero; true compute is ~60 µs. ‡ callback CPU can't be isolated cleanly
(the in-process mock OP signs the id_token during the stubbed token fetch);
component estimate from Part 1: readState 6 + verifyIdToken-crypto ~40 +
mintSession 6 ≈ **~60 µs**. Its wall is dominated by 6 KV ops + the token exchange.

### Traffic-weighted per request

| Metric | Value |
|---|--:|
| Mean worker CPU | **~41 µs** |
| Mean origin fetches | **0.96** |
| Mean KV reads | **0.026** |
| CPU as fraction of the 50 ms CPU limit | **0.083 %** |

The deny/reject paths (401/403/400) are the only ones where CPU *is* the wall —
because they make no subrequest. They fail fast in **26–44 µs** with zero I/O,
which is exactly what you want from an authorization gate under attack.

---

## Findings & optimization guidance

### 1. The origin fetch is the wall-time bottleneck; the worker is noise
The worker's compute is ~40 µs — **0.08 % of the CPU limit** (this needs no
assumptions). For wall-time: ~96 % of traffic forwards, and there wall-time ≈ the
origin RTT (~35 ms modeled), so the worker contributes ~0.1 %. Either way,
shaving worker CPU will not move user-perceived latency. **Invest in the origin
path instead:**

- Public responses already forward with edge caching intact
  ([`origin.js`](../../src/origin.js) only disables cache for protected/secured) —
  confirm the EDS cache hit-rate at the edge is high; a cache HIT removes the
  35 ms entirely.
- Origin proximity / connection reuse (keep-alive to the AEM origin) is where
  real latency lives.

### 2. Login callback re-reads OIDC discovery from KV — add an isolate cache *(low priority)*
The callback makes **6 sequential KV ops**, and OIDC discovery is read from KV
**twice** per callback — once in [`handleCallback`](../../src/oidc.js) and again
inside [`verifyIdToken`](../../src/jwt.js) → `getDiscovery`. JWKS is read once
more. Unlike [`policy-snapshot.js`](../../src/policy-snapshot.js), which memoizes
the parsed policy in an isolate-level `Map`, [`jwt.js`](../../src/jwt.js)'s
`cachedJson` caches **only in KV** — so every `getDiscovery`/`getJwks` is a KV
round-trip even in a warm isolate.

**Fix:** mirror the policy-snapshot pattern — wrap discovery/JWKS in an
isolate-level memo (TTL'd) in front of the KV cache. That cuts the callback from
~6 KV ops to ~3 and removes the duplicate discovery read on the verify path. It
also helps the **302 login-redirect** path, whose one KV read is the same
`getDiscovery` call in [`startLogin`](../../src/oidc.js).

_Priority: low._ Callback is ~0.1 % of traffic and user-interactive (an ~85 ms
login is imperceptible). But it's a clean, localized win and removes the only
repeated I/O in the codebase.

### 3. `loadConfig` is the most expensive non-crypto per-request op *(micro)*
At **1.88 µs**, [`loadConfig`](../../src/config.js) is ~5 % of steady-state CPU —
small, but it's the largest avoidable slice. It re-runs every request:
`JSON.parse(ROUTES)`, `JSON.parse(AUDIENCE_MAP)` and `assertKeyLength`
(a `TextEncoder.encode` of each secret) are **not** memoized, while
`ACCESS_POLICY`/`WORKER_MANAGED_PATHS` already are (`parseJsonMemo`). Memoizing
the whole derived config by isolate would erase this. _Priority: very low — it's
40 ns × traffic; only worth it if touching the file anyway._

### 4. Crypto is cheap; don't pre-optimize it
HMAC session verify is **6 µs**, RSA id_token verify is **17 µs**. Both run on
BoringSSL and are nowhere near a concern. The session design (opaque HMAC cookie,
id_token parked in KV) keeps the per-request hot path free of asymmetric crypto
entirely — RSA only runs once per login.

### 5. Observer effect (validates the instrumentation is production-safe)
With the real tracer attached, requests cost **+14–25 µs** (≈7 `performance.now()`
calls per request) vs the `NOOP` path. That's why production runs with `NOOP` and
the tracer is opt-in. The CPU figures above are from `NOOP` batches, so they
exclude this overhead. The residual cost of the `NOOP` path itself (≈9 frozen
empty method calls per request, no clock reads, no allocation) is negligible but
was **not separately measured** against a pristine pre-instrumentation handler.

---

## Caveats

- **Modeled latencies are assumptions**, not measurements (local KV/origin are
  microseconds). Only the *op counts* and *CPU* are measured. Swap in real edge
  numbers from production logs (`x-auth-request-id` ↔ origin correlation) to
  validate the 35 ms/8 ms assumptions.
- workerd's ~1 ms clock resolution means per-request **percentiles** are not
  meaningful here; all figures are **means over batches**. CPU at this scale is
  tight and stable; tail latency in production will be dominated by origin/KV tail,
  which this harness does not model.
- The callback CPU figure is a component estimate, not a clean isolation
  measurement (see ‡ above).
- **The traffic weights (55 %/30 %/…) are an assumed EDS-typical mix, not measured
  traffic.** The weighted-CPU conclusion is insensitive to them: every hot path
  measures 26–64 µs, so any reasonable reweighting lands in the same ~40 µs band.
