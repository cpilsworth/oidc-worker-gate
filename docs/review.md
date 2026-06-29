# Plan review — simpler / faster / compliant / reliable / observable

> Review of `README.md`, `conformance-testing.md`, `folder-authorization.md`
> (2026-06-10). This is a **review with recommendations**, not a rewrite of the
> design docs. Each rec is tagged with the goal it serves and an effort/impact
> read. Apply selectively — the plan is already strong.

## Verdict

The design is sound and the reasoning is unusually careful (deny-by-default with
the EDS infra carve-out, KV only for staleness-tolerant data, login state in the
signed cookie, the N1–N15 negative matrix, disjoint-additive DA grants). The
biggest wins are **structural and sequencing**, not algorithmic — the hot path is
already optimal. Lead changes: explicit MVP phasing, one normalized policy model,
and lift observability to a top-level concern.

---

## 1. Phase the build — defer the risky, unresolved parts (simpler, faster) ★ top rec

The plan reads as one monolith, but it contains three subsystems at very different
risk levels. The IMS profile fetch, the DA-sourced ACL, and the User Management API
lookup are the **least-resolved** parts (Q3 is still open: product-profiles vs.
user-groups), yet nothing about a working core gate depends on them. Sequence:

- **Phase 1 — core gate (ships alone).** Generic IdP, static `ACCESS_POLICY`, the
  three tiers, single origin `fetch()`, mock-OP tests (P1–P7, N1–N15). This is a
  complete, demonstrable RP. No IMS, no DA, no UMA.
- **Phase 2 — IMS as OP.** Swap issuer, add the `/ims/profile/v1` call at
  session-mint, map product-profiles → session entitlements. Gated on Q3.
- **Phase 3 — DA folder-authz.** Control-plane push → KV ACL, unified matcher,
  last-known-good. Depends on Phase 1 + Q3 + Q4.

**Why:** Phase 1 is the fastest path to working software and carries zero open
questions. Phases 2–3 are where the unknowns live; building the DA control-plane
pipeline before the gate works (and before Q3 resolves) is the plan's main YAGNI
risk. State this phasing explicitly in `README.md` so an implementer doesn't try
to land everything at once.

## 2. Unify the two policy systems (simpler) ★

`README.md` should define a single static `ACCESS_POLICY`, and
`folder-authorization.md` should use the same row shape for the DA-sourced KV ACL.
Avoid parallel "path policy" and "claim policy" concepts:

- **One ACL shape**: `{ path, tier (public|protected|secured), audience? }`,
  evaluated by most-specific match.
- **Static `ACCESS_POLICY` is the Phase 1 source** baked into config; **the KV ACL
  is the Phase 3 runtime source** that supersedes it when present. Same matcher
  reads both.
- `tier` controls the unauthenticated behavior; `audience` controls authorization
  for authenticated sessions.

**Why:** one evaluator, one mental model, one set of tests. Removes the "which
policy wins?" question before it's asked.

## 3. Lift observability to a top-level section (observable) ★

Observability currently lives only inside `folder-authorization.md`
(`{policy_version, sub, path, decision}`). The gate is the thing operators will
watch — give `README.md` its own section:

- **One structured log line per decision**: `tier`, `decision`
  (`forward|302|401|403|400`), `reason`, `sub` (or a salted hash), `kid`,
  `policy_version`, origin-fetch latency, `cf-ray`.
- **Outcome codes as metrics, not just responses.** The 400-on-bad-callback the
  conformance doc already insists on (so rejection is observable) should also be a
  *counter*. Counters worth having: login starts, callback success/fail **by
  reason**, JWKS refetch, ACL staleness-serve events, KV read errors.
- **CF-native sink**: name **Workers Analytics Engine** (cheap, high-cardinality
  decision stream) and/or **Logpush**. This is the concrete answer to "observable"
  on Cloudflare and is currently unstated.
- Propagate a request id to origin (`x-auth-request-id: <cf-ray>`) for
  edge↔origin correlation.

## 4. "Port almost verbatim" hides real conformance work (compliant, reliable) ★

I checked the sibling `../oidc-edge-gate/src/jwt.js`. It already covers a lot of
the matrix — RS256-only (N2), `kid` selection (N7), `iss` (N3), array-aware `aud`
(N4), `exp`/`nbf` with skew (N5), `nonce` (N6). But it is **missing** three things
the N-matrix and the OIDF Basic/Config RP plans require:

- **`c_hash` / `at_hash` validation (N11)** — not implemented at all.
- **`azp` check when `aud` is multi-valued** — spec says if there are multiple
  audiences, `azp` MUST be present and equal `client_id`. Current `audienceMatches`
  only checks membership.
- **"refetch JWKS once on `kid` miss" (N7)** — current code throws on unknown
  `kid`; there's no single-refetch-then-reject path for key rotation.

**Action:** change Milestone 2 from "copy verbatim" to "**port and close the
N-matrix gaps**", and add these three as explicit tasks. Otherwise the conformance
layer fails on day one and the effort is invisible in the plan.

## 5. Be honest about "faster" — the hot path is already optimal (faster)

Single origin `fetch()` + local HMAC verify is the right design; there's little to
wring out. State the *real* wins plainly instead of padding:

- **Warm-isolate memoization in front of KV.** Discovery, JWKS, and the ACL should
  sit in module-scope memory with a TTL so a warm isolate never round-trips to KV.
  The plan says this for the ACL ("cached in isolate memory") — say it explicitly
  for discovery/JWKS too. This is the single biggest latency lever.
- **Public short-circuits before cookie parse** — already in step 4. Good; keep it
  first.
- **No `nodejs_compat`** — pure Web Crypto means a smaller, faster bundle. Worth a
  one-line note so nobody adds it reflexively.
- The IMS `/ims/profile/v1` round-trip is at the callback only (rare), not per
  request — already correct; just label it so it isn't mistaken for hot-path cost.

## 6. Reliability hardening (reliable)

- **JWKS last-known-good window**, mirroring the ACL design. If a JWKS refetch
  fails transiently, keep serving with cached keys inside a staleness window rather
  than failing *all* logins on a blip.
- **Backoff / negative-cache on `kid` miss** so a flood of bad/old `kid`s can't
  hammer the JWKS endpoint (pairs with rec 4's refetch-once).
- Keep the **signed-policy-blob** idea (verify in worker so a KV mis-write can't
  silently widen access) — that's good defensive design, not gold-plating.
- `jti`/`sub` denylist and two-key change control are correctly deferred — leave
  them deferred.

## 7. Three-tier vs. content negotiation (simpler) — *footnote, not a change*

The only difference between `protected` and `secured` is the **unauthenticated
response** (302 vs 401); the auth/session/audience logic is identical. One *could*
derive 302-vs-401 from `Sec-Fetch-Mode: navigate` / `Accept: text/html` and drop
the `secured` list. **Don't lead with this.** It's the user's own framing and the
project's defining feature, and deriving behavior from client-controlled headers
trades away the auditability/predictability that a *conformance reference*
implementation is selling. Worth one line in `README.md` as an option —
"302-vs-401 *may* optionally be content-negotiated within the protected/secured
tiers, at the cost of auditability" — and nothing more.

---

## Applying the writing-plans skill

These are **design docs**, and they're good ones — converting them wholesale into
checkbox-TDD task ceremony would bloat them. Take the principles that transfer:

- **Scope split.** The skill says one plan per subsystem, each independently
  shippable. That's exactly rec 1's phasing. Consider a companion
  `plan.md` (or `docs/plans/2026-06-10-oidc-worker-gate.md`) **only when you start
  building**, with the skill's header (Goal / Architecture / Tech Stack), the file
  map (already present in `README.md` — reuse it), and bite-sized tasks.
- **Resolve-or-spike the open questions.** A plan must not ship placeholders;
  Q1–Q4 are fine in a *design doc* but in an implementation plan each becomes a
  **time-boxed spike with a decision criterion** (e.g. "Q3: confirm whether the DA
  ACL names product-profiles or user-groups by inspecting one real ACL sheet;
  decision gate before Phase 2/3"). `ask-fluffyjaws` is the tool for Q1/Q3/Q4.
- **TDD fit is already there.** Each N-case in `conformance-testing.md` is
  literally a failing-test-first. The skill's red→green→commit loop maps onto the
  N-matrix one-to-one — call this out so the implementer writes the broken-token
  test before the rejection code.
- **File granularity.** The 10-file split mirrors the sibling's 8 + `policy.js` +
  `origin.js`; it follows the established pattern and is fine. Optional micro-merge
  (`pkce.js`→`oidc.js`, `encoding.js`→`cookies.js`) only if you dislike sub-50-LOC
  files — low value, skip unless it bothers you.

---

## Priority order

1. **Phase the build** (rec 1) — biggest simpler+faster win, unblocks shipping.
2. **Close the N-matrix gaps** in the port (rec 4) — compliance correctness; the
   plan currently hides this work.
3. **Top-level observability section** (rec 3) — names the CF-native sink that's
   missing.
4. **Unify the policy systems** (rec 2) — removes a parallel-mechanism mental tax.
5. JWKS last-known-good + backoff (rec 6), warm-isolate memo note (rec 5),
   tier-negotiation footnote (rec 7) — smaller, do alongside.
