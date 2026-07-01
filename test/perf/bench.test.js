// Performance benchmark for the OIDC worker gate.
//
// Runs inside workerd (vitest-pool-workers) so timings come from the same V8
// engine, BoringSSL crypto and miniflare KV as production. workerd coarsens
// performance.now() to ~1ms (a Spectre mitigation), which is far too coarse to
// time a single request's tens-of-microseconds of CPU. So we measure by
// AMORTISATION: run each unit of work N times in a tight loop, time the whole
// batch at ~1ms resolution, and divide — giving sub-microsecond precision on
// the mean. I/O is reported as a deterministic op COUNT (KV reads, origin
// subrequests) which a production wall-time model multiplies by assumed
// latencies (local miniflare/stub I/O is microseconds and not representative).
//
// Run with:  npm run bench -- --disable-console-intercept
// Emits a JSON result blob to stdout between PERF_RESULTS markers.

import { it, expect } from "vitest";
import { env } from "cloudflare:test";
import worker from "../../src/index.js";
import { Tracer } from "../../src/perf.js";
import { loadConfig } from "../../src/config.js";
import { normalizePath } from "../../src/path.js";
import { classify, matchesAny } from "../../src/policy.js";
import { readSession, mintSessionCookie, mintStateCookie } from "../../src/session.js";
import { sign, unsign, deriveCookieKey } from "../../src/cookies.js";
import { verifyIdToken } from "../../src/jwt.js";
import {
  signPolicyPayload, verifyPolicyEnvelope, policyCacheKey, canonicalJson,
} from "../../src/policy-snapshot.js";
import { createPkcePair, randomState, randomNonce } from "../../src/pkce.js";
import { createMockOp } from "../mock-op.js";
import { seedDiscovery } from "../helpers.js";
import { installFetchTracing, traceKv, makeEnv, tracerRef } from "./harness.js";

const drain = (res) => res.arrayBuffer().catch(() => {});

const SCENARIO_ITERS = 4000;
const CALLBACK_ITERS = 400;

// Modeled production latencies for the wall-time projection (NOT measured).
const MODEL = { originMs: 35, kvReadMs: 8 };

const ORIGIN = "https://www.example.com";
const POLICY_HMAC_KEY = "bench-policy-hmac-key-at-least-32-bytes!!";
const us = (ms) => ms * 1000;

/** Amortised micro-benchmark: warm, then time N calls as one batch. */
async function micro(name, n, fn) {
  const warm = Math.min(n, 1000);
  for (let i = 0; i < warm; i++) await fn(i);
  const t0 = performance.now();
  for (let i = 0; i < n; i++) await fn(i);
  const batchMs = performance.now() - t0;
  return { name, n, perOpUs: us(batchMs) / n, batchMs };
}

function req(path, { cookie, method = "GET" } = {}) {
  const h = new Headers();
  if (cookie) h.set("cookie", cookie);
  h.set("cf-ray", "bench-ray-0000");
  return new Request(`${ORIGIN}${path}`, { method, headers: h });
}

it("performance benchmark", async () => {
  const op = await createMockOp({ issuer: env.OIDC_ISSUER, clientId: env.CLIENT_ID });
  await seedDiscovery(env.OIDC_ISSUER, op.discovery, op.jwks);

  // Seed a signed policy snapshot so the KV-backed policy path is exercised.
  const policyRules = JSON.parse(env.ACCESS_POLICY).rules;
  const policyPayload = {
    schema_version: 1, site_id: env.POLICY_SITE_ID, version: "bench-1",
    published_at: new Date().toISOString(), rules: policyRules,
  };
  const policySignature = await signPolicyPayload(policyPayload, POLICY_HMAC_KEY);
  const policyEnvelope = { payload: policyPayload, signature: policySignature };
  await env.OIDC_CACHE.put(policyCacheKey(env.POLICY_SITE_ID), JSON.stringify(policyEnvelope));

  const restoreFetch = installFetchTracing({ issuerHost: new URL(env.OIDC_ISSUER).hostname, op });
  const baseEnv = makeEnv({ POLICY_HMAC_KEY });
  const cfg = loadConfig({ ...env, POLICY_HMAC_KEY, OIDC_CACHE: env.OIDC_CACHE });

  const mintCfg = {
    sessionKey: env.SESSION_HMAC_KEY, sessionTtlSeconds: 3600,
    groupsClaim: env.GROUPS_CLAIM, audienceMap: JSON.parse(env.AUDIENCE_MAP), kv: null,
  };
  const cookieFor = async (groups) => {
    const line = await mintSessionCookie({ sub: "user-123", [env.GROUPS_CLAIM]: groups }, mintCfg);
    return `__Host-gate_session=${line.match(/__Host-gate_session=([^;]*)/)[1]}`;
  };
  const medicalCookie = await cookieFor(["medical"]);
  const secureCookie = await cookieFor(["secure"]);
  const wrongCookie = await cookieFor(["secure"]);

  // =========================================================================
  // PART 1 — Phase micro-benchmarks (pure on-CPU cost of each hot operation)
  // =========================================================================
  const policyObj = { rules: policyRules, default_tier: cfg.policy.default_tier };
  const sessKey = await deriveCookieKey(env.SESSION_HMAC_KEY, "gate-session-v1");
  const sessReq = req("/members/account", { cookie: medicalCookie });

  // RSA verify material (the callback's signature check, in isolation).
  const rsaPubKey = await crypto.subtle.importKey(
    "jwk", { kty: op.key.publicJwk.kty, n: op.key.publicJwk.n, e: op.key.publicJwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const rsaSignKey = op.key.privateKey;
  const rsaData = new TextEncoder().encode("header.payload.sample-jwt-signing-input-string");
  const rsaSig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", rsaSignKey, rsaData);

  // A valid id_token for the full verifyIdToken path (incl. its 2 KV reads).
  const idToken = await op.mintIdToken({ nonce: "n-1", claims: { nonce: "n-1" } });

  const micros = [];
  micros.push(await micro("loadConfig (per request)", 50000, () => loadConfig(baseEnv)));
  micros.push(await micro("normalizePath /styles/styles.css", 100000, () => normalizePath("/styles/styles.css")));
  micros.push(await micro("normalizePath /blog/post-123", 100000, () => normalizePath("/blog/post-123")));
  micros.push(await micro("normalizePath /a/b/../c/./d (dot-seg)", 100000, () => normalizePath("/a/b/../c/./d")));
  micros.push(await micro("normalizePath /blog/%2fadmin (reject)", 100000, () => normalizePath("/blog/%2fadmin")));
  micros.push(await micro("matchesAny worker-managed (/styles hit)", 100000, () => matchesAny(cfg.workerManagedPaths, "/styles/x.css")));
  micros.push(await micro("matchesAny worker-managed (/blog miss)", 100000, () => matchesAny(cfg.workerManagedPaths, "/blog/post")));
  micros.push(await micro("classify public hit (/blog)", 100000, () => classify("/blog/post", policyObj)));
  micros.push(await micro("classify protected hit (/members)", 100000, () => classify("/members/x", policyObj)));
  micros.push(await micro("classify default-tier fallthrough", 100000, () => classify("/deeply/unmatched/path", policyObj)));
  micros.push(await micro("canonicalJson(policy payload)", 20000, () => canonicalJson(policyPayload)));
  micros.push(await micro("HMAC sign (cookie)", 20000, () => sign('{"sub":"user-123","groups":["medical"],"iat":1,"exp":9999999999}', sessKey)));
  micros.push(await micro("readSession (parse+HMAC verify+validate)", 20000, () => readSession(sessReq, mintCfg)));
  micros.push(await micro("mintSessionCookie (HMAC sign)", 20000, () => mintSessionCookie({ sub: "u", [env.GROUPS_CLAIM]: ["medical"] }, mintCfg)));
  micros.push(await micro("verifyPolicyEnvelope (KV cold: HMAC verify)", 20000, () => verifyPolicyEnvelope(policyEnvelope, cfg)));
  micros.push(await micro("RSA-2048 verify (raw, pure CPU)", 4000, () => crypto.subtle.verify("RSASSA-PKCS1-v1_5", rsaPubKey, rsaSig, rsaData)));
  micros.push(await micro("verifyIdToken (RSA + 2 KV reads + claims)", 4000, () => verifyIdToken(idToken, cfg, "n-1")));

  // =========================================================================
  // PART 2 — End-to-end scenarios (amortised CPU + deterministic I/O counts)
  // =========================================================================
  const scenarios = [
    { name: "public-asset (worker-managed /styles)", weight: 55, status: 200, request: () => req("/styles/styles.css") },
    { name: "public-page (KV policy /blog)", weight: 30, status: 200, request: (i) => req(`/blog/post-${i % 50}`) },
    { name: "protected-authorized (/members)", weight: 8, status: 200, request: () => req("/members/account", { cookie: medicalCookie }) },
    { name: "secured-authorized (/api)", weight: 3, status: 200, request: () => req("/api/orders", { cookie: secureCookie }) },
    { name: "protected-denied-nosession (302)", weight: 2, status: 302, request: () => req("/members/account") },
    { name: "secured-denied-nosession (401)", weight: 1, status: 401, request: () => req("/api/orders") },
    { name: "protected-denied-audience (403)", weight: 0.5, status: 403, request: () => req("/members/account", { cookie: wrongCookie }) },
    { name: "bad-path-encoded-sep (400)", weight: 0.2, status: 400, request: () => req("/blog/%2fadmin") },
  ];

  // CPU-isolation fetch: OP requests still resolve (instantly) via the mock so
  // the callback flow completes; everything else (the origin) returns instantly.
  const issuerHost = new URL(env.OIDC_ISSUER).hostname;
  const isoFetch = async (input, init) => {
    const r = input instanceof Request ? input : new Request(input, init);
    if (new URL(r.url).hostname === issuerHost) return op.handle(r);
    return new Response("ok");
  };

  const results = [];
  for (const sc of scenarios) {
    results.push(await runScenario(sc, SCENARIO_ITERS, baseEnv, isoFetch));
  }

  // --- Login callback (full OIDC code exchange incl. RSA id_token verify) ---
  {
    const cbEnv = makeEnv({ POLICY_HMAC_KEY });
    const stateCfg = { sessionKey: env.SESSION_HMAC_KEY };
    const cbRequest = async (i) => {
      const state = randomState() + i;
      const nonce = randomNonce();
      const pkce = await createPkcePair();
      const code = `code-${state}`;
      op.issueCode(code, { claims: { nonce }, codeChallenge: pkce.challenge });
      const stateCookie = await mintStateCookie(
        { state, nonce, verifier: pkce.verifier, returnTo: "/members/account" }, stateCfg);
      const token = stateCookie.match(/__Host-gate_login=([^;]*)/)[1];
      return req(`/.auth/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`,
        { cookie: `__Host-gate_login=${token}` });
    };
    results.push(await runScenario(
      { name: "login-callback (RSA verify)", weight: 0.1, status: 302, request: cbRequest, async: true },
      CALLBACK_ITERS, cbEnv, isoFetch));
  }

  restoreFetch();

  const meta = {
    runtime: "workerd (vitest-pool-workers)",
    method: "amortised batch timing (perf.now ~1ms resolution); I/O reported as op counts",
    scenarioIters: SCENARIO_ITERS, callbackIters: CALLBACK_ITERS,
    model: MODEL, generatedAt: new Date().toISOString(),
  };
  console.log("===PERF_RESULTS_BEGIN===");
  console.log(JSON.stringify({ meta, micros, results }));
  console.log("===PERF_RESULTS_END===");
  expect(results.length).toBe(scenarios.length + 1);
}, 180_000);

/**
 * Amortised end-to-end run for one scenario. Returns mean per-request CPU
 * (instrumented vs not, for the observer effect) and the deterministic I/O
 * op-count breakdown captured from a representative request.
 */
async function runScenario(sc, iters, scEnv, isoFetch) {
  const build = sc.async ? (i) => sc.request(i) : (i) => Promise.resolve(sc.request(i));

  // Warm: compile matchers, populate the in-isolate policy cache.
  for (let i = 0; i < Math.min(iters, 300); i++) {
    const t = new Tracer(); scEnv.__perf = t; tracerRef.current = t;
    const res = await worker.fetch(await build(`w${i}`), scEnv);
    expect(res.status).toBe(sc.status);
    await drain(res);
  }

  // Instrumented batch — also accumulate per-phase CPU and I/O counts.
  const phaseCpu = {}; let waitSum = 0; let repSample = null;
  const reqs = [];
  for (let i = 0; i < iters; i++) reqs.push(await build(i)); // build outside the timed region
  const ti0 = performance.now();
  for (let i = 0; i < iters; i++) {
    const t = new Tracer(); scEnv.__perf = t; tracerRef.current = t;
    const res = await worker.fetch(reqs[i], scEnv);
    await drain(res);
    const rep = t.report();
    repSample = rep; waitSum += rep.wait;
    for (const p of rep.phases) phaseCpu[p.name] = (phaseCpu[p.name] || 0) + p.cpu;
  }
  const instrBatchMs = performance.now() - ti0;

  // NOOP batch — true wall with no tracer attached (observer-effect baseline).
  const reqs2 = [];
  for (let i = 0; i < iters; i++) reqs2.push(await build(i + iters));
  scEnv.__perf = undefined; tracerRef.current = null;
  const tn0 = performance.now();
  for (let i = 0; i < iters; i++) {
    const res = await worker.fetch(reqs2[i], scEnv);
    await drain(res);
  }
  const noopBatchMs = performance.now() - tn0;

  // CPU-isolation batch — origin subrequest resolves instantly so the batch wall
  // is the worker's own compute (no network/stub variance). KV reads (if any)
  // still hit local miniflare; steady-state scenarios make none (warm cache).
  const reqs3 = [];
  for (let i = 0; i < iters; i++) reqs3.push(await build(i + 2 * iters));
  const realFetch = globalThis.fetch;
  globalThis.fetch = isoFetch;
  scEnv.__perf = undefined; tracerRef.current = null;
  const tc0 = performance.now();
  for (let i = 0; i < iters; i++) {
    const res = await worker.fetch(reqs3[i], scEnv);
    await drain(res);
  }
  const cpuIsoBatchMs = performance.now() - tc0;
  globalThis.fetch = realFetch;

  const meanInstrUs = us(instrBatchMs) / iters;
  const meanNoopUs = us(noopBatchMs) / iters;
  const meanCpuIsoUs = us(cpuIsoBatchMs) / iters;
  const meanWaitLocalUs = us(waitSum) / iters;
  const phases = Object.entries(phaseCpu).map(([name, sum]) => ({ name, cpuUs: us(sum) / iters }));

  return {
    name: sc.name, weight: sc.weight, status: sc.status,
    workerCpuUs: meanCpuIsoUs,
    meanWallNoopUs: meanNoopUs,
    meanWallInstrUs: meanInstrUs,
    observerEffectUs: Math.max(0, meanInstrUs - meanNoopUs),
    localWaitUs: meanWaitLocalUs,
    kvOps: repSample.kvOps, originOps: repSample.originOps,
    ioByPhase: repSample.phases
      .filter((p) => p.kvOps || p.originOps)
      .map((p) => ({ name: p.name, kvOps: p.kvOps, originOps: p.originOps })),
    phases,
  };
}
