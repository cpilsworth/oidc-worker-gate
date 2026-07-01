// Performance-harness plumbing: I/O tracing, percentile stats, env wiring.
// Runs inside workerd (vitest-pool-workers) so CPU numbers come from the same
// V8 + BoringSSL crypto + miniflare KV the worker uses in production.

import { env } from "cloudflare:test";

/** Holder so the global fetch wrapper can find the current request's tracer. */
export const tracerRef = { current: null };

/**
 * Patch globalThis.fetch to (a) time every subrequest as off-CPU "origin" wait
 * and (b) route OpenID-Provider URLs to an in-process mock when one is given,
 * so the only thing that varies between runs is the worker's own work.
 * @param {{ issuerHost?: string, op?: { handle: (r: Request) => Promise<Response> } }} [opts]
 * @returns {() => void} restore
 */
export function installFetchTracing({ issuerHost, op } = {}) {
  const orig = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const req = input instanceof Request ? input : new Request(input, init);
    const host = new URL(req.url).hostname;
    const t0 = performance.now();
    let res;
    if (op && issuerHost && host === issuerHost) {
      res = await op.handle(req);
    } else {
      res = await orig(input, init);
    }
    tracerRef.current?.recordIo("origin", performance.now() - t0);
    return res;
  };
  return () => { globalThis.fetch = orig; };
}

/** Wrap a KV namespace so get/put/delete are timed as off-CPU "kv" wait. */
export function traceKv(kv) {
  const time = (fn) => async (...args) => {
    const t0 = performance.now();
    try {
      return await fn(...args);
    } finally {
      tracerRef.current?.recordIo("kv", performance.now() - t0);
    }
  };
  return new Proxy(kv, {
    get(target, prop, recv) {
      const v = Reflect.get(target, prop, recv);
      if (prop === "get" || prop === "put" || prop === "delete") return time(v.bind(target));
      return typeof v === "function" ? v.bind(target) : v;
    },
  });
}

/**
 * Build the env the worker sees: real bindings plus harness extras (a traced KV,
 * the tracer, and any policy/secret overrides a scenario needs).
 */
export function makeEnv(overrides = {}) {
  return {
    ...env,
    ...overrides,
    OIDC_CACHE: traceKv(overrides.OIDC_CACHE || env.OIDC_CACHE),
  };
}

export function percentile(sortedAsc, p) {
  if (sortedAsc.length === 0) return 0;
  const idx = Math.min(sortedAsc.length - 1, Math.ceil((p / 100) * sortedAsc.length) - 1);
  return sortedAsc[Math.max(0, idx)];
}

/** Summary stats (ms) over a sample array. */
export function stats(samples) {
  const s = [...samples].sort((a, b) => a - b);
  const sum = s.reduce((a, b) => a + b, 0);
  return {
    n: s.length,
    min: s[0] ?? 0,
    p50: percentile(s, 50),
    p90: percentile(s, 90),
    p99: percentile(s, 99),
    max: s[s.length - 1] ?? 0,
    mean: s.length ? sum / s.length : 0,
  };
}

export const fmt = (n, d = 3) => Number(n).toFixed(d);
