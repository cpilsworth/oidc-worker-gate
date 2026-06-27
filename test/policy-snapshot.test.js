import { describe, it, expect } from "vitest";
import { loadRuntimePolicy, policyCacheKey, signPolicyPayload, verifyPolicyEnvelope } from "../src/policy-snapshot.js";

const policyHmacKey = "policy-hmac-key-at-least-32-bytes-long!!";

function config(overrides = {}) {
  return {
    policySource: "auto",
    policySiteId: `cpilsworth/j2retail-${crypto.randomUUID()}`,
    policyHmacKey,
    policyRefreshTtlSeconds: 60,
    policyStaleTtlSeconds: 900,
    policy: {
      rules: [{ path: "/static/**", tier: "protected", audience: ["static"] }],
      default_tier: "protected",
    },
    kv: memoryKv(),
    ...overrides,
  };
}

function memoryKv() {
  const values = new Map();
  return {
    get: (key) => values.get(key) || null,
    put: (key, value) => values.set(key, value),
    delete: (key) => values.delete(key),
  };
}

async function signedEnvelope(payload, secret = policyHmacKey) {
  return { payload, signature: await signPolicyPayload(payload, secret) };
}

function payload(siteId, rules = [{ path: "/members/**", tier: "protected", audience: ["medical"] }]) {
  return {
    schema_version: 1,
    site_id: siteId,
    version: "2026-06-27T14:30:00Z",
    published_at: "2026-06-27T14:30:00Z",
    rules,
    ignored_rules: [{ row: 3, path: "/media_*", reason: "reserved_path" }],
  };
}

describe("policy snapshots", () => {
  it("verifies a signed envelope", async () => {
    const c = config();
    const p = payload(c.policySiteId);
    await expect(verifyPolicyEnvelope(await signedEnvelope(p), c)).resolves.toEqual(p);
  });

  it("rejects a bad signature", async () => {
    const c = config();
    const p = payload(c.policySiteId);
    await expect(verifyPolicyEnvelope({ payload: p, signature: "bad" }, c))
      .rejects.toThrow(/signature/);
  });

  it("loads a valid KV policy in auto mode", async () => {
    const c = config();
    await c.kv.put(policyCacheKey(c.policySiteId), JSON.stringify(await signedEnvelope(payload(c.policySiteId))));
    const loaded = await loadRuntimePolicy(c, 1_000);
    expect(loaded.source).toBe("kv");
    expect(loaded.version).toBe("2026-06-27T14:30:00Z");
    expect(loaded.policy.rules[0]).toEqual({ path: "/members/**", tier: "protected", audience: ["medical"] });
    expect(loaded.policy.default_tier).toBe("protected");
  });

  it("falls back to static policy when KV is missing", async () => {
    const c = config();
    const loaded = await loadRuntimePolicy(c, 1_000);
    expect(loaded.source).toBe("static-fallback");
    expect(loaded.policy).toBe(c.policy);
  });

  it("required policy source fails closed when KV policy is missing", async () => {
    const c = config({ policySource: "required" });
    await expect(loadRuntimePolicy(c, 1_000)).rejects.toThrow(/policy snapshot missing/);
  });

  it("required policy source fails closed when configuration is incomplete", async () => {
    const c = config({ policySource: "required", policyHmacKey: "" });
    await expect(loadRuntimePolicy(c, 1_000)).rejects.toThrow(/configuration is incomplete/);
  });

  it("worker policy source disables KV policy", async () => {
    const c = config({ policySource: "worker" });
    await c.kv.put(policyCacheKey(c.policySiteId), JSON.stringify(await signedEnvelope(payload(c.policySiteId))));
    const loaded = await loadRuntimePolicy(c, 1_000);
    expect(loaded.source).toBe("worker");
    expect(loaded.policy).toBe(c.policy);
  });

  it("uses last-known-good policy within the stale window after refresh failure", async () => {
    const c = config({ policyRefreshTtlSeconds: 1, policyStaleTtlSeconds: 10 });
    await c.kv.put(policyCacheKey(c.policySiteId), JSON.stringify(await signedEnvelope(payload(c.policySiteId))));

    const first = await loadRuntimePolicy(c, 1_000);
    expect(first.source).toBe("kv");

    await c.kv.delete(policyCacheKey(c.policySiteId));
    const second = await loadRuntimePolicy(c, 3_000);
    expect(second.source).toBe("last-known-good");
    expect(second.policy.rules[0].path).toBe("/members/**");

    const third = await loadRuntimePolicy(c, 12_000);
    expect(third.source).toBe("static-fallback");
    expect(third.policy).toBe(c.policy);
  });

  it("required policy source uses last-known-good within stale window but rejects after it expires", async () => {
    const c = config({ policySource: "required", policyRefreshTtlSeconds: 1, policyStaleTtlSeconds: 10 });
    await c.kv.put(policyCacheKey(c.policySiteId), JSON.stringify(await signedEnvelope(payload(c.policySiteId))));

    const first = await loadRuntimePolicy(c, 1_000);
    expect(first.source).toBe("kv");

    await c.kv.delete(policyCacheKey(c.policySiteId));
    const second = await loadRuntimePolicy(c, 3_000);
    expect(second.source).toBe("last-known-good");

    await expect(loadRuntimePolicy(c, 12_000)).rejects.toThrow(/policy snapshot missing/);
  });
});
