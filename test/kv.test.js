import { describe, it, expect } from "vitest";
import { kvGetFresh, kvPutWithTtl } from "../src/kv.js";

function memoryKv() {
  const m = new Map();
  return {
    get: async (key, type) => {
      const raw = m.get(key);
      if (raw == null) return null;
      return type === "json" ? JSON.parse(raw) : raw;
    },
    put: async (key, value) => { m.set(key, value); },
  };
}

describe("kv expiry-wrapper helpers (S3)", () => {
  it("round-trips a value within its TTL", async () => {
    const kv = memoryKv();
    await kvPutWithTtl(kv, "k", { a: 1 }, 10, { now: 1_000 });
    expect(await kvGetFresh(kv, "k", { now: 5_000 })).toEqual({ a: 1 });
  });

  it("returns null once the wrapped value is stale", async () => {
    const kv = memoryKv();
    await kvPutWithTtl(kv, "k", "v", 10, { now: 1_000 }); // expires at 11_000
    expect(await kvGetFresh(kv, "k", { now: 20_000 })).toBeNull();
  });

  it("returns null for a missing key", async () => {
    expect(await kvGetFresh(memoryKv(), "absent")).toBeNull();
  });

  it("treats an unbound KV as a miss / no-op (does not throw)", async () => {
    expect(await kvGetFresh(null, "k")).toBeNull();
    await expect(kvPutWithTtl(null, "k", "v", 10)).resolves.toBeUndefined();
  });

  it("stores a KV expirationTtl alongside the wrapper", async () => {
    let seen;
    const kv = { put: async (_k, _v, opts) => { seen = opts; }, get: async () => null };
    await kvPutWithTtl(kv, "k", "v", 42);
    expect(seen).toEqual({ expirationTtl: 42 });
  });
});
