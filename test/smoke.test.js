import { describe, it, expect } from "vitest";
import { env } from "cloudflare:test";

describe("harness", () => {
  it("runs in workerd with Web Crypto + KV bindings", async () => {
    expect(typeof crypto.subtle.digest).toBe("function");
    await env.OIDC_CACHE.put("k", "v");
    expect(await env.OIDC_CACHE.get("k")).toBe("v");
  });
});
