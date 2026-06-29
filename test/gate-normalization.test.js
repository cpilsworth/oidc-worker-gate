import { describe, it, expect, beforeEach } from "vitest";
import { env, SELF } from "cloudflare:test";
import { createMockOp } from "./mock-op.js";
import { seedDiscovery } from "./helpers.js";

// End-to-end H1 coverage: the gate must classify (and forward) a canonicalized
// path so an encoded/duplicate-separator variant cannot be served as a more
// permissive tier than the resource the origin resolves it to. The static
// ACCESS_POLICY (wrangler.toml) has /blog/** public and /members/** protected.
beforeEach(async () => {
  const op = await createMockOp({ issuer: env.OIDC_ISSUER });
  await seedDiscovery(env.OIDC_ISSUER, op.discovery, op.jwks);
});

describe("gate path normalization (H1)", () => {
  it("encoded dot-traversal under a public prefix is NOT served as public", async () => {
    // Raw `/blog/%2e%2e/members/secret` matches /blog/** but normalizes to the
    // protected /members/secret → must redirect to login, not 200 from origin.
    const res = await SELF.fetch("https://www.example.com/blog/%2e%2e/members/secret", { redirect: "manual" });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain("/authorize");
  });

  it("DOUBLE-encoded dot-traversal under a public prefix is NOT served as public (C-1)", async () => {
    // Raw `/blog/%252e%252e/members/secret` survives a single decode as the literal
    // /blog/%2e%2e/... (public), but the origin resolves it to the protected /members/secret.
    const res = await SELF.fetch("https://www.example.com/blog/%252e%252e/members/secret", { redirect: "manual" });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain("/authorize");
  });

  it("rejects encoded path separators with 400", async () => {
    const res = await SELF.fetch("https://www.example.com/blog/..%2fmembers/secret");
    expect(res.status).toBe(400);
  });

  it("rejects malformed percent-encoding with 400", async () => {
    const res = await SELF.fetch("https://www.example.com/%zz");
    expect(res.status).toBe(400);
  });

  it("percent-encoded protected path is classified protected", async () => {
    const res = await SELF.fetch("https://www.example.com/%6d%65%6d%62%65%72%73/x", { redirect: "manual" });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain("/authorize");
  });

  it("a canonical public path still forwards after normalization", async () => {
    const res = await SELF.fetch("https://www.example.com/%2e%2e/blog/post");
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("origin-body");
  });
});
