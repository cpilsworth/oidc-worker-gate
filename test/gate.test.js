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
