import { describe, it, expect, beforeEach } from "vitest";
import { forwardToOrigin } from "../src/origin.js";
import { reqFor } from "./helpers.js";

let seen; // capture what the worker sent to origin
const config = {
  originHostname: "main--mysite--myorg.aem.live",
  forwardedHost: "www.example.com",
  pushInvalidation: true,
};

beforeEach(() => {
  seen = null;
  globalThis.fetch = async (input, init) => {
    const r = input instanceof Request ? input : new Request(input, init);
    seen = { url: r.url, headers: r.headers };
    // Origin replies with a publicly-cacheable header to test the carve-out.
    return new Response("body", { headers: { "cache-control": "public, max-age=3600", "age": "120" } });
  };
});

describe("forwardToOrigin — client header spoofing (C1)", () => {
  it("C1a public tier: inbound x-auth-* headers are stripped before reaching origin", async () => {
    const req = reqFor("/blog/post", {
      headers: {
        "x-auth-subject": "attacker",
        "x-auth-groups": "admins",
        "x-auth-name": "spoof",
      },
    });
    await forwardToOrigin(req, null, "public", config);
    expect(seen.headers.get("x-auth-subject")).toBeNull();
    expect(seen.headers.get("x-auth-groups")).toBeNull();
    expect(seen.headers.get("x-auth-name")).toBeNull();
  });

  it("C1b protected tier: inbound x-auth-name and x-auth-roles are stripped; gate-managed headers are set", async () => {
    const session = { sub: "user-123", email: "u@example.com", groups: ["site-readers"] };
    const req = reqFor("/members/x", {
      headers: {
        "x-auth-name": "spoof",
        "x-auth-roles": "admin",
      },
    });
    await forwardToOrigin(req, session, "protected", config);
    expect(seen.headers.get("x-auth-name")).toBeNull();
    expect(seen.headers.get("x-auth-roles")).toBeNull();
    // Gate-managed headers must still reach origin.
    expect(seen.headers.get("x-auth-subject")).toBe("user-123");
    expect(seen.headers.get("x-auth-email")).toBe("u@example.com");
    expect(seen.headers.get("x-auth-groups")).toBe("site-readers");
  });

  it("C1c pushInvalidation:false: inbound x-push-invalidation header is stripped", async () => {
    const noInvalidationConfig = { ...config, pushInvalidation: false };
    const req = reqFor("/blog/post", {
      headers: { "x-push-invalidation": "enabled" },
    });
    await forwardToOrigin(req, null, "public", noInvalidationConfig);
    expect(seen.headers.get("x-push-invalidation")).toBeNull();
  });
});

describe("forwardToOrigin", () => {
  it("P3 forwards to the EDS origin with x-auth-* and strips the cookie", async () => {
    const session = { sub: "user-123", email: "u@example.com", groups: ["site-readers"] };
    await forwardToOrigin(reqFor("/members/x", { cookie: "__gate_session=abc" }), session, "protected", config);
    expect(new URL(seen.url).hostname).toBe("main--mysite--myorg.aem.live");
    expect(seen.headers.get("cookie")).toBeNull();
    expect(seen.headers.get("x-auth-subject")).toBe("user-123");
    expect(seen.headers.get("x-auth-email")).toBe("u@example.com");
    expect(seen.headers.get("x-auth-groups")).toBe("site-readers");
    expect(seen.headers.get("x-forwarded-host")).toBe("www.example.com");
    expect(seen.headers.get("x-push-invalidation")).toBe("enabled");
  });

  it("protected/secured responses are rewritten to private, no-store", async () => {
    const res = await forwardToOrigin(reqFor("/api/orders"), { sub: "x", groups: [] }, "secured", config);
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    expect(res.headers.get("age")).toBeNull();
  });

  it("public responses preserve origin caching and inject no identity", async () => {
    const res = await forwardToOrigin(reqFor("/blog/post"), null, "public", config);
    expect(res.headers.get("cache-control")).toBe("public, max-age=3600");
    expect(seen.headers.get("x-auth-subject")).toBeNull();
  });
});
