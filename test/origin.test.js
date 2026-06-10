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
