import { describe, it, expect, beforeEach } from "vitest";
import { forwardToOrigin, fetchErrorPage } from "../src/origin.js";
import { errorPageResponse } from "../src/http.js";
import { normalizePath } from "../src/path.js";
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
    const session = { sub: "user-123", groups: ["site-readers"] };
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
    const session = { sub: "user-123", groups: ["site-readers"] };
    await forwardToOrigin(reqFor("/members/x", { cookie: "__Host-gate_session=abc" }), session, "protected", config);
    expect(new URL(seen.url).hostname).toBe("main--mysite--myorg.aem.live");
    expect(seen.headers.get("cookie")).toBeNull();
    expect(seen.headers.get("x-auth-subject")).toBe("user-123");
    expect(seen.headers.get("x-auth-groups")).toBe("site-readers");
    expect(seen.headers.get("x-forwarded-host")).toBe("www.example.com");
    expect(seen.headers.get("x-push-invalidation")).toBe("enabled");
  });

  it("C-1: the canonical path the gate classified is exactly what reaches the origin", async () => {
    // normalizePath resolves the double-encoded traversal to /members/secret; forwardToOrigin
    // must send that same resource to origin — no re-divergence at the URL-parser boundary.
    const canonical = normalizePath("/blog/%252e%252e/members/secret").path;
    expect(canonical).toBe("/members/secret");
    await forwardToOrigin(reqFor("/blog/%252e%252e/members/secret"), { sub: "x", groups: [] }, "protected", config, canonical);
    expect(new URL(seen.url).pathname).toBe("/members/secret");
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

  it("strips origin Set-Cookie entries for gate-owned cookie names", async () => {
    globalThis.fetch = async (input, init) => {
      const r = input instanceof Request ? input : new Request(input, init);
      seen = { url: r.url, headers: r.headers };
      return new Response("body", {
        headers: [
          ["set-cookie", "__Host-gate_session=attacker; Path=/"],
          ["set-cookie", "__Host-gate_login=attacker; Path=/"],
          ["set-cookie", "eds_pref=ok; Path=/"],
        ],
      });
    };

    const res = await forwardToOrigin(reqFor("/members/x"), { sub: "x", groups: [] }, "protected", config);
    const setCookies = res.headers.getSetCookie ? res.headers.getSetCookie() : [res.headers.get("set-cookie")];
    expect(setCookies.join("\n")).not.toContain("__Host-gate_session=");
    expect(setCookies.join("\n")).not.toContain("__Host-gate_login=");
    expect(setCookies.join("\n")).toContain("eds_pref=ok");
  });
});

describe("fetchErrorPage", () => {
  it("requests a bare GET /error/{code} with no cookie and no query string", async () => {
    globalThis.fetch = async (input, init) => {
      const r = input instanceof Request ? input : new Request(input, init);
      seen = { url: r.url, method: r.method, headers: r.headers };
      return new Response("<h1>denied</h1>", { headers: { "content-type": "text/html" } });
    };
    const res = await fetchErrorPage(config, 403);
    expect(res).not.toBeNull();
    const url = new URL(seen.url);
    expect(url.hostname).toBe("main--mysite--myorg.aem.live");
    expect(url.pathname).toBe("/error/403");
    expect(url.search).toBe(""); // no original path/query echoed back (H7)
    expect(seen.method).toBe("GET");
    expect(seen.headers.get("cookie")).toBeNull();
  });

  it("returns null when the origin lacks the page (non-2xx) so the caller falls back to JSON", async () => {
    globalThis.fetch = async () => new Response("not found", { status: 404 });
    expect(await fetchErrorPage(config, 403)).toBeNull();
  });

  it("returns null when the origin fetch throws", async () => {
    globalThis.fetch = async () => { throw new Error("network down"); };
    expect(await fetchErrorPage(config, 401)).toBeNull();
  });
});

describe("errorPageResponse", () => {
  it("forces the denial status onto the origin's 200 page and applies hardening headers", () => {
    const page = new Response("<h1>denied</h1>", { status: 200, headers: { "content-type": "text/html; charset=utf-8" } });
    const res = errorPageResponse(403, page);
    expect(res.status).toBe(403); // never the origin's 200
    expect(res.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("cache-control")).toBe("private, no-store");
  });

  it("adds the WWW-Authenticate challenge on 401 and never copies origin Set-Cookie", () => {
    const page = new Response("body", { status: 200, headers: { "set-cookie": "origin=1", "cache-control": "public, max-age=60" } });
    const res = errorPageResponse(401, page, { wwwAuthenticate: 'Bearer error="invalid_token"' });
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain("Bearer");
    expect(res.headers.get("cache-control")).toBe("private, no-store"); // not the origin's public cache
    expect(res.headers.get("set-cookie")).toBeNull();
  });

  it("surfaces the request id as x-request-id so a bodyless page is still correlatable", () => {
    const page = new Response("<h1>denied</h1>", { status: 200, headers: { "content-type": "text/html" } });
    const res = errorPageResponse(403, page, { requestId: "ray-abc123" });
    expect(res.headers.get("x-request-id")).toBe("ray-abc123");
  });
});
