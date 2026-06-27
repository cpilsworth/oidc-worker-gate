import { afterEach, describe, expect, it, vi } from "vitest";
import { handlePublisherRequest } from "../src/publisher-worker.js";
import { policyStatusKey } from "../src/policy-publisher.js";
import { policyCacheKey, verifyPolicyEnvelope } from "../src/policy-snapshot.js";

const siteId = "cpilsworth/authz";
const policyHmacKey = "policy-hmac-key-at-least-32-bytes-long!!";

function env(overrides = {}) {
  return {
    POLICY_HMAC_KEY: policyHmacKey,
    PUBLISHER_SITES: JSON.stringify({
      [siteId]: {
        audience_map: {
          medical: ["medical"],
          secure: ["secure"],
          "market-access": ["market-access"],
        },
      },
    }),
    DA_BASE_URL: "https://da.test",
    OIDC_CACHE: memoryKv(),
    ...overrides,
  };
}

function memoryKv() {
  const values = new Map();
  return {
    values,
    get: (key) => values.get(key) || null,
    put: (key, value) => values.set(key, value),
  };
}

function req(body, headers = {}) {
  return new Request("https://publisher.example.com/", {
    method: "POST",
    headers: {
      authorization: "Bearer da-token",
      "content-type": "application/json",
      ...headers,
    },
    body: JSON.stringify(body),
  });
}

function options(headers = {}) {
  return new Request("https://publisher.example.com/", {
    method: "OPTIONS",
    headers,
  });
}

function mockDa(rows, status = 200) {
  vi.stubGlobal("fetch", vi.fn(async (url, init) => {
    return new Response(JSON.stringify({ data: rows, source_version: "da-v1", url, auth: init.headers.authorization }), {
      status,
      statusText: status === 200 ? "OK" : "Nope",
      headers: { "content-type": "application/json" },
    });
  }));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("publisher worker", () => {
  it("answers browser preflight for allowed DA origins", async () => {
    const res = await handlePublisherRequest(options({
      origin: "https://main--authz--cpilsworth.aem.live",
      "access-control-request-method": "POST",
      "access-control-request-headers": "authorization,content-type,accept",
    }), env());

    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe("https://main--authz--cpilsworth.aem.live");
    expect(res.headers.get("access-control-allow-methods")).toBe("POST, OPTIONS");
    expect(res.headers.get("access-control-allow-headers")).toBe("Authorization, Content-Type, Accept");
    expect(res.headers.get("access-control-max-age")).toBe("86400");
    expect(res.headers.get("vary")).toBe("Origin");
  });

  it("does not grant credentialed CORS to unknown origins", async () => {
    const res = await handlePublisherRequest(options({ origin: "https://example.com" }), env());
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe("null");
  });

  it("publishes an allow-listed site from DA source", async () => {
    mockDa([{ path: "/members/**", tier: "protected", audience: "medical" }]);
    const e = env();

    const res = await handlePublisherRequest(req({ site_id: siteId }, {
      origin: "https://da.live",
    }), e);
    expect(res.status).toBe(200);
    expect(res.headers.get("access-control-allow-origin")).toBe("https://da.live");
    await expect(res.json()).resolves.toMatchObject({
      status: "published",
      site_id: siteId,
      version: "da-v1",
      rules: 1,
    });

    expect(fetch).toHaveBeenCalledWith("https://da.test/cpilsworth/authz/", {
      headers: { authorization: "Bearer da-token", accept: "application/json" },
    });
    const envelope = JSON.parse(await e.OIDC_CACHE.get(policyCacheKey(siteId)));
    await expect(verifyPolicyEnvelope(envelope, { policySiteId: siteId, policyHmacKey }))
      .resolves.toEqual(envelope.payload);
    expect(JSON.parse(await e.OIDC_CACHE.get(policyStatusKey(siteId))).last_success).toBeTruthy();
  });

  it("accepts org and site event fields", async () => {
    mockDa([{ path: "/members/**", tier: "protected", audience: "medical" }]);
    const res = await handlePublisherRequest(req({ org: "cpilsworth", site: "authz" }), env());
    expect(res.status).toBe(200);
  });

  it("accepts market-access as a configured audience", async () => {
    mockDa([{ path: "/market/**", tier: "protected", audience: "market-access" }]);
    const e = env();

    const res = await handlePublisherRequest(req({ site_id: siteId }), e);
    expect(res.status).toBe(200);

    const envelope = JSON.parse(await e.OIDC_CACHE.get(policyCacheKey(siteId)));
    expect(envelope.payload.rules).toEqual([
      { path: "/market/**", tier: "protected", audience: ["market-access"] },
    ]);
  });

  it("rejects missing DA token", async () => {
    const res = await handlePublisherRequest(req({ site_id: siteId }, {
      authorization: "",
      origin: "https://main--authz--cpilsworth.aem.page",
    }), env());
    expect(res.status).toBe(401);
    expect(res.headers.get("access-control-allow-origin")).toBe("https://main--authz--cpilsworth.aem.page");
    await expect(res.json()).resolves.toMatchObject({ error: "missing_da_token" });
  });

  it("rejects sites outside the allow-list", async () => {
    const res = await handlePublisherRequest(req({ site_id: "cpilsworth/other" }), env());
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toMatchObject({ error: "site_not_allowed" });
  });

  it("writes failure status but no current policy when validation fails", async () => {
    mockDa([{ path: "/members/**", tier: "protected", audience: "typo" }]);
    const e = env();

    const res = await handlePublisherRequest(req({ site_id: siteId }), e);
    expect(res.status).toBe(422);
    await expect(res.json()).resolves.toMatchObject({
      status: "validation_failed",
      errors: [{ row: 2, field: "audience", message: "unknown audience: typo" }],
    });
    expect(await e.OIDC_CACHE.get(policyCacheKey(siteId))).toBeNull();
    expect(JSON.parse(await e.OIDC_CACHE.get(policyStatusKey(siteId))).last_failure).toBeTruthy();
  });

  it("returns a bad-gateway response when DA cannot be read", async () => {
    mockDa([], 403);
    const res = await handlePublisherRequest(req({ site_id: siteId }), env());
    expect(res.status).toBe(502);
    await expect(res.json()).resolves.toMatchObject({
      error: "da_fetch_failed",
      da_url: "https://da.test/cpilsworth/authz/",
    });
  });

  it("allows only POST", async () => {
    const res = await handlePublisherRequest(new Request("https://publisher.example.com/"), env());
    expect(res.status).toBe(405);
    expect(res.headers.get("access-control-allow-origin")).toBe("null");
  });
});
