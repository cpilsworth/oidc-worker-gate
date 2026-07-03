import { describe, it, expect } from "vitest";
import { loadConfig } from "../src/config.js";

const env = {
  OIDC_ISSUER: "https://op.test/",       // trailing slash must be trimmed
  CLIENT_ID: "test-client",
  OIDC_CLIENT_SECRET: "secret",
  REDIRECT_URI: "https://www.example.com/.auth/callback",
  SCOPES: "openid profile email groups",
  SESSION_TTL: "3600",
  ORIGIN_HOSTNAME: "main--mysite--myorg.aem.live",
  FORWARDED_HOST: "www.example.com",
  PUSH_INVALIDATION: "enabled",
  SESSION_HMAC_KEY: "test-hmac-key-at-least-32-bytes-long!!",
  ROUTES: '{"callback":"/.auth/callback","logout":"/.auth/logout"}',
  ACCESS_POLICY: '{"rules":[{"path":"/","tier":"public"}],"default_tier":"protected"}',
  POLICY_SOURCE: "auto",
  POLICY_SITE_ID: "cpilsworth/j2retail",
  POLICY_HMAC_KEY: "policy-hmac-key-at-least-32-bytes-long!!",
  AUDIENCE_MAP: '{"medical":["auth0:role:medical"]}',
  OIDC_CACHE: { fake: "kv" },
};

describe("loadConfig", () => {
  it("maps env vars + secrets into a Config", () => {
    const c = loadConfig(env);
    expect(c.issuer).toBe("https://op.test");            // trimmed
    expect(c.clientId).toBe("test-client");
    expect(c.clientSecret).toBe("secret");
    expect(c.sessionTtlSeconds).toBe(3600);
    expect(c.pushInvalidation).toBe(true);
    expect(c.routes.callback).toBe("/.auth/callback");
    expect(c.policy.default_tier).toBe("protected");
    expect(c.policy.rules[0]).toEqual({ path: "/", tier: "public" });
    expect(c.policySource).toBe("auto");
    expect(c.policySiteId).toBe("cpilsworth/j2retail");
    expect(c.policyHmacKey).toBe("policy-hmac-key-at-least-32-bytes-long!!");
    expect(c.audienceMap).toEqual({ medical: ["auth0:role:medical"] });
    expect(c.groupsClaim).toBe("groups"); // default single claim
    expect(c.workerManagedPaths).toContain("/media_*");
    expect(c.kv).toBe(env.OIDC_CACHE);
  });
  it("throws if a required secret is missing", () => {
    expect(() => loadConfig({ ...env, SESSION_HMAC_KEY: undefined })).toThrow(/SESSION_HMAC_KEY/);
  });
  it("throws if a required var is missing", () => {
    for (const key of ["OIDC_ISSUER", "CLIENT_ID", "REDIRECT_URI", "ORIGIN_HOSTNAME", "FORWARDED_HOST"]) {
      expect(() => loadConfig({ ...env, [key]: undefined }), key).toThrow(new RegExp(key));
    }
  });
  it("allows required policy source mode", () => {
    expect(loadConfig({ ...env, POLICY_SOURCE: "required" }).policySource).toBe("required");
  });
  it("rejects invalid policy source values", () => {
    expect(() => loadConfig({ ...env, POLICY_SOURCE: "other" })).toThrow(/POLICY_SOURCE/);
  });

  it("H4 makes the groups claim configurable", () => {
    expect(loadConfig({ ...env, GROUPS_CLAIM: "https://oidc.workers.dev/groups" }).groupsClaim)
      .toBe("https://oidc.workers.dev/groups");
  });

  it("H6 rejects a SESSION_HMAC_KEY shorter than 32 bytes", () => {
    expect(() => loadConfig({ ...env, SESSION_HMAC_KEY: "too-short" })).toThrow(/SESSION_HMAC_KEY.*32/);
  });

  it("H6 rejects a POLICY_HMAC_KEY shorter than 32 bytes when set", () => {
    expect(() => loadConfig({ ...env, POLICY_HMAC_KEY: "short" })).toThrow(/POLICY_HMAC_KEY.*32/);
  });

  it("H6 allows an empty POLICY_HMAC_KEY (worker/auto modes without KV policy)", () => {
    expect(loadConfig({ ...env, POLICY_HMAC_KEY: "" }).policyHmacKey).toBe("");
  });

  it("H6 rejects a non-numeric SESSION_TTL (no NaN exp → no silent login loop)", () => {
    expect(() => loadConfig({ ...env, SESSION_TTL: "not-a-number" })).toThrow(/SESSION_TTL/);
  });

  it("H6 rejects a zero or negative SESSION_TTL", () => {
    expect(() => loadConfig({ ...env, SESSION_TTL: "0" })).toThrow(/SESSION_TTL/);
    expect(() => loadConfig({ ...env, SESSION_TTL: "-5" })).toThrow(/SESSION_TTL/);
  });

  it("H6 rejects non-numeric policy refresh/stale TTLs", () => {
    expect(() => loadConfig({ ...env, POLICY_REFRESH_TTL_SECONDS: "soon" })).toThrow(/POLICY_REFRESH_TTL_SECONDS/);
    expect(() => loadConfig({ ...env, POLICY_STALE_TTL_SECONDS: "later" })).toThrow(/POLICY_STALE_TTL_SECONDS/);
  });
});
