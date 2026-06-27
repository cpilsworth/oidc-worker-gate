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
    expect(c.workerManagedPaths).toContain("/media_*");
    expect(c.kv).toBe(env.OIDC_CACHE);
  });
  it("throws if a required secret is missing", () => {
    expect(() => loadConfig({ ...env, SESSION_HMAC_KEY: undefined })).toThrow(/SESSION_HMAC_KEY/);
  });
  it("allows required policy source mode", () => {
    expect(loadConfig({ ...env, POLICY_SOURCE: "required" }).policySource).toBe("required");
  });
  it("rejects invalid policy source values", () => {
    expect(() => loadConfig({ ...env, POLICY_SOURCE: "other" })).toThrow(/POLICY_SOURCE/);
  });
});
