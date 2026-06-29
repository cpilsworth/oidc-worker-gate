import { describe, it, expect } from "vitest";
import { SESSION_COOKIE, mintSessionCookie, readSession, clearSessionCookie,
         mintStateCookie, readStateCookie, clearStateCookie,
         SESSION_KEY_LABEL, STATE_KEY_LABEL, idTokenKey } from "../src/session.js";
import { sign, deriveCookieKey } from "../src/cookies.js";
import { reqFor, getSetCookie } from "./helpers.js";

const config = {
  sessionKey: "test-hmac-key-at-least-32-bytes-long!!",
  sessionTtlSeconds: 3600,
  audienceMap: { "site-readers": ["site-readers"], admins: ["raw-admin"] },
};

// Sign test fixtures with the SAME per-purpose derived key the production code uses
// (M-4), so "missing required field" assertions exercise field validation rather
// than failing at the signature check.
async function signedSessionCookie(body) {
  const token = await sign(JSON.stringify(body), await deriveCookieKey(config.sessionKey, SESSION_KEY_LABEL));
  return `__Host-gate_session=${encodeURIComponent(token)}`;
}

async function signedLoginCookie(body) {
  const token = await sign(JSON.stringify(body), await deriveCookieKey(config.sessionKey, STATE_KEY_LABEL));
  return `__Host-gate_login=${encodeURIComponent(token)}`;
}

/** Minimal in-memory KV matching the kvGetFresh/kvPutWithTtl wire shape. */
function makeStubKv() {
  const store = new Map();
  return {
    async get(key, type) {
      const v = store.get(key);
      if (v == null) return null;
      return type === "json" ? JSON.parse(v) : v;
    },
    async put(key, val) { store.set(key, val); },
    async delete(key) { store.delete(key); },
  };
}

describe("session", () => {
  it("uses the project cookie name", () => { expect(SESSION_COOKIE).toBe("__Host-gate_session"); });

  it("mints then reads a valid session", async () => {
    const setCookie = await mintSessionCookie(
      { sub: "user-123", email: "u@example.com", name: "User", groups: ["site-readers"] }, config);
    const value = setCookie.match(/__Host-gate_session=([^;]*)/)[1];
    const req = reqFor("/members/x", { cookie: `__Host-gate_session=${value}` });
    const s = await readSession(req, config);
    expect(s.sub).toBe("user-123");
    expect(s.groups).toEqual(["site-readers"]);
    expect(s.email).toBeUndefined();
    expect(s.name).toBeUndefined();
  });

  it("stores normalized audiences and drops unmapped raw values", async () => {
    const setCookie = await mintSessionCookie(
      { sub: "user-123", groups: ["raw-admin", "unmapped"] }, config);
    const value = setCookie.match(/__Host-gate_session=([^;]*)/)[1];
    const s = await readSession(reqFor("/members/x", { cookie: `__Host-gate_session=${value}` }), config);
    expect(s.groups).toEqual(["admins"]);
  });

  it("H4 reads only the configured claim — no silent roles/namespaced fallback", async () => {
    // `roles` must NOT be consulted when the configured claim (default `groups`) is absent.
    const setCookie = await mintSessionCookie({ sub: "user-123", roles: ["raw-admin"] }, config);
    const value = setCookie.match(/__Host-gate_session=([^;]*)/)[1];
    const s = await readSession(reqFor("/m", { cookie: `__Host-gate_session=${value}` }), config);
    expect(s.groups).toEqual([]);
  });

  it("H4 honors a configured GROUPS_CLAIM and ignores the default `groups`", async () => {
    const c = { ...config, groupsClaim: "https://oidc.workers.dev/groups" };
    const setCookie = await mintSessionCookie(
      { sub: "user-123", "https://oidc.workers.dev/groups": ["raw-admin"], groups: ["site-readers"] }, c);
    const value = setCookie.match(/__Host-gate_session=([^;]*)/)[1];
    const s = await readSession(reqFor("/m", { cookie: `__Host-gate_session=${value}` }), c);
    expect(s.groups).toEqual(["admins"]); // namespaced claim → raw-admin→admins; plain `groups` ignored
  });

  it("returns null for an expired session", async () => {
    const expired = { ...config, sessionTtlSeconds: -10 };
    const setCookie = await mintSessionCookie({ sub: "x" }, expired);
    const value = setCookie.match(/__Host-gate_session=([^;]*)/)[1];
    const s = await readSession(reqFor("/m", { cookie: `__Host-gate_session=${value}` }), config);
    expect(s).toBeNull();
  });

  it("returns null for a tampered session", async () => {
    const setCookie = await mintSessionCookie({ sub: "x" }, config);
    const value = setCookie.match(/__Host-gate_session=([^;]*)/)[1];
    const tampered = value.slice(0, -2) + (value.endsWith("aa") ? "bb" : "aa");
    expect(await readSession(reqFor("/m", { cookie: `__Host-gate_session=${tampered}` }), config)).toBeNull();
  });

  it("returns null instead of throwing for malformed percent-encoded cookie values", async () => {
    await expect(readSession(reqFor("/m", { cookie: "__Host-gate_session=%" }), config))
      .resolves.toBeNull();
  });

  it("returns null instead of throwing for invalid base64 session tokens", async () => {
    await expect(readSession(reqFor("/m", { cookie: "__Host-gate_session=not-valid!!!" }), config))
      .resolves.toBeNull();
  });

  it("returns null instead of throwing for malformed login-state cookies", async () => {
    await expect(readStateCookie(reqFor("/.auth/callback", { cookie: "__Host-gate_login=%" }), config))
      .resolves.toBeNull();
    await expect(readStateCookie(reqFor("/.auth/callback", { cookie: "__Host-gate_login=garbage!!!" }), config))
      .resolves.toBeNull();
  });

  it("rejects signed session cookies with valid JSON but missing required fields", async () => {
    const now = Math.floor(Date.now() / 1000);
    const base = { sub: "user-123", iat: now, exp: now + 3600, groups: ["site-readers"] };

    await expect(readSession(reqFor("/m", { cookie: await signedSessionCookie({ ...base, sub: "" }) }), config))
      .resolves.toBeNull();
    await expect(readSession(reqFor("/m", { cookie: await signedSessionCookie({ iat: now, exp: now + 3600, groups: [] }) }), config))
      .resolves.toBeNull();
    await expect(readSession(reqFor("/m", { cookie: await signedSessionCookie({ sub: "x", exp: now + 3600, groups: [] }) }), config))
      .resolves.toBeNull();
    await expect(readSession(reqFor("/m", { cookie: await signedSessionCookie({ sub: "x", iat: now, groups: [] }) }), config))
      .resolves.toBeNull();
    await expect(readSession(reqFor("/m", { cookie: await signedSessionCookie({ sub: "x", iat: now, exp: now + 3600 }) }), config))
      .resolves.toBeNull();
    await expect(readSession(reqFor("/m", { cookie: await signedSessionCookie({ sub: "x", iat: now, exp: now + 3600, groups: "admins" }) }), config))
      .resolves.toBeNull();
    await expect(readSession(reqFor("/m", { cookie: await signedSessionCookie("not-an-object") }), config))
      .resolves.toBeNull();
  });

  it("rejects signed login-state cookies with valid JSON but missing required fields", async () => {
    const base = { state: "s", nonce: "n", verifier: "v", returnTo: "/members/x" };

    await expect(readStateCookie(reqFor("/.auth/callback", { cookie: await signedLoginCookie({ ...base, state: "" }) }), config))
      .resolves.toBeNull();
    await expect(readStateCookie(reqFor("/.auth/callback", { cookie: await signedLoginCookie({ state: "s", verifier: "v", returnTo: "/" }) }), config))
      .resolves.toBeNull();
    await expect(readStateCookie(reqFor("/.auth/callback", { cookie: await signedLoginCookie({ state: "s", nonce: "n", returnTo: "/" }) }), config))
      .resolves.toBeNull();
    await expect(readStateCookie(reqFor("/.auth/callback", { cookie: await signedLoginCookie({ state: "s", nonce: "n", verifier: "v" }) }), config))
      .resolves.toBeNull();
    await expect(readStateCookie(reqFor("/.auth/callback", { cookie: await signedLoginCookie([]) }), config))
      .resolves.toBeNull();
  });

  it("M-3 keeps the id_token in KV (only an opaque jti in the cookie, no PII)", async () => {
    const kv = makeStubKv();
    const cfg = { ...config, kv };
    const setCookie = await mintSessionCookie({ sub: "user-123", groups: ["site-readers"] }, cfg, "header.payload.signature");
    const value = setCookie.match(/__Host-gate_session=([^;]*)/)[1];
    const s = await readSession(reqFor("/members/x", { cookie: `__Host-gate_session=${value}` }), cfg);
    expect(typeof s.jti).toBe("string");
    expect(s.id_token).toBeUndefined();           // the raw token never enters the cookie
    const stored = await kv.get(idTokenKey(s.jti), "json");
    expect(stored.value).toBe("header.payload.signature"); // it lives server-side in KV instead
  });

  it("M-3 mints without a jti when no KV is bound (graceful, no id_token in cookie)", async () => {
    const setCookie = await mintSessionCookie({ sub: "user-123", groups: [] }, config, "an-id-token");
    const value = setCookie.match(/__Host-gate_session=([^;]*)/)[1];
    const s = await readSession(reqFor("/m", { cookie: `__Host-gate_session=${value}` }), config);
    expect(s.jti).toBeUndefined();
    expect(s.id_token).toBeUndefined();
  });

  it("M-4 session and login-state cookies use independent keys (no cross-purpose validation)", async () => {
    // A blob with a valid login-state shape, but signed with the SESSION key, must
    // NOT validate when read as a login-state cookie — domain separation in action.
    const stateShape = { state: "s", nonce: "n", verifier: "v", returnTo: "/" };
    const crossSigned = await sign(JSON.stringify(stateShape), await deriveCookieKey(config.sessionKey, SESSION_KEY_LABEL));
    const cookie = `__Host-gate_login=${encodeURIComponent(crossSigned)}`;
    expect(await readStateCookie(reqFor("/.auth/callback", { cookie }), config)).toBeNull();

    // And the genuine login-state key round-trips, proving the rejection is key-based.
    const ok = `__Host-gate_login=${encodeURIComponent(await sign(JSON.stringify(stateShape), await deriveCookieKey(config.sessionKey, STATE_KEY_LABEL)))}`;
    expect(await readStateCookie(reqFor("/.auth/callback", { cookie: ok }), config)).toMatchObject({ state: "s" });
  });

  it("state cookie round-trips and clears", async () => {
    const setCookie = await mintStateCookie({ state: "s", nonce: "n", verifier: "v", returnTo: "/members/x" }, config);
    expect(setCookie).toContain("__Host-gate_login=");
    const value = setCookie.match(/__Host-gate_login=([^;]*)/)[1];
    const saved = await readStateCookie(reqFor("/.auth/callback", { cookie: `__Host-gate_login=${value}` }), config);
    expect(saved.returnTo).toBe("/members/x");
    expect(clearStateCookie()).toContain("Max-Age=0");
    expect(clearSessionCookie()).toContain("Max-Age=0");
  });
});
