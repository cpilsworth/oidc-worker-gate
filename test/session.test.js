import { describe, it, expect } from "vitest";
import { SESSION_COOKIE, mintSessionCookie, readSession, clearSessionCookie,
         mintStateCookie, readStateCookie, clearStateCookie } from "../src/session.js";
import { reqFor, getSetCookie } from "./helpers.js";

const config = { sessionKey: "test-hmac-key-at-least-32-bytes-long!!", sessionTtlSeconds: 3600 };

describe("session", () => {
  it("uses the project cookie name", () => { expect(SESSION_COOKIE).toBe("__gate_session"); });

  it("mints then reads a valid session", async () => {
    const setCookie = await mintSessionCookie(
      { sub: "user-123", email: "u@example.com", groups: ["site-readers"] }, config);
    const value = setCookie.match(/__gate_session=([^;]*)/)[1];
    const req = reqFor("/members/x", { cookie: `__gate_session=${value}` });
    const s = await readSession(req, config);
    expect(s.sub).toBe("user-123");
    expect(s.groups).toEqual(["site-readers"]);
  });

  it("returns null for an expired session", async () => {
    const expired = { ...config, sessionTtlSeconds: -10 };
    const setCookie = await mintSessionCookie({ sub: "x" }, expired);
    const value = setCookie.match(/__gate_session=([^;]*)/)[1];
    const s = await readSession(reqFor("/m", { cookie: `__gate_session=${value}` }), config);
    expect(s).toBeNull();
  });

  it("returns null for a tampered session", async () => {
    const setCookie = await mintSessionCookie({ sub: "x" }, config);
    const value = setCookie.match(/__gate_session=([^;]*)/)[1];
    const tampered = value.slice(0, -2) + (value.endsWith("aa") ? "bb" : "aa");
    expect(await readSession(reqFor("/m", { cookie: `__gate_session=${tampered}` }), config)).toBeNull();
  });

  it("state cookie round-trips and clears", async () => {
    const setCookie = await mintStateCookie({ state: "s", nonce: "n", verifier: "v", returnTo: "/members/x" }, config);
    expect(setCookie).toContain("__gate_login=");
    const value = setCookie.match(/__gate_login=([^;]*)/)[1];
    const saved = await readStateCookie(reqFor("/.auth/callback", { cookie: `__gate_login=${value}` }), config);
    expect(saved.returnTo).toBe("/members/x");
    expect(clearStateCookie()).toContain("Max-Age=0");
    expect(clearSessionCookie()).toContain("Max-Age=0");
  });
});
