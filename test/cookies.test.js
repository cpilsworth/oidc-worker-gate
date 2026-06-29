import { describe, it, expect, beforeAll } from "vitest";
import { parseCookies, serializeCookie, sign, unsign, deriveCookieKey } from "../src/cookies.js";

const MASTER = "test-hmac-key-at-least-32-bytes-long!!";
let KEY, OTHER_KEY;
beforeAll(async () => {
  KEY = await deriveCookieKey(MASTER, "label-a");
  OTHER_KEY = await deriveCookieKey(MASTER, "label-b"); // same master, different purpose → different key
});

describe("cookies", () => {
  it("parses a cookie header into a map", () => {
    expect(parseCookies("a=1; b=two%20words")).toEqual({ a: "1", b: "two words" });
    expect(parseCookies(null)).toEqual({});
  });

  it("skips malformed percent-encoded values without throwing", () => {
    expect(parseCookies("__gate_session=%; good=1")).toEqual({ good: "1" });
  });
  it("serializes with security attributes by default", () => {
    const c = serializeCookie("__gate_session", "v", { maxAge: 60 });
    expect(c).toContain("__gate_session=v");
    expect(c).toContain("HttpOnly");
    expect(c).toContain("Secure");
    expect(c).toContain("SameSite=Lax");
    expect(c).toContain("Max-Age=60");
  });
  it("sign/unsign round-trips and rejects tampering and a different derived key", async () => {
    const token = await sign(JSON.stringify({ sub: "x" }), KEY);
    expect(await unsign(token, KEY)).toBe('{"sub":"x"}');
    expect(await unsign(token + "x", KEY)).toBeNull();
    expect(await unsign(token, OTHER_KEY)).toBeNull(); // domain separation: wrong-purpose key fails
  });

  it("unsign returns null for garbage tokens without throwing", async () => {
    await expect(unsign("not-valid-base64!!!", KEY)).resolves.toBeNull();
    await expect(unsign(".", KEY)).resolves.toBeNull();
    await expect(unsign("payload-only.", KEY)).resolves.toBeNull();
    await expect(unsign("", KEY)).resolves.toBeNull();
  });
});
