import { describe, it, expect } from "vitest";
import { normalizePath } from "../src/path.js";

describe("normalizePath (H1)", () => {
  it("passes through an already-canonical path", () => {
    expect(normalizePath("/members/x")).toEqual({ ok: true, path: "/members/x" });
    expect(normalizePath("/")).toEqual({ ok: true, path: "/" });
  });

  it("collapses duplicate slashes", () => {
    expect(normalizePath("//members//x").path).toBe("/members/x");
    expect(normalizePath("///").path).toBe("/");
  });

  it("resolves . and .. segments and clamps at the root", () => {
    expect(normalizePath("/a/./b").path).toBe("/a/b");
    expect(normalizePath("/a/b/../c").path).toBe("/a/c");
    expect(normalizePath("/../../a").path).toBe("/a");
  });

  it("percent-decodes non-separator escapes before classifying", () => {
    expect(normalizePath("/%70rotected").path).toBe("/protected");
    expect(normalizePath("/%6d%65%6d%62%65%72%73/x").path).toBe("/members/x");
  });

  it("resolves encoded dot-segments that a glob would otherwise miss", () => {
    // The classic bypass: would match a public /blog/** rule raw, but is really /members/secret.
    expect(normalizePath("/blog/%2e%2e/members/secret").path).toBe("/members/secret");
  });

  it("rejects encoded path separators", () => {
    expect(normalizePath("/blog/..%2fmembers").ok).toBe(false);
    expect(normalizePath("/a%2Fb").ok).toBe(false);
    expect(normalizePath("/a%5cb").ok).toBe(false);
  });

  it("rejects literal backslashes", () => {
    expect(normalizePath("/a\\b").ok).toBe(false);
  });

  it("rejects malformed percent-encoding", () => {
    expect(normalizePath("/a%zz").ok).toBe(false);
    expect(normalizePath("/a%").ok).toBe(false);
  });

  it("rejects an empty/invalid input", () => {
    expect(normalizePath("").ok).toBe(false);
    expect(normalizePath(undefined).ok).toBe(false);
  });

  it("preserves a trailing slash (origins may treat /a and /a/ differently)", () => {
    expect(normalizePath("/members/").path).toBe("/members/");
    expect(normalizePath("/members//").path).toBe("/members/");
  });
});
