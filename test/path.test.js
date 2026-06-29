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

  it("resolves DOUBLE-encoded dot-segments (C-1: %252e survives one decode as a literal)", () => {
    // url.pathname keeps %252e; a single decode yields the literal segment %2e%2e, which a
    // glob sees as public /blog/**, yet new Request(originUrl) resolves to /members/secret.
    expect(normalizePath("/blog/%252e%252e/members/secret").path).toBe("/members/secret");
  });

  it("resolves TRIPLE-encoded dot-segments (decode must reach a fixpoint)", () => {
    expect(normalizePath("/blog/%25252e%25252e/members/secret").path).toBe("/members/secret");
  });

  it("canonical output is a fixpoint of the URL parser (gate and origin can never disagree)", () => {
    // The core C-1 guarantee: what we classify must equal what new Request(originUrl) resolves to.
    for (const input of [
      "/members/x", "/blog/%252e%252e/members/secret", "/%6d%65%6d%62%65%72%73/x",
      "/a/b/../c", "//members//x", "/members/", "/blog/café", "/a b",
    ]) {
      const r = normalizePath(input);
      expect(r.ok).toBe(true);
      expect(new URL("https://h" + r.path).pathname).toBe(r.path);
    }
  });

  it("re-encodes (does NOT over-reject) non-ASCII and space — structure is preserved", () => {
    // The security requirement is segment-structure agreement, not byte-identity, so a
    // legitimate non-ASCII/space slug must still be served (matching pre-fix behavior).
    expect(normalizePath("/blog/café").path).toBe("/blog/caf%C3%A9");
    expect(normalizePath("/blog/caf%C3%A9").path).toBe("/blog/caf%C3%A9");
    expect(normalizePath("/a b").path).toBe("/a%20b");
  });

  it("rejects ? / # and ASCII control chars that would diverge at the origin", () => {
    expect(normalizePath("/foo%23bar").ok).toBe(false); // decoded '#' starts a fragment at re-parse
    expect(normalizePath("/foo%3Fbar").ok).toBe(false); // decoded '?' starts a query
    expect(normalizePath("/foo%09bar").ok).toBe(false); // tab is stripped by the URL parser
    expect(normalizePath("/foo%00bar").ok).toBe(false); // NUL
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
