import { describe, it, expect } from "vitest";
import { classify, isAuthorized, matchesAny } from "../src/policy.js";

const policy = {
  rules: [
    { path: "/", tier: "public" },
    { path: "/blog/**", tier: "public" },
    { path: "/media_*", tier: "public" },
    { path: "/nav.plain.html", tier: "public" },
    { path: "/members/**", tier: "protected", audience: ["site-readers"] },
    { path: "/members/admin/**", tier: "protected", audience: ["admins"] },
    { path: "/api/*", tier: "secured", audience: ["site-readers"] },
  ],
  default_tier: "protected",
};

describe("classify", () => {
  it("exact root match is public", () => {
    expect(classify("/", policy)).toEqual({ tier: "public", audience: undefined });
  });
  it("prefix globs match", () => {
    expect(classify("/blog/2026/post", policy).tier).toBe("public");
    expect(classify("/media_abc123.png", policy).tier).toBe("public");
    expect(classify("/nav.plain.html", policy).tier).toBe("public");
  });
  it("single-star globs do not cross path separators", () => {
    expect(classify("/api/orders", policy)).toEqual({ tier: "secured", audience: ["site-readers"] });
    expect(classify("/api/orders/1", policy)).toEqual({ tier: "protected", audience: undefined });
  });
  it("terminal recursive globs include the folder itself", () => {
    expect(classify("/members", policy)).toEqual({ tier: "protected", audience: ["site-readers"] });
    expect(classify("/members/", policy)).toEqual({ tier: "protected", audience: ["site-readers"] });
  });
  it("most-specific rule wins (longer literal prefix)", () => {
    expect(classify("/members/x", policy)).toEqual({ tier: "protected", audience: ["site-readers"] });
    expect(classify("/members/admin/y", policy)).toEqual({ tier: "protected", audience: ["admins"] });
  });
  it("secured tier carries its audience", () => {
    expect(classify("/api/orders", policy)).toEqual({ tier: "secured", audience: ["site-readers"] });
  });
  it("unmatched path falls to default_tier with no audience", () => {
    expect(classify("/totally/new/route", policy)).toEqual({ tier: "protected", audience: undefined });
  });
});

describe("matchesAny (worker-managed paths, S4)", () => {
  const patterns = ["/.auth/**", "/scripts/**", "/media_*", "/robots.txt"];
  it("matches recursive, single-star and exact patterns", () => {
    expect(matchesAny(patterns, "/.auth/callback")).toBe(true);
    expect(matchesAny(patterns, "/scripts/app.js")).toBe(true);
    expect(matchesAny(patterns, "/media_abc.png")).toBe(true);
    expect(matchesAny(patterns, "/robots.txt")).toBe(true);
  });
  it("does not match unrelated paths and tolerates non-arrays", () => {
    expect(matchesAny(patterns, "/members/x")).toBe(false);
    expect(matchesAny(undefined, "/x")).toBe(false);
  });
});

describe("isAuthorized", () => {
  it("no audience required → any authenticated session passes", () => {
    expect(isAuthorized({ groups: [] }, undefined)).toBe(true);
    expect(isAuthorized({ groups: ["x"] }, [])).toBe(true);
  });
  it("group intersection decides authorization", () => {
    expect(isAuthorized({ groups: ["site-readers"] }, ["site-readers"])).toBe(true);
    expect(isAuthorized({ groups: ["other"] }, ["site-readers"])).toBe(false);
    expect(isAuthorized({}, ["site-readers"])).toBe(false);
  });
});
