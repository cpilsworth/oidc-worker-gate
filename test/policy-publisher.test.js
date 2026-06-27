import { describe, it, expect } from "vitest";
import {
  compilePolicyRows,
  daAccessControlUrl,
  extractRowsFromDaDocument,
  policyStatusKey,
  publishPolicyRows,
} from "../src/policy-publisher.js";
import { policyCacheKey, verifyPolicyEnvelope } from "../src/policy-snapshot.js";

const siteId = "cpilsworth/j2retail";
const policyHmacKey = "policy-hmac-key-at-least-32-bytes-long!!";
const audienceMap = {
  medical: ["auth0:role:medical"],
  secure: ["auth0:role:secure"],
};
const workerManagedPaths = ["/.auth/**", "/media_*", "/nav.plain.html"];

function options(overrides = {}) {
  return {
    siteId,
    policyHmacKey,
    audienceMap,
    workerManagedPaths,
    now: new Date("2026-06-27T14:30:00.000Z"),
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

describe("policy publisher compiler", () => {
  it("normalizes valid rows and signs publishable payloads", () => {
    const result = compilePolicyRows([
      { path: "/members/**", tier: " Protected ", audience: "medical, secure, medical", description: "members" },
      { path: "/api/*", tier: "secured", audience: "secure" },
      { path: "", tier: "", audience: "", description: "" },
    ], options({ sourceVersion: "da-version-1" }));

    expect(result.errors).toEqual([]);
    expect(result.payload).toMatchObject({
      schema_version: 1,
      site_id: siteId,
      version: "da-version-1",
      published_at: "2026-06-27T14:30:00.000Z",
      rules: [
        { path: "/members/**", tier: "protected", audience: ["medical", "secure"] },
        { path: "/api/*", tier: "secured", audience: ["secure"] },
      ],
      ignored_rules: [],
    });
  });

  it("warns for unknown columns and empty non-public audience", () => {
    const result = compilePolicyRows([
      { path: "/members/**", tier: "protected", audience: "", owner: "team" },
    ], options());

    expect(result.errors).toEqual([]);
    expect(result.warnings).toEqual([
      { row: 2, field: "owner", message: "unknown column ignored" },
      { row: 2, field: "audience", message: "protected row allows any authenticated user" },
    ]);
  });

  it("rejects malformed rows", () => {
    const result = compilePolicyRows([
      { path: "members/**", tier: "protected", audience: "medical" },
      { path: "/public/**", tier: "public", audience: "medical" },
      { path: "/private/**", tier: "private", audience: "" },
      { path: "/unknown/**", tier: "protected", audience: "typo" },
      { path: "/with-query?x=1", tier: "protected", audience: "medical" },
      { path: "/partial/**", tier: "", audience: "" },
    ], options());

    expect(result.errors.map((err) => err.message)).toEqual([
      "path must start with /",
      "public rows must not specify audience",
      "invalid tier: private",
      "unknown audience: typo",
      "path must not contain query or fragment",
      "partial policy row",
    ]);
  });

  it("keeps reserved path overlaps out of enforced rules", () => {
    const result = compilePolicyRows([
      { path: "/media_*", tier: "protected", audience: "medical" },
      { path: "/members/**", tier: "protected", audience: "medical" },
    ], options());

    expect(result.errors).toEqual([]);
    expect(result.payload.rules).toEqual([
      { path: "/members/**", tier: "protected", audience: ["medical"] },
    ]);
    expect(result.payload.ignored_rules).toEqual([
      { row: 2, path: "/media_*", reason: "reserved_path", reserved_path: "/media_*" },
    ]);
  });

  it("rejects equal-specificity overlapping rules", () => {
    const result = compilePolicyRows([
      { path: "/members/*", tier: "protected", audience: "medical" },
      { path: "/members/**", tier: "protected", audience: "secure" },
    ], options());

    expect(result.errors).toEqual([
      { row: 3, field: "path", message: "equal-specificity overlap with row 2: /members/**" },
    ]);
  });

  it("extracts rows from common DA document shapes", () => {
    const rows = [{ path: "/members/**", tier: "protected" }];
    expect(extractRowsFromDaDocument(rows)).toBe(rows);
    expect(extractRowsFromDaDocument({ data: rows })).toBe(rows);
    expect(extractRowsFromDaDocument({ "access-control": { data: rows } })).toBe(rows);
    expect(extractRowsFromDaDocument({
      data: { data: [{}] },
      "access-control": { data: rows },
      ":names": ["data", "access-control"],
    })).toBe(rows);
  });

  it("derives the fixed DA access-control URL from site id", () => {
    expect(daAccessControlUrl("cpilsworth/j2retail"))
      .toBe("https://admin.da.live/config/cpilsworth/j2retail/");
  });

  it("writes current policy, version history, and status on successful publish", async () => {
    const kv = memoryKv();
    const result = await publishPolicyRows([
      { path: "/members/**", tier: "protected", audience: "medical" },
    ], options({ kv, sourceVersion: "da-version-1" }));

    expect(result.wroteCurrent).toBe(true);
    const envelope = JSON.parse(await kv.get(policyCacheKey(siteId)));
    await expect(verifyPolicyEnvelope(envelope, { policySiteId: siteId, policyHmacKey }))
      .resolves.toEqual(envelope.payload);
    expect(JSON.parse(await kv.get(policyStatusKey(siteId))).last_success).toBe("2026-06-27T14:30:00.000Z");
  });

  it("writes failure status without replacing current policy on validation failure", async () => {
    const kv = memoryKv();
    await kv.put(policyCacheKey(siteId), "existing");

    const result = await publishPolicyRows([
      { path: "/members/**", tier: "protected", audience: "typo" },
    ], options({ kv }));

    expect(result.wroteCurrent).toBe(false);
    expect(await kv.get(policyCacheKey(siteId))).toBe("existing");
    const status = JSON.parse(await kv.get(policyStatusKey(siteId)));
    expect(status.last_failure).toBe("2026-06-27T14:30:00.000Z");
    expect(status.errors[0].message).toBe("unknown audience: typo");
  });
});
