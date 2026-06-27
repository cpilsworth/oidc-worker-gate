#!/usr/bin/env node
import fs from "node:fs/promises";
import process from "node:process";
import {
  buildSignedPolicyEnvelope,
  daAccessControlUrl,
  policyStatusKey,
  policyVersionKey,
  extractRowsFromDaDocument,
} from "../src/policy-publisher.js";
import { policyCacheKey } from "../src/policy-snapshot.js";
import { DEFAULT_WORKER_MANAGED_PATHS } from "../src/policy-defaults.js";
import { loadDotEnv } from "./env.js";

main().catch((err) => {
  console.error(JSON.stringify({ level: "error", message: err.message }));
  process.exit(1);
});

async function main() {
  await loadDotEnv();
  const args = parseArgs(process.argv.slice(2));
  const siteId = args.site || process.env.POLICY_SITE_ID;
  if (!siteId) throw new Error("--site or POLICY_SITE_ID is required");
  const policyHmacKey = args["policy-hmac-key"] || process.env.POLICY_HMAC_KEY;
  if (!policyHmacKey) throw new Error("POLICY_HMAC_KEY or --policy-hmac-key is required");

  const audienceMap = await readJsonArg(args["audience-map"] || process.env.AUDIENCE_MAP || "{}");
  const workerManagedPaths = args["worker-managed-paths"]
    ? await readJsonArg(args["worker-managed-paths"])
    : DEFAULT_WORKER_MANAGED_PATHS;
  const document = args.input
    ? JSON.parse(await fs.readFile(args.input, "utf8"))
    : await fetchDaPolicy(siteId, args);
  const rows = extractRowsFromDaDocument(document);

  const result = await buildSignedPolicyEnvelope(rows, {
    siteId,
    policyHmacKey,
    audienceMap,
    workerManagedPaths,
    sourceVersion: args["source-version"],
  });
  const status = buildStatus(siteId, result, args["source-version"]);

  for (const warning of result.warnings) {
    console.warn(JSON.stringify({ level: "warn", site_id: siteId, ...warning }));
  }
  for (const ignored of result.payload.ignored_rules) {
    console.warn(JSON.stringify({ level: "warn", site_id: siteId, ignored_rule: ignored }));
  }

  if (result.errors.length > 0) {
    for (const error of result.errors) {
      console.error(JSON.stringify({ level: "error", site_id: siteId, ...error }));
    }
    await maybeWriteStatus(args, siteId, status);
    process.exit(1);
  }

  if (args["dry-run"]) {
    console.log(JSON.stringify({ envelope: result.envelope, status }, null, 2));
    return;
  }

  await writeKv(args, policyCacheKey(siteId), JSON.stringify(result.envelope));
  await writeKv(args, policyVersionKey(siteId, result.payload.version), JSON.stringify(result.envelope));
  await writeKv(args, policyStatusKey(siteId), JSON.stringify(status));
  console.log(JSON.stringify({
    level: "info",
    message: "policy published",
    site_id: siteId,
    version: result.payload.version,
    rules: result.payload.rules.length,
    ignored_rules: result.payload.ignored_rules.length,
    warnings: result.warnings.length,
  }));
}

async function fetchDaPolicy(siteId, args) {
  const token = args["da-token"] || process.env.DA_TOKEN;
  if (!token) throw new Error("DA_TOKEN, --da-token, or --input is required");
  const url = daAccessControlUrl(siteId, args["da-base-url"] || process.env.DA_BASE_URL || "https://admin.da.live/config");
  const res = await fetch(url, { headers: { authorization: `Bearer ${token}`, accept: "application/json" } });
  if (!res.ok) throw new Error(`DA policy fetch failed: ${res.status} ${res.statusText}`);
  return res.json();
}

async function writeKv(args, key, value) {
  const accountId = args["cf-account-id"] || process.env.CLOUDFLARE_ACCOUNT_ID;
  const namespaceId = args["kv-namespace-id"] || process.env.KV_NAMESPACE_ID;
  const token = args["cf-api-token"] || process.env.CLOUDFLARE_API_TOKEN;
  if (!accountId || !namespaceId || !token) {
    throw new Error("Cloudflare KV write requires CLOUDFLARE_ACCOUNT_ID, KV_NAMESPACE_ID, and CLOUDFLARE_API_TOKEN");
  }

  const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/values/${encodeURIComponent(key)}`;
  const res = await fetch(url, {
    method: "PUT",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: value,
  });
  if (!res.ok) throw new Error(`KV write failed for ${key}: ${res.status} ${res.statusText}`);
}

async function maybeWriteStatus(args, siteId, status) {
  if (args["dry-run"]) return;
  try {
    await writeKv(args, policyStatusKey(siteId), JSON.stringify(status));
  } catch (err) {
    console.error(JSON.stringify({ level: "error", message: "failed to write policy status", reason: err.message }));
  }
}

function buildStatus(siteId, result, sourceVersion) {
  const now = new Date().toISOString();
  if (result.errors.length > 0) {
    return {
      site_id: siteId,
      updated_at: now,
      source_version: sourceVersion || null,
      last_success: null,
      last_failure: now,
      errors: result.errors,
      warnings: result.warnings,
    };
  }
  return {
    site_id: siteId,
    updated_at: now,
    source_version: result.payload.version,
    last_success: now,
    last_failure: null,
    errors: [],
    warnings: result.warnings,
  };
}

async function readJsonArg(value) {
  if (value.startsWith("@")) return JSON.parse(await fs.readFile(value.slice(1), "utf8"));
  return JSON.parse(value);
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) throw new Error(`unexpected argument: ${arg}`);
    const key = arg.slice(2);
    if (key === "dry-run") {
      out[key] = true;
      continue;
    }
    const value = argv[++i];
    if (!value) throw new Error(`missing value for --${key}`);
    out[key] = value;
  }
  return out;
}
