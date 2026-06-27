#!/usr/bin/env node
import process from "node:process";
import { policyCacheKey } from "../src/policy-snapshot.js";
import { policyStatusKey } from "../src/policy-publisher.js";
import { loadDotEnv } from "./env.js";

main().catch((err) => {
  console.error(JSON.stringify({ level: "error", message: err.message }));
  process.exit(1);
});

async function main() {
  await loadDotEnv();
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printUsage();
    return;
  }

  const siteId = args.site || process.env.POLICY_SITE_ID;
  const accountId = args["cf-account-id"] || process.env.CLOUDFLARE_ACCOUNT_ID;
  const namespaceId = args["kv-namespace-id"] || process.env.KV_NAMESPACE_ID;
  const token = args["cf-api-token"] || process.env.CLOUDFLARE_API_TOKEN;
  if (!siteId) throw new Error("--site or POLICY_SITE_ID is required");
  if (!accountId || !namespaceId || !token) {
    throw new Error("Cloudflare KV read requires CLOUDFLARE_ACCOUNT_ID, KV_NAMESPACE_ID, and CLOUDFLARE_API_TOKEN");
  }

  const status = await readKvJson({ accountId, namespaceId, token }, policyStatusKey(siteId));
  const out = {
    site_id: siteId,
    status,
  };

  if (args.current) {
    const current = await readKvJson({ accountId, namespaceId, token }, policyCacheKey(siteId));
    out.current = summarizePolicy(current);
  }

  console.log(JSON.stringify(out, null, args.pretty ? 2 : 0));
}

async function readKvJson(config, key) {
  const value = await readKv(config, key);
  if (value === null) return null;
  return JSON.parse(value);
}

async function readKv({ accountId, namespaceId, token }, key) {
  const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/values/${encodeURIComponent(key)}`;
  const res = await fetch(url, {
    headers: { authorization: `Bearer ${token}`, accept: "application/json" },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`KV read failed for ${key}: ${res.status} ${res.statusText}`);
  return res.text();
}

function summarizePolicy(envelope) {
  if (!envelope?.payload) return envelope;
  return {
    schema_version: envelope.payload.schema_version,
    site_id: envelope.payload.site_id,
    version: envelope.payload.version,
    published_at: envelope.payload.published_at,
    rules: envelope.payload.rules?.length || 0,
    ignored_rules: envelope.payload.ignored_rules?.length || 0,
    signed: typeof envelope.signature === "string" && envelope.signature.length > 0,
  };
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) throw new Error(`unexpected argument: ${arg}`);
    const key = arg.slice(2);
    if (key === "help" || key === "pretty" || key === "current") {
      out[key] = true;
      continue;
    }
    const value = argv[++i];
    if (!value) throw new Error(`missing value for --${key}`);
    out[key] = value;
  }
  return out;
}

function printUsage() {
  console.log(`Usage:
  npm run policy-status -- --site cpilsworth/authz --current --pretty

Environment alternatives:
  POLICY_SITE_ID=cpilsworth/authz
  CLOUDFLARE_ACCOUNT_ID=<account-id>
  KV_NAMESPACE_ID=<kv-namespace-id>
  CLOUDFLARE_API_TOKEN=<api-token>

Options:
  --current  Also read and summarize policy:current:<site-id>.
  --pretty   Pretty-print JSON output.
`);
}
