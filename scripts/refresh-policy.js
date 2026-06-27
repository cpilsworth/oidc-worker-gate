#!/usr/bin/env node
import process from "node:process";
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
  const publisherUrl = args.url || process.env.POLICY_PUBLISHER_URL;
  const daToken = args["da-token"] || process.env.DA_TOKEN;
  if (!siteId) throw new Error("--site or POLICY_SITE_ID is required");
  if (!publisherUrl) throw new Error("--url or POLICY_PUBLISHER_URL is required");
  if (!daToken) throw new Error("--da-token or DA_TOKEN is required");

  const body = { site_id: siteId };
  if (args["source-version"]) body.source_version = args["source-version"];

  const res = await fetch(publisherUrl, {
    method: "POST",
    headers: {
      authorization: `Bearer ${daToken}`,
      "content-type": "application/json",
      accept: "application/json",
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    payload = { raw: text };
  }

  const out = {
    level: res.ok ? "info" : "error",
    status: res.status,
    publisher_url: publisherUrl,
    site_id: siteId,
    response: payload,
  };
  const line = JSON.stringify(out, null, args.pretty ? 2 : 0);
  if (res.ok) console.log(line);
  else {
    console.error(line);
    process.exit(1);
  }
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) throw new Error(`unexpected argument: ${arg}`);
    const key = arg.slice(2);
    if (key === "help" || key === "pretty") {
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
  npm run refresh-policy -- --site cpilsworth/authz --url https://<publisher-worker> --da-token <token>

Environment alternatives:
  POLICY_SITE_ID=cpilsworth/authz
  POLICY_PUBLISHER_URL=https://<publisher-worker>
  DA_TOKEN=<token>

Options:
  --source-version <value>  Optional source version to include in the event.
  --pretty                 Pretty-print JSON output.
`);
}
