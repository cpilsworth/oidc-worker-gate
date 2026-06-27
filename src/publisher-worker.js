import {
  daAccessControlUrl,
  extractRowsFromDaDocument,
  publishPolicyRows,
} from "./policy-publisher.js";
import { DEFAULT_WORKER_MANAGED_PATHS } from "./policy-defaults.js";

const ALLOWED_CORS_ORIGINS = [
  /^https:\/\/([a-z0-9-]+--)?authz--cpilsworth\.aem\.(live|page)$/,
  /^https:\/\/da\.live$/,
];

export default {
  async fetch(request, env) {
    return handlePublisherRequest(request, env);
  },
};

export async function handlePublisherRequest(request, env) {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request) });
  if (request.method !== "POST") return json(request, { error: "method_not_allowed" }, 405);
  if (!env.OIDC_CACHE) return json(request, { error: "missing_kv_binding" }, 500);
  if (!env.POLICY_HMAC_KEY) return json(request, { error: "missing_policy_hmac_key" }, 500);

  const daToken = bearerToken(request.headers.get("authorization"));
  if (!daToken) return json(request, { error: "missing_da_token" }, 401);

  let event;
  try {
    event = await request.json();
  } catch {
    return json(request, { error: "invalid_json" }, 400);
  }

  let siteId;
  try {
    siteId = resolveSiteId(event);
  } catch (err) {
    return json(request, { error: "invalid_site", message: err.message }, 400);
  }

  const sites = loadSiteConfig(env);
  const siteConfig = sites[siteId];
  if (!siteConfig) return json(request, { error: "site_not_allowed", site_id: siteId }, 403);

  let document;
  try {
    document = await fetchDaPolicy(siteId, daToken, env.DA_BASE_URL);
  } catch (err) {
    return json(request, { error: "da_fetch_failed", site_id: siteId, da_url: err.daUrl || null, message: err.message }, 502);
  }

  let rows;
  try {
    rows = extractRowsFromDaDocument(document);
  } catch (err) {
    return json(request, { error: "invalid_da_policy_document", site_id: siteId, message: err.message }, 422);
  }

  const result = await publishPolicyRows(rows, {
    siteId,
    policyHmacKey: env.POLICY_HMAC_KEY,
    audienceMap: siteConfig.audience_map || {},
    workerManagedPaths: siteConfig.worker_managed_paths || DEFAULT_WORKER_MANAGED_PATHS,
    sourceVersion: event.source_version || document.source_version || document.version,
    kv: env.OIDC_CACHE,
  });

  logPublishResult(siteId, result);

  if (result.errors.length > 0) {
    return json(request, {
      status: "validation_failed",
      site_id: siteId,
      errors: result.errors,
      warnings: result.warnings,
      ignored_rules: result.payload.ignored_rules,
    }, 422);
  }

  return json(request, {
    status: "published",
    site_id: siteId,
    version: result.payload.version,
    rules: result.payload.rules.length,
    ignored_rules: result.payload.ignored_rules.length,
    warnings: result.warnings,
  });
}

async function fetchDaPolicy(siteId, daToken, baseUrl) {
  const url = daAccessControlUrl(siteId, baseUrl || "https://admin.da.live/config");
  const res = await fetch(url, {
    headers: { authorization: `Bearer ${daToken}`, accept: "application/json" },
  });
  if (!res.ok) {
    const err = new Error(`${res.status} ${res.statusText}`);
    err.daUrl = url;
    throw err;
  }
  return res.json();
}

function loadSiteConfig(env) {
  try {
    return JSON.parse(env.PUBLISHER_SITES || "{}");
  } catch {
    return {};
  }
}

function resolveSiteId(event) {
  if (typeof event.site_id === "string" && event.site_id) return event.site_id;
  if (typeof event.org === "string" && typeof event.site === "string" && event.org && event.site) {
    return `${event.org}/${event.site}`;
  }
  throw new Error("event must include site_id or org+site");
}

function bearerToken(header) {
  const match = /^Bearer\s+(.+)$/i.exec(header || "");
  return match ? match[1] : "";
}

function logPublishResult(siteId, result) {
  for (const warning of result.warnings) console.warn("policy publish warning", { site_id: siteId, ...warning });
  for (const ignored of result.payload.ignored_rules)
    console.warn("policy publish ignored rule", { site_id: siteId, ...ignored });
  if (result.errors.length > 0) {
    for (const error of result.errors) console.error("policy publish error", { site_id: siteId, ...error });
    return;
  }
  console.info("policy published", {
    site_id: siteId,
    version: result.payload.version,
    rules: result.payload.rules.length,
    ignored_rules: result.payload.ignored_rules.length,
    warnings: result.warnings.length,
  });
}

function corsHeaders(request) {
  const origin = request.headers.get("origin") || "";
  const allowed = ALLOWED_CORS_ORIGINS.some((pattern) => pattern.test(origin));
  return {
    "access-control-allow-origin": allowed ? origin : "null",
    vary: "Origin",
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-headers": "Authorization, Content-Type, Accept",
    "access-control-max-age": "86400",
  };
}

function json(request, body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "private, no-store",
      ...corsHeaders(request),
    },
  });
}
