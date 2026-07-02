import { matchGlob, specificity } from "./policy.js";
import { policyCacheKey, signPolicyPayload } from "./policy-snapshot.js";
import { isRecord } from "./util.js";

const KNOWN_COLUMNS = new Set(["path", "tier", "audience", "description"]);
const TIERS = new Set(["public", "protected", "secured"]);

export function compilePolicyRows(rows, options) {
  const {
    siteId,
    audienceMap = {},
    workerManagedPaths = [],
    sourceVersion,
    now = new Date(),
  } = options;
  const rules = [];
  const ignored_rules = [];
  const warnings = [];
  const errors = [];
  const knownAudiences = new Set(Object.keys(audienceMap));

  rows.forEach((row, index) => {
    const rowNumber = index + 2; // Header row is line 1 in author-facing sheets.
    if (!isRecord(row)) {
      errors.push({ row: rowNumber, field: "row", message: "row must be an object" });
      return;
    }
    if (isBlankRow(row)) return;

    for (const key of Object.keys(row)) {
      if (!KNOWN_COLUMNS.has(key)) {
        warnings.push({ row: rowNumber, field: key, message: "unknown column ignored" });
      }
    }

    const path = stringValue(row.path).trim();
    const tier = stringValue(row.tier).trim().toLowerCase();
    const audience = parseAudience(row.audience);
    const hasAnyEnforcementValue = path || tier || audience.length > 0;

    if (!path || !tier) {
      if (hasAnyEnforcementValue) {
        errors.push({ row: rowNumber, field: !path ? "path" : "tier", message: "partial policy row" });
      }
      return;
    }

    if (!path.startsWith("/")) errors.push({ row: rowNumber, field: "path", message: "path must start with /" });
    if (path.includes("?") || path.includes("#"))
      errors.push({ row: rowNumber, field: "path", message: "path must not contain query or fragment" });
    if (!TIERS.has(tier)) errors.push({ row: rowNumber, field: "tier", message: `invalid tier: ${tier}` });
    if (tier === "public" && audience.length > 0)
      errors.push({ row: rowNumber, field: "audience", message: "public rows must not specify audience" });
    // Deny-by-default guard (H2): a DA author must not be able to silently make
    // the whole site public. A site-wide `/**` public rule is rejected outright;
    // a top-level `/*` public rule is allowed but surfaced as a warning so the
    // breadth is never silent.
    if (tier === "public" && path === "/**")
      errors.push({ row: rowNumber, field: "path", message: "public /** would expose the entire site; scope public paths explicitly" });
    else if (tier === "public" && path === "/*")
      warnings.push({ row: rowNumber, field: "path", message: "public /* exposes all top-level paths" });
    if ((tier === "protected" || tier === "secured") && audience.length === 0)
      warnings.push({ row: rowNumber, field: "audience", message: `${tier} row allows any authenticated user` });

    for (const value of audience) {
      if (!knownAudiences.has(value)) {
        errors.push({ row: rowNumber, field: "audience", message: `unknown audience: ${value}` });
      }
    }

    if (errors.some((err) => err.row === rowNumber)) return;

    const rule = { path, tier };
    if (audience.length > 0) rule.audience = audience;

    const reserved = workerManagedPaths.find((pattern) => patternsOverlap(path, pattern));
    if (reserved) {
      ignored_rules.push({ row: rowNumber, path, reason: "reserved_path", reserved_path: reserved });
      return;
    }

    rules.push({ ...rule, row: rowNumber });
  });

  validateEqualSpecificityOverlaps(rules, errors);

  const payload = {
    schema_version: 1,
    site_id: siteId,
    version: sourceVersion || now.toISOString(),
    published_at: now.toISOString(),
    rules: rules.map(({ row, ...rule }) => rule),
    ignored_rules,
  };

  return { payload, warnings, errors };
}

export async function buildSignedPolicyEnvelope(rows, options) {
  const result = compilePolicyRows(rows, options);
  if (result.errors.length > 0) return { ...result, envelope: null };
  return {
    ...result,
    envelope: {
      payload: result.payload,
      signature: await signPolicyPayload(result.payload, options.policyHmacKey),
    },
  };
}

export async function publishPolicyRows(rows, options) {
  const result = await buildSignedPolicyEnvelope(rows, options);
  const status = buildStatus(result, options);

  if (result.errors.length > 0) {
    await options.kv.put(policyStatusKey(options.siteId), JSON.stringify(status));
    return { ...result, status, wroteCurrent: false };
  }

  const currentKey = policyCacheKey(options.siteId);
  await options.kv.put(currentKey, JSON.stringify(result.envelope));
  await options.kv.put(policyVersionKey(options.siteId, result.payload.version), JSON.stringify(result.envelope));
  await options.kv.put(policyStatusKey(options.siteId), JSON.stringify(status));
  return { ...result, status, wroteCurrent: true };
}

export function extractRowsFromDaDocument(document) {
  if (Array.isArray(document)) return document;
  if (!isRecord(document)) throw new Error("DA policy document must be an object or array");

  const accessControl = document["access-control"];
  if (Array.isArray(accessControl)) return accessControl;
  if (isRecord(accessControl) && Array.isArray(accessControl.data)) return accessControl.data;
  if (isRecord(accessControl) && Array.isArray(accessControl.rows)) return accessControl.rows;

  if (Array.isArray(document.data)) return document.data;
  if (Array.isArray(document.rows)) return document.rows;

  for (const value of Object.values(document)) {
    if (Array.isArray(value)) return value;
    if (isRecord(value) && Array.isArray(value.data)) return value.data;
    if (isRecord(value) && Array.isArray(value.rows)) return value.rows;
  }

  throw new Error("No policy rows found in DA document");
}

export function daAccessControlUrl(siteId, baseUrl = "https://admin.da.live/config") {
  const [org, site] = splitSiteId(siteId);
  return `${baseUrl.replace(/\/$/, "")}/${encodeURIComponent(org)}/${encodeURIComponent(site)}/`;
}

export function policyStatusKey(siteId) {
  return `policy:status:${siteId}`;
}

export function policyVersionKey(siteId, version) {
  return `policy:version:${siteId}:${version}`;
}

export function buildStatus(result, options) {
  const now = (options.now || new Date()).toISOString();
  if (result.errors.length > 0) {
    return {
      site_id: options.siteId,
      updated_at: now,
      source_version: options.sourceVersion || null,
      last_success: null,
      last_failure: now,
      errors: result.errors,
      warnings: result.warnings,
    };
  }
  return {
    site_id: options.siteId,
    updated_at: now,
    source_version: result.payload.version,
    last_success: now,
    last_failure: null,
    errors: [],
    warnings: result.warnings,
  };
}

function validateEqualSpecificityOverlaps(rules, errors) {
  for (let i = 0; i < rules.length; i++) {
    for (let j = i + 1; j < rules.length; j++) {
      if (specificity(rules[i].path) !== specificity(rules[j].path)) continue;
      if (!patternsOverlap(rules[i].path, rules[j].path)) continue;
      errors.push({
        row: rules[j].row,
        field: "path",
        message: `equal-specificity overlap with row ${rules[i].row}: ${rules[j].path}`,
      });
    }
  }
}

function patternsOverlap(a, b) {
  const samples = [...patternSamples(a), ...patternSamples(b)];
  return samples.some((sample) => matchGlob(a, sample) && matchGlob(b, sample));
}

function patternSamples(pattern) {
  const samples = new Set();
  samples.add(pattern.replaceAll("**", "x/y").replaceAll("*", "x"));
  samples.add(pattern.replaceAll("**", "x").replaceAll("*", "x"));
  if (pattern.endsWith("/**")) {
    const base = pattern.slice(0, -3);
    samples.add(base);
    samples.add(`${base}/`);
    samples.add(`${base}/x`);
  }
  return samples;
}

function parseAudience(value) {
  if (value == null) return [];
  return [...new Set(String(value).split(",").map((v) => v.trim()).filter(Boolean))];
}

function isBlankRow(row) {
  return [...KNOWN_COLUMNS].every((key) => stringValue(row[key]).trim() === "");
}

function stringValue(value) {
  return value == null ? "" : String(value);
}

function splitSiteId(siteId) {
  const parts = String(siteId || "").split("/");
  if (parts.length !== 2 || !parts[0] || !parts[1]) throw new Error("site ID must use org/site format");
  return parts;
}
