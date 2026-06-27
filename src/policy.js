/**
 * @typedef {Object} Config — see config.js loadConfig() for the full shape.
 */

// Compilation caches (S4). Building a RegExp per rule per request is wasteful on
// the hot path, so we compile each rule's matcher + specificity once and reuse
// it for every request that shares the same policy/pattern-array reference.
// config.js and policy-snapshot.js keep those references stable across requests
// in a warm isolate, so this memoizes across requests, not just within one.
const compiledPolicies = new WeakMap();
const compiledMatcherLists = new WeakMap();

/**
 * Resolve a request path to its tier and (optional) required audience using the
 * most-specific matching rule. "Most specific" = the rule whose pattern has the
 * longest literal prefix before any `*`; an exact (wildcard-free) pattern always
 * wins over a glob. Unmatched paths fall to `policy.default_tier`.
 * @returns {{ tier: string, audience: (string[]|undefined) }}
 */
export function classify(pathname, policy) {
  // Rules are pre-sorted by specificity (desc), so the first match is the best.
  for (const rule of compilePolicy(policy)) {
    if (rule.match(pathname)) return { tier: rule.tier, audience: rule.audience };
  }
  return { tier: policy.default_tier, audience: undefined };
}

/** True if `path` matches any pattern in `patterns` (used for worker-managed paths). */
export function matchesAny(patterns, path) {
  for (const match of compileMatcherList(patterns)) {
    if (match(path)) return true;
  }
  return false;
}

/** Authenticated-session authorization: empty/absent audience = any session OK. */
export function isAuthorized(session, audience) {
  if (!audience || audience.length === 0) return true;
  const groups = Array.isArray(session.groups) ? session.groups : [];
  return audience.some((a) => groups.includes(a));
}

export function specificity(pattern) {
  const star = pattern.indexOf("*");
  if (star === -1) return 1000 + pattern.length;   // exact patterns rank above any glob
  return pattern.slice(0, star).length;            // else longest literal prefix wins
}

export function matchGlob(pattern, path) {
  if (typeof pattern !== "string" || typeof path !== "string") return false;
  if (!pattern.includes("*")) return pattern === path;
  return patternToRegExp(pattern).test(path);
}

function compilePolicy(policy) {
  let compiled = compiledPolicies.get(policy);
  if (!compiled) {
    compiled = (policy.rules || [])
      .map((r) => ({ tier: r.tier, audience: r.audience, match: buildMatcher(r.path), _s: specificity(r.path) }))
      .sort((a, b) => b._s - a._s);
    compiledPolicies.set(policy, compiled);
  }
  return compiled;
}

function compileMatcherList(patterns) {
  if (!Array.isArray(patterns)) return [];
  let compiled = compiledMatcherLists.get(patterns);
  if (!compiled) {
    compiled = patterns.map(buildMatcher);
    compiledMatcherLists.set(patterns, compiled);
  }
  return compiled;
}

/** Precompile a single pattern into a `(path) => boolean` matcher. */
function buildMatcher(pattern) {
  if (typeof pattern !== "string") return () => false;
  if (!pattern.includes("*")) return (path) => path === pattern;
  const re = patternToRegExp(pattern);
  return (path) => typeof path === "string" && re.test(path);
}

function patternToRegExp(pattern) {
  if (pattern.endsWith("/**")) {
    const base = pattern.slice(0, -3);
    return new RegExp(`^${escapeRe(base)}(?:/.*)?/?$`);
  }

  let out = "^";
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch !== "*") {
      out += escapeRe(ch);
      continue;
    }

    if (pattern[i + 1] === "*") {
      out += ".*";
      i++;
    } else {
      out += "[^/]*";
    }
  }
  return new RegExp(out + "$");
}

function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
