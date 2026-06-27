/**
 * @typedef {Object} Config — see config.js loadConfig() for the full shape.
 */

/**
 * Resolve a request path to its tier and (optional) required audience using the
 * most-specific matching rule. "Most specific" = the rule whose pattern has the
 * longest literal prefix before any `*`; an exact (wildcard-free) pattern always
 * wins over a glob. Unmatched paths fall to `policy.default_tier`.
 * @returns {{ tier: string, audience: (string[]|undefined) }}
 */
export function classify(pathname, policy) {
  const matches = (policy.rules || []).filter((r) => matchGlob(r.path, pathname));
  if (matches.length === 0) return { tier: policy.default_tier, audience: undefined };
  matches.sort((a, b) => specificity(b.path) - specificity(a.path));
  const best = matches[0];
  return { tier: best.tier, audience: best.audience };
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
