/**
 * Canonicalize a request pathname before policy classification (H1).
 *
 * The matcher in policy.js classifies on the literal path. Without
 * canonicalization an attacker can smuggle a segment past a glob — e.g.
 * `/blog/%2e%2e/members/secret` matches a public `/blog/**` rule yet the origin
 * resolves it to the protected `/members/secret`. We close that gap by deriving
 * a single canonical form that the gate both classifies AND forwards, so the
 * gate and origin can never disagree about which resource was requested.
 *
 * Rules:
 *  - Reject encoded path separators (`%2F`, `%5C`) — never legitimate in an EDS
 *    path and the classic matcher-bypass vector.
 *  - Reject malformed percent-encoding and literal backslashes.
 *  - Percent-decode the remainder, collapse duplicate slashes, and resolve
 *    `.`/`..` segments (clamping `..` at the root).
 *
 * @param {string} rawPathname  typically `new URL(request.url).pathname`
 * @returns {{ ok: true, path: string } | { ok: false, reason: string }}
 */
export function normalizePath(rawPathname) {
  if (typeof rawPathname !== "string" || rawPathname.length === 0) {
    return { ok: false, reason: "empty path" };
  }

  // Encoded separators would change segment structure once decoded; refuse them
  // outright rather than try to reason about the decoded shape.
  if (/%2f/i.test(rawPathname) || /%5c/i.test(rawPathname)) {
    return { ok: false, reason: "encoded path separator" };
  }

  let decoded;
  try {
    decoded = decodeURIComponent(rawPathname);
  } catch {
    return { ok: false, reason: "malformed percent-encoding" };
  }

  // Many origins/browsers treat "\" as a separator; reject so the gate and
  // origin can never disagree about segment boundaries.
  if (decoded.includes("\\")) return { ok: false, reason: "backslash in path" };

  if (!decoded.startsWith("/")) decoded = "/" + decoded;
  const hadTrailingSlash = decoded.length > 1 && decoded.endsWith("/");

  const segments = [];
  for (const segment of decoded.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") { segments.pop(); continue; }
    segments.push(segment);
  }

  let path = "/" + segments.join("/");
  if (hadTrailingSlash && path !== "/") path += "/";
  return { ok: true, path };
}
