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
 *    path and the classic matcher-bypass vector. Checked on every decode pass.
 *  - Percent-decode to a FIXPOINT (C-1). A single decode leaves a double-encoded
 *    `%252e%252e` as the literal segment `%2e%2e`, which a glob treats as opaque
 *    yet the WHATWG URL parser (which resolves `%2e`/`%2e%2e` as dot-segments)
 *    collapses at the origin — so the gate would classify a different resource
 *    than it forwards. Decoding until stable closes that gap.
 *  - Reject malformed percent-encoding and literal backslashes.
 *  - Collapse duplicate slashes and resolve `.`/`..` (clamping `..` at the root).
 *  - Reject `?`/`#` and ASCII control chars: when the origin re-parses the
 *    forwarded URL these start a query/fragment (truncating the path) or are
 *    stripped, so they'd diverge from what we classified.
 *  - Re-encode the result to the URL-parser canonical form (space / non-ASCII
 *    become percent-escapes without changing segment structure). The value we
 *    classify is then byte-identical to what `new Request(originUrl)` resolves
 *    to — without over-rejecting legitimate non-ASCII slugs.
 *
 * @param {string} rawPathname  typically `new URL(request.url).pathname`
 * @returns {{ ok: true, path: string } | { ok: false, reason: string }}
 */
const MAX_DECODE_PASSES = 5;

export function normalizePath(rawPathname) {
  if (typeof rawPathname !== "string" || rawPathname.length === 0) {
    return { ok: false, reason: "empty path" };
  }

  let decoded = rawPathname;
  for (let pass = 0; ; pass++) {
    // Reject encoded separators on the STILL-ENCODED string, before decoding, so
    // a `%2f`/`%5c` (at any encoding depth) can never decode into a real separator
    // that silently changes segment structure.
    if (/%2f/i.test(decoded) || /%5c/i.test(decoded)) {
      return { ok: false, reason: "encoded path separator" };
    }
    if (!decoded.includes("%")) break; // fully decoded
    if (pass >= MAX_DECODE_PASSES) return { ok: false, reason: "excessive percent-encoding" };
    let next;
    try {
      next = decodeURIComponent(decoded);
    } catch {
      return { ok: false, reason: "malformed percent-encoding" };
    }
    if (next === decoded) break; // stable
    decoded = next;
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

  // `?`/`#` would start a query/fragment when the origin re-parses the forwarded
  // URL (truncating the path to a different resource); ASCII control chars (incl.
  // tab/newline, which the URL parser strips outright) would likewise change the
  // resource. Reject these so the path we classify can't diverge from what we
  // forward. (Spaces and non-ASCII are fine — the parser percent-escapes them
  // without changing segment structure, so they're re-encoded below, not rejected.)
  if (hasUnsafePathChar(path)) return { ok: false, reason: "illegal character in path" };
  // Re-encode to the URL-parser canonical form — space / non-ASCII become
  // percent-escapes WITHOUT changing segment structure — so the classified value
  // is byte-identical to what `new Request(originUrl)` resolves to, and the result
  // is idempotent under re-parsing. (No `%` survives the fixpoint decode above, so
  // this can't double-encode.)
  try {
    path = new URL("https://x" + path).pathname;
  } catch {
    return { ok: false, reason: "non-canonical path" };
  }
  return { ok: true, path };
}

/** True if the path contains `?`, `#`, an ASCII C0 control (0x00–0x1F), or DEL (0x7F). */
function hasUnsafePathChar(path) {
  for (let i = 0; i < path.length; i++) {
    const c = path.charCodeAt(i);
    if (c === 0x23 /* # */ || c === 0x3f /* ? */ || c < 0x20 || c === 0x7f) return true;
  }
  return false;
}
