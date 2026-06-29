import { getDiscovery, verifyIdToken } from "./jwt.js";
import { createPkcePair, randomNonce, randomState } from "./pkce.js";
import {
  clearSessionCookie, clearStateCookie, mintSessionCookie, mintStateCookie,
  readSession, readStateCookie, takeSessionIdToken,
} from "./session.js";
import { timingSafeEqual } from "./encoding.js";
import { errorResponse, requestId } from "./http.js";
import { kvGetFresh, kvPutWithTtl } from "./kv.js";

const STATE_TTL_SECONDS = 600;

export class OidcClient {
  constructor(config) { this.config = config; }

  async startLogin(req, url) {
    const discovery = await getDiscovery(this.config);
    const state = randomState();
    const nonce = randomNonce();
    const pkce = await createPkcePair();
    const authorize = new URL(discovery.authorization_endpoint);
    authorize.searchParams.set("response_type", "code");
    authorize.searchParams.set("client_id", this.config.clientId);
    authorize.searchParams.set("redirect_uri", this.config.redirectUri);
    authorize.searchParams.set("scope", this.config.scopes);
    authorize.searchParams.set("state", state);
    authorize.searchParams.set("nonce", nonce);
    authorize.searchParams.set("code_challenge", pkce.challenge);
    authorize.searchParams.set("code_challenge_method", pkce.method);
    const stateCookie = await mintStateCookie(
      { state, nonce, verifier: pkce.verifier, returnTo: url.pathname + url.search }, this.config);
    return new Response(null, { status: 302, headers: { location: authorize.toString(), "set-cookie": stateCookie } });
  }

  async handleCallback(req, url) {
    const saved = await readStateCookie(req, this.config);
    if (!saved) return fail(req, 400, "invalid_login", "missing_or_expired_state");

    const returnedState = url.searchParams.get("state") || "";
    if (!timingSafeEqual(returnedState, saved.state)) return fail(req, 400, "invalid_login", "state_mismatch");

    // Single-use state requires a store to record consumption. Without KV we
    // cannot prevent replay, so we fail closed rather than silently skip (H5).
    if (!this.config.kv) return fail(req, 503, "login_unavailable", "state_store_unbound");

    // Best-effort single-use check (N9). CF KV is eventually consistent, so this
    // stops practical replays, not a perfectly-timed race. Marked consumed once
    // the state validates; a later failure still burns the state (user retries),
    // which is the safe direction.
    const usedKey = `state-used:${saved.state}`;
    if (await kvGetFresh(this.config.kv, usedKey)) return fail(req, 400, "invalid_login", "state_replayed");
    await kvPutWithTtl(this.config.kv, usedKey, true, STATE_TTL_SECONDS);

    const idpError = url.searchParams.get("error");
    if (idpError) return fail(req, 401, "login_failed", `idp_error:${idpError}`);

    const code = url.searchParams.get("code");
    if (!code) return fail(req, 400, "invalid_login", "missing_code");

    const discovery = await getDiscovery(this.config);
    const body = new URLSearchParams({
      grant_type: "authorization_code", code, redirect_uri: this.config.redirectUri,
      client_id: this.config.clientId, client_secret: this.config.clientSecret, code_verifier: saved.verifier,
    });
    const tokenRes = await fetch(discovery.token_endpoint, {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: body.toString(),
    });
    if (!tokenRes.ok) return fail(req, 401, "login_failed", `token_exchange_${tokenRes.status}`);

    const tokens = await tokenRes.json();
    if (!tokens.id_token) return fail(req, 401, "login_failed", "no_id_token");

    let claims;
    try {
      claims = await verifyIdToken(tokens.id_token, this.config, saved.nonce,
        { code, accessToken: tokens.access_token });
    } catch (e) {
      return fail(req, 400, "invalid_token", e.message);
    }

    const sessionCookie = await mintSessionCookie(claims, this.config, tokens.id_token);
    const headers = new Headers({ location: safeReturnTo(saved.returnTo, url.origin) });
    headers.append("set-cookie", sessionCookie);
    headers.append("set-cookie", clearStateCookie());
    return new Response(null, { status: 302, headers });
  }

  async handleLogout(req, url) {
    // RP-initiated logout is state-changing; require POST so a cross-site GET
    // cannot force a logout (CSRF — H9).
    if (req.method !== "POST") {
      return errorResponse(405, "method_not_allowed", { requestId: requestId(req) });
    }

    const session = await readSession(req, this.config);
    // Resolve (and clean up) the server-side id_token kept for id_token_hint (M-3).
    const idTokenHint = await takeSessionIdToken(session, this.config);
    const discovery = await getDiscovery(this.config).catch(() => ({}));
    const headers = new Headers();
    headers.append("set-cookie", clearSessionCookie());
    headers.append("set-cookie", clearStateCookie());
    if (discovery.end_session_endpoint) {
      const logout = new URL(discovery.end_session_endpoint);
      logout.searchParams.set("client_id", this.config.clientId);
      logout.searchParams.set("post_logout_redirect_uri", `${url.origin}/`);
      if (idTokenHint) logout.searchParams.set("id_token_hint", idTokenHint);
      headers.set("location", logout.toString());
      return new Response(null, { status: 302, headers });
    }
    headers.set("location", "/");
    return new Response(null, { status: 302, headers });
  }
}

function safeReturnTo(returnTo, origin) {
  if (typeof returnTo !== "string" || !returnTo.startsWith("/")) return "/";
  try {
    const resolved = new URL(returnTo, origin);
    if (resolved.origin !== origin) return "/";   // catches //evil.com and /\evil.com
    return resolved.pathname + resolved.search;
  } catch {
    return "/";
  }
}

/** Log the real reason server-side, return a generic body to the caller (H7). */
function fail(req, status, code, detail) {
  console.warn("callback rejected", { status, code, detail });
  return errorResponse(status, code, {
    requestId: requestId(req),
    wwwAuthenticate: status === 401 ? 'Bearer error="invalid_token"' : undefined,
  });
}
