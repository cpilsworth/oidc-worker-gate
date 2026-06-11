import { getDiscovery, verifyIdToken } from "./jwt.js";
import { createPkcePair, randomNonce, randomState } from "./pkce.js";
import { clearSessionCookie, clearStateCookie, mintSessionCookie, mintStateCookie, readStateCookie } from "./session.js";
import { timingSafeEqual } from "./encoding.js";

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
    if (!saved) return errorResponse(400, "Login session expired — please retry.");

    const returnedState = url.searchParams.get("state") || "";
    if (!timingSafeEqual(returnedState, saved.state)) return errorResponse(400, "State mismatch — possible CSRF.");

    // Single-use state: reject a replayed callback (N9). Best-effort via KV — CF KV is
    // eventually consistent, so this stops practical replays, not a perfectly-timed race.
    // Marked consumed once the state is validated; a later token-exchange failure still
    // burns the state (user re-initiates login), which is the safe direction.
    if (this.config.kv) {
      const usedKey = `state-used:${saved.state}`;
      if (await this.config.kv.get(usedKey)) return errorResponse(400, "State already used — possible replay.");
      await this.config.kv.put(usedKey, "1", { expirationTtl: 600 });
    }

    const idpError = url.searchParams.get("error");
    if (idpError) return errorResponse(401, `Authorization failed: ${idpError}`);

    const code = url.searchParams.get("code");
    if (!code) return errorResponse(400, "Missing authorization code.");

    const discovery = await getDiscovery(this.config);
    const body = new URLSearchParams({
      grant_type: "authorization_code", code, redirect_uri: this.config.redirectUri,
      client_id: this.config.clientId, client_secret: this.config.clientSecret, code_verifier: saved.verifier,
    });
    const tokenRes = await fetch(discovery.token_endpoint, {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: body.toString(),
    });
    if (!tokenRes.ok) return errorResponse(401, `Token exchange failed: ${tokenRes.status}`);

    const tokens = await tokenRes.json();
    if (!tokens.id_token) return errorResponse(401, "No id_token in token response.");

    let claims;
    try {
      claims = await verifyIdToken(tokens.id_token, this.config, saved.nonce,
        { code, accessToken: tokens.access_token });

    } catch (e) {
      return errorResponse(400, `ID token validation failed: ${e.message}`);
    }

    const sessionCookie = await mintSessionCookie(claims, this.config);
    const headers = new Headers({ location: safeReturnTo(saved.returnTo, url.origin) });
    headers.append("set-cookie", sessionCookie);
    headers.append("set-cookie", clearStateCookie());
    return new Response(null, { status: 302, headers });
  }

  async handleLogout(req, url) {
    const discovery = await getDiscovery(this.config).catch(() => ({}));
    const headers = new Headers();
    headers.append("set-cookie", clearSessionCookie());
    if (discovery.end_session_endpoint) {
      const logout = new URL(discovery.end_session_endpoint);
      logout.searchParams.set("client_id", this.config.clientId);
      logout.searchParams.set("post_logout_redirect_uri", `${url.origin}/`);
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

function errorResponse(status, message) {
  return new Response(`${status} — ${message}\n`, { status, headers: { "content-type": "text/plain; charset=utf-8" } });
}
