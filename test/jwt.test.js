import { describe, it, expect, beforeEach } from "vitest";
import { env } from "cloudflare:test";
import { verifyIdToken, getDiscovery } from "../src/jwt.js";
import { createMockOp } from "./mock-op.js";
import { signJwt, seedDiscovery, tokenHash, makeRsaKey } from "./helpers.js";

let op, config;

async function tokenFromMock(opts) {
  // Register a code and run the OP's token endpoint to get a realistic id_token.
  return op.mintIdToken(opts);
}

beforeEach(async () => {
  op = await createMockOp();
  config = { issuer: op.discovery.issuer, clientId: "test-client", kv: env.OIDC_CACHE };
  await seedDiscovery(config.issuer, op.discovery, op.jwks);
  // Route the worker's discovery/JWKS fetches to the mock OP.
  globalThis.fetch = (input, init) => op.handle(new Request(input, init));
});

describe("verifyIdToken — happy path", () => {
  it("accepts a valid token and returns claims", async () => {
    const t = await tokenFromMock({ nonce: "n1" });
    const claims = await verifyIdToken(t, config, "n1");
    expect(claims.sub).toBe("user-123");
    expect(claims.groups).toEqual(["site-readers"]);
  });
  it("validates at_hash/c_hash when present (N11 positive)", async () => {
    const t = await tokenFromMock({ nonce: "n1", accessToken: "atk", code: "code-1" });
    const claims = await verifyIdToken(t, config, "n1", { accessToken: "atk", code: "code-1" });
    expect(claims.sub).toBe("user-123");
  });
});

describe("verifyIdToken — negative matrix", () => {
  it("N1 invalid signature", async () => {
    await expect(verifyIdToken(await tokenFromMock({ nonce: "n1", broken: "bad-sig" }), config, "n1"))
      .rejects.toThrow(/signature/);
  });
  it("N2 alg:none", async () => {
    await expect(verifyIdToken(await tokenFromMock({ nonce: "n1", broken: "alg-none" }), config, "n1"))
      .rejects.toThrow(/alg/);
  });
  it("N3 wrong iss", async () => {
    await expect(verifyIdToken(await tokenFromMock({ nonce: "n1", broken: "wrong-iss" }), config, "n1"))
      .rejects.toThrow(/iss/);
  });
  it("N3 iss with trailing slash is accepted (Auth0 issuer format)", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { alg: "RS256", kid: op.key.kid, typ: "JWT" },
      { iss: config.issuer + "/", aud: "test-client", sub: "user-123", groups: ["site-readers"],
        iat: now, exp: now + 3600, nonce: "n1" },
      op.key.privateKey,
    );
    const claims = await verifyIdToken(token, config, "n1");
    expect(claims.sub).toBe("user-123");
  });
  it("N4 wrong aud", async () => {
    await expect(verifyIdToken(await tokenFromMock({ nonce: "n1", broken: "wrong-aud" }), config, "n1"))
      .rejects.toThrow(/aud/);
  });
  it("N4b multi-aud without azp", async () => {
    await expect(verifyIdToken(await tokenFromMock({ nonce: "n1", broken: "multi-aud-no-azp" }), config, "n1"))
      .rejects.toThrow(/azp/);
  });
  it("N5 expired", async () => {
    await expect(verifyIdToken(await tokenFromMock({ nonce: "n1", broken: "expired" }), config, "n1"))
      .rejects.toThrow(/expired/);
  });
  it("N6 nonce mismatch", async () => {
    await expect(verifyIdToken(await tokenFromMock({ nonce: "n1", broken: "bad-nonce" }), config, "n1"))
      .rejects.toThrow(/nonce/);
  });
  it("N11 at_hash mismatch", async () => {
    const t = await tokenFromMock({ nonce: "n1", accessToken: "atk", code: "code-1", broken: "bad-at-hash" });
    await expect(verifyIdToken(t, config, "n1", { accessToken: "atk", code: "code-1" }))
      .rejects.toThrow(/at_hash/);
  });
  it("M2 single-aud token with wrong azp is rejected", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { alg: "RS256", kid: op.key.kid, typ: "JWT" },
      { iss: config.issuer, aud: "test-client", sub: "user-123", groups: ["site-readers"],
        iat: now, exp: now + 3600, nonce: "n1", azp: "other-client" },
      op.key.privateKey,
    );
    await expect(verifyIdToken(token, config, "n1")).rejects.toThrow(/azp/);
  });
});

describe("verifyIdToken — I1 exp required and iat cannot be in the future", () => {
  it("I1a rejects a token with exp omitted", async () => {
    const now = Math.floor(Date.now() / 1000);
    // Sign with the real OP key so signature verifies; only exp is missing.
    const token = await signJwt(
      { alg: "RS256", kid: op.key.kid, typ: "JWT" },
      { iss: config.issuer, aud: "test-client", sub: "user-123", groups: ["site-readers"],
        iat: now, nonce: "n1" },
      op.key.privateKey,
    );
    await expect(verifyIdToken(token, config, "n1")).rejects.toThrow(/expired/);
  });

  it("I1b rejects a token with iat far in the future", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { alg: "RS256", kid: op.key.kid, typ: "JWT" },
      { iss: config.issuer, aud: "test-client", sub: "user-123", groups: ["site-readers"],
        iat: now + 100000, exp: now + 3600, nonce: "n1" },
      op.key.privateKey,
    );
    await expect(verifyIdToken(token, config, "n1")).rejects.toThrow(/iat/);
  });

  it("I1c rejects a token with sub omitted", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { alg: "RS256", kid: op.key.kid, typ: "JWT" },
      { iss: config.issuer, aud: "test-client", groups: ["site-readers"],
        iat: now, exp: now + 3600, nonce: "n1" },
      op.key.privateKey,
    );
    await expect(verifyIdToken(token, config, "n1")).rejects.toThrow(/sub/);
  });

  it("I1d rejects a token with iat omitted", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { alg: "RS256", kid: op.key.kid, typ: "JWT" },
      { iss: config.issuer, aud: "test-client", sub: "user-123", groups: ["site-readers"],
        exp: now + 3600, nonce: "n1" },
      op.key.privateKey,
    );
    await expect(verifyIdToken(token, config, "n1")).rejects.toThrow(/iat/);
  });
});

describe("getDiscovery — H8 trust boundary", () => {
  it("rejects a discovery document whose issuer does not match config", async () => {
    await seedDiscovery(config.issuer, { ...op.discovery, issuer: "https://evil.test" }, op.jwks);
    await expect(getDiscovery(config)).rejects.toThrow(/issuer/);
  });

  it("rejects a discovery document with a non-https endpoint", async () => {
    await seedDiscovery(config.issuer, { ...op.discovery, token_endpoint: "http://op.test/token" }, op.jwks);
    await expect(getDiscovery(config)).rejects.toThrow(/https/);
  });

  it("accepts a well-formed discovery document", async () => {
    await seedDiscovery(config.issuer, op.discovery, op.jwks);
    await expect(getDiscovery(config)).resolves.toMatchObject({ issuer: config.issuer });
  });

  it("M-1 rejects a discovery doc whose token_endpoint is on a different host than the issuer", async () => {
    // A poisoned cache pointing token_endpoint at an attacker host would exfiltrate
    // client_secret + the auth code; pin every endpoint to the issuer's origin.
    await seedDiscovery(config.issuer, { ...op.discovery, token_endpoint: "https://evil.test/token" }, op.jwks);
    await expect(getDiscovery(config)).rejects.toThrow(/origin/);
  });

  it("M-1 rejects a discovery doc whose jwks_uri is on a different host than the issuer", async () => {
    // jwks_uri → attacker host would let attacker-signed id_tokens verify.
    await seedDiscovery(config.issuer, { ...op.discovery, jwks_uri: "https://evil.test/jwks" }, op.jwks);
    await expect(getDiscovery(config)).rejects.toThrow(/origin/);
  });

  it("M-1 rejects a discovery doc whose authorization_endpoint is on a different host", async () => {
    await seedDiscovery(config.issuer, { ...op.discovery, authorization_endpoint: "https://evil.test/authorize" }, op.jwks);
    await expect(getDiscovery(config)).rejects.toThrow(/origin/);
  });
});

describe("selectSigningJwk — use/alg hardening", () => {
  it("kid-absent token picks the sig key even when the JWKS also serves an enc RSA key", async () => {
    const sig = await makeRsaKey("sig-key");
    const enc = await makeRsaKey("enc-key");
    delete sig.publicJwk.kid; // kid-less keys: selection must fall back to use/alg, not count
    delete enc.publicJwk.kid;
    enc.publicJwk.use = "enc";
    delete enc.publicJwk.alg;
    op.jwks.keys = [enc.publicJwk, sig.publicJwk];
    await seedDiscovery(config.issuer, op.discovery, op.jwks);

    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { alg: "RS256", typ: "JWT" }, // header omits kid
      { iss: config.issuer, aud: "test-client", sub: "user-123", groups: ["site-readers"],
        iat: now, exp: now + 3600, nonce: "n1" },
      sig.privateKey,
    );
    const claims = await verifyIdToken(token, config, "n1");
    expect(claims.sub).toBe("user-123");
  });

  it("rejects when the only RSA key is enc-only (no usable signing key)", async () => {
    const enc = await makeRsaKey("enc-key");
    delete enc.publicJwk.kid;
    enc.publicJwk.use = "enc";
    op.jwks.keys = [enc.publicJwk];
    await seedDiscovery(config.issuer, op.discovery, op.jwks);

    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { alg: "RS256", typ: "JWT" },
      { iss: config.issuer, aud: "test-client", sub: "x", iat: now, exp: now + 3600, nonce: "n1" },
      enc.privateKey,
    );
    await expect(verifyIdToken(token, config, "n1")).rejects.toThrow(/no JWKS key/);
  });
});

describe("verifyIdToken — kid-absent + iss guard", () => {
  it("accepts a token with no kid when the JWKS has exactly one key (oidcc-idtoken-kid-absent-single-jwks)", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { alg: "RS256", typ: "JWT" }, // header omits kid
      { iss: config.issuer, aud: "test-client", sub: "user-123", groups: ["site-readers"],
        iat: now, exp: now + 3600, nonce: "n1" },
      op.key.privateKey,
    );
    const claims = await verifyIdToken(token, config, "n1");
    expect(claims.sub).toBe("user-123");
  });

  it("rejects a token with no kid when the JWKS has multiple keys (ambiguous)", async () => {
    const second = await makeRsaKey("key-2");
    op.jwks.keys = [op.key.publicJwk, second.publicJwk];
    await seedDiscovery(config.issuer, op.discovery, op.jwks);
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { alg: "RS256", typ: "JWT" }, // header omits kid
      { iss: config.issuer, aud: "test-client", sub: "x", iat: now, exp: now + 3600, nonce: "n1" },
      op.key.privateKey,
    );
    await expect(verifyIdToken(token, config, "n1")).rejects.toThrow(/no JWKS key/);
  });

  it("rejects a token whose iss claim is absent (no raw TypeError)", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { alg: "RS256", kid: op.key.kid, typ: "JWT" },
      { aud: "test-client", sub: "x", iat: now, exp: now + 3600, nonce: "n1" }, // no iss
      op.key.privateKey,
    );
    await expect(verifyIdToken(token, config, "n1")).rejects.toThrow(/iss/);
  });
});

describe("verifyIdToken — N7 kid rotation (refetch JWKS exactly once)", () => {
  // The cache (seeded in beforeEach) holds only the original "test-key-1". A fetch spy
  // counts live /jwks hits to prove the refetch happens EXACTLY once — an implementation
  // that loops would fail the count assertion even though the resolve/reject is correct.
  function spyJwks() {
    let n = 0;
    globalThis.fetch = (input, init) => {
      const r = new Request(input, init);
      if (new URL(r.url).pathname === "/jwks") n++;
      return op.handle(r);
    };
    return () => n;
  }

  it("refetches once and accepts a key present only in the FRESH JWKS", async () => {
    const rotated = await makeRsaKey("key-B");
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { alg: "RS256", kid: "key-B", typ: "JWT" },
      { iss: config.issuer, aud: "test-client", sub: "user-123", groups: ["site-readers"],
        iat: now, exp: now + 3600, nonce: "n1" },
      rotated.privateKey,
    );
    op.jwks.keys = [op.key.publicJwk, rotated.publicJwk]; // live JWKS rotated; cache still stale
    const count = spyJwks();
    const claims = await verifyIdToken(token, config, "n1");
    expect(claims.sub).toBe("user-123");
    expect(count()).toBe(1); // exactly one forced refetch
  });

  it("refetches once then rejects a kid present NOWHERE", async () => {
    const ghost = await makeRsaKey("ghost-key");
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { alg: "RS256", kid: "ghost-key", typ: "JWT" },
      { iss: config.issuer, aud: "test-client", sub: "x", iat: now, exp: now + 3600, nonce: "n1" },
      ghost.privateKey,
    );
    const count = spyJwks(); // live JWKS unchanged → ghost-key absent everywhere
    await expect(verifyIdToken(token, config, "n1")).rejects.toThrow(/no JWKS key/);
    expect(count()).toBe(1); // refetched exactly once before giving up — not a loop
  });
});
