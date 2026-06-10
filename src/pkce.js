import { base64UrlEncode, utf8 } from "./encoding.js";

function randomString(bytes = 32) {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return base64UrlEncode(buf);
}

export function randomState() { return randomString(16); }
export function randomNonce() { return randomString(16); }

export async function createPkcePair() {
  const verifier = randomString(32);
  const digest = await crypto.subtle.digest("SHA-256", utf8(verifier));
  return { verifier, challenge: base64UrlEncode(digest), method: "S256" };
}
