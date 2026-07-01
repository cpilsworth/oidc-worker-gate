import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

// Dedicated config for the performance benchmark (npm run bench). Mirrors the
// main test config's worker bindings but includes ONLY test/perf, so the slow
// high-iteration benchmark never runs as part of `npm test`.
export default defineConfig({
  test: { include: ["test/perf/**/*.test.js"] },
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: {
        bindings: {
          OIDC_CLIENT_SECRET: "test-client-secret",
          SESSION_HMAC_KEY: "test-hmac-key-at-least-32-bytes-long!!",
        },
        outboundService(request) {
          const url = new URL(request.url);
          if (url.hostname.endsWith("aem.live")) {
            return new Response("origin-body", { headers: { "cache-control": "public, max-age=60" } });
          }
          return new Response(`unexpected outbound: ${request.url}`, { status: 502 });
        },
      },
    }),
  ],
});
