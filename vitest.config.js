import { defineConfig, configDefaults } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

export default defineConfig({
  // Stray git worktrees under .claude/ carry their own (stale) copy of this
  // suite; never let them join the run — they execute against the main worker
  // build and produce confusing cross-contaminated failures.
  test: { exclude: [...configDefaults.exclude, "**/.claude/**", "**/.wrangler/**"] },
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
            // The site defines /error/401 but not /error/403, so end-to-end
            // tests exercise both the page path (401) and the JSON fallback (403).
            if (url.pathname === "/error/401") {
              return new Response("<h1>Please sign in</h1>", { headers: { "content-type": "text/html; charset=utf-8" } });
            }
            if (url.pathname.startsWith("/error/")) {
              return new Response("not found", { status: 404 });
            }
            return new Response("origin-body", { headers: { "cache-control": "public, max-age=60" } });
          }
          return new Response(`unexpected outbound: ${request.url}`, { status: 502 });
        },
      },
    }),
  ],
});
