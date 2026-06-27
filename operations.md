# Operations runbook

This runbook covers the DA-authored policy path:

1. DA authors edit the `access-control` sheet in the site configuration.
2. The publisher worker reads `https://admin.da.live/config/{org}/{site}/` with the
   provided DA token.
3. The publisher validates, normalizes, signs, and writes the policy snapshot to KV.
4. The delivery worker verifies the signed KV snapshot and enforces it for content paths.

For the current test site, `{org}/{site}` is `cpilsworth/authz`.

## Local secret file

Create `.env` from `.env.example` and fill in the values needed for the operation you are
running. `.env` is ignored by git.

Required for manual refresh through the publisher worker:

```dotenv
DA_TOKEN=
POLICY_SITE_ID=cpilsworth/authz
POLICY_PUBLISHER_URL=https://<publisher-worker-host>
```

Required for direct KV publish or policy status inspection:

```dotenv
CLOUDFLARE_ACCOUNT_ID=
KV_NAMESPACE_ID=d4bec63e176f41b0902126d281e9be2e
CLOUDFLARE_API_TOKEN=
POLICY_HMAC_KEY=
```

The Cloudflare API token should be scoped to the target account and KV namespace. The DA
token should be constrained to the access-control document path.

## Policy HMAC key

`POLICY_HMAC_KEY` is a shared secret between the publisher and delivery workers. Generate
it once per environment and set the same value on both workers:

```bash
openssl rand -base64 32
npx wrangler secret put POLICY_HMAC_KEY
npx wrangler secret put POLICY_HMAC_KEY --config wrangler.publisher.toml
```

Keep it separate from `SESSION_HMAC_KEY`. Rotation requires deploying the new secret to the
publisher and delivery workers, then republishing the policy so the delivery worker can
verify snapshots signed with the new key.

## Deploy workers

Deploy the delivery gate:

```bash
npm run deploy
```

Deploy the policy publisher:

```bash
npm run deploy:publisher
```

The publisher worker uses the same `OIDC_CACHE` KV namespace as the delivery worker for the
current MVP.

## Manual refresh

Trigger a DA-backed refresh after the DA sheet is published:

```bash
npm run refresh-policy -- --pretty
```

The script reads `DA_TOKEN`, `POLICY_SITE_ID`, and `POLICY_PUBLISHER_URL` from `.env`.

Expected success shape:

```json
{
  "level": "info",
  "status": 200,
  "site_id": "cpilsworth/authz",
  "response": {
    "status": "published"
  }
}
```

## Direct publish fallback

If the publisher endpoint is unavailable, publish directly from the DA source to KV:

```bash
npm run publish-policy
```

For local fixture validation without writing KV:

```bash
npm run publish-policy -- --input test/fixtures/access-control-policy.json --dry-run
```

## Inspect policy status

Read the publisher status document from KV:

```bash
npm run policy-status -- --pretty
```

Also summarize the active signed policy snapshot:

```bash
npm run policy-status -- --current --pretty
```

`status.last_success` should advance after a successful refresh. If validation fails,
`status.last_failure` and `status.errors` are updated, but `policy:current:<site-id>` is
not overwritten.

## Delivery verification

After a successful refresh, check representative paths through the delivery worker:

```bash
curl -i https://oidc-worker-gate.cpilsworth.workers.dev/
curl -i https://oidc-worker-gate.cpilsworth.workers.dev/members/x
curl -i https://oidc-worker-gate.cpilsworth.workers.dev/api/example
```

Expected unauthenticated behavior:

- public path: forwarded to the EDS origin
- protected path: `302` to the identity provider
- secured path: `401` JSON

## Failure behavior

- Missing DA/KV policy with `POLICY_SOURCE=auto`: delivery falls back to the static worker
  policy.
- `POLICY_SOURCE=worker`: delivery ignores DA/KV policy entirely.
- Invalid signature or validation failure: delivery keeps the last known good in-memory
  policy within the stale TTL, otherwise falls back to static worker policy.
- DA rows overlapping worker-managed paths are ignored and logged by the publisher; those
  paths remain owned by the worker.
