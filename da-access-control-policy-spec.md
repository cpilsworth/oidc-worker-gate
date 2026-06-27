# DA-authored access-control policy

> Shared design for making `oidc-worker-gate` authorization policy manageable from a
> DA-authored access-control sheet.

Captured: 2026-06-27

## Goal

The delivery gate should enforce content authorization from a DA-authored policy, while
keeping the worker responsible for authentication, reserved infrastructure paths, snapshot
integrity, and fail-safe defaults.

The DA policy is the source of truth for content rules. It does not control EDS
infrastructure paths, gate-owned routes, or unmatched-path fallback behavior.

## Source model

- One policy sheet exists per DA site as the `access-control` sheet in the DA site
  configuration.
- The publisher reads the multi-sheet config document from
  `https://admin.da.live/config/{org}/{site}/` with the incoming DA token.
- The `POLICY_SITE_ID` worker/publisher config uses the format `org/site`.
- The publisher infers `{org}` and `{site}` from `POLICY_SITE_ID`.
- The sheet contains a single table of policy rows.
- The enforced columns are:
  - `path`
  - `tier`
  - `audience`
  - `description`
- `description` is ignored by enforcement.
- Blank rows are allowed and ignored.
- Partial rows are validation errors.
- Unknown extra columns are ignored for enforcement and reported as publish warnings.

## Authoring semantics

### `path`

- Must be an absolute pathname beginning with `/`.
- Must not contain `?` or `#`.
- Matching is case-sensitive.
- Matching uses the raw request `URL.pathname`; there is no logical content-path
  normalization in the MVP.
- Authors should use folder patterns such as `/members/**` to cover derived
  representations such as `.html` and `.json`.

### Pattern syntax

The worker will understand normalized DA-style path patterns directly:

- `*` matches within one path segment and does not cross `/`.
- `**` spans path separators.
- A terminal `/**` matches the folder path, the trailing-slash form, and descendants.
  Example: `/members/**` matches `/members`, `/members/`, and `/members/a/b`.
- Exact paths outrank glob patterns.
- Among matching globs, the longest literal prefix before the first wildcard wins.
- Equal-specificity overlaps are rejected during publish validation.

### `tier`

Allowed values are exactly:

- `public`
- `protected`
- `secured`

Publisher input is normalized for case and whitespace, then stored as lowercase. Values
outside the three allowed tiers are rejected.

Tier behavior remains the current worker behavior:

- `public`: forward without authentication.
- `protected`: unauthenticated request redirects to OIDC login.
- `secured`: unauthenticated request returns JSON `401`.
- Authenticated but unauthorized requests return generic JSON `403` for both
  `protected` and `secured`.

### `audience`

- `audience` is an additive allow-list only.
- There are no deny rules, exclusions, negative groups, or boolean expressions.
- The cell is parsed as comma-separated values.
- Values are trimmed, empty segments are dropped, and duplicates are removed.
- Audience names are case-sensitive after trimming.
- A `public` row with `audience` is rejected.
- A `protected` or `secured` row with empty `audience` means any authenticated user.
- Empty `audience` on `protected` or `secured` produces a non-blocking warning.

## Audience vocabulary

DA `audience` entries use normalized internal audience names, not raw IdP-specific group
or role names.

- The operator manages an audience map in worker/publisher configuration.
- IdP claims are mapped to normalized names before the session cookie is minted.
- Unmapped IdP groups/roles are dropped.
- The session field remains `groups` for now, but its values are normalized audiences.
- `x-auth-groups` continues to be forwarded to origin for compatibility, containing only
  normalized audiences.
- Existing sessions keep their mapped audiences until `SESSION_TTL` expiry.
- Publisher validation rejects unknown normalized audience names in DA policy rows.

Example audience map shape:

```json
{
  "medical": ["auth0:role:medical", "ims:profile:Medical Readers"],
  "secure": ["auth0:role:secure"]
}
```

## Worker-managed paths

DA policy focuses on content only. The delivery worker owns reserved paths and EDS
infrastructure paths.

Reserved/operator-managed paths are configured by the operator and seeded with:

- `/.auth/**`
- `/scripts/**`
- `/styles/**`
- `/blocks/**`
- `/icons/**`
- `/fonts/**`
- `/media_*`
- `/sitemap.xml`
- `/robots.txt`
- `/.well-known/**`
- configurable public fragment paths, seeded with:
  - `/nav.plain.html`
  - `/footer.plain.html`

`/*.plain.html` is intentionally not a blanket public rule.

Reserved-path handling:

- Operator-managed paths are classified before DA policy refresh.
- DA policy refresh is skipped for those requests.
- DA rows overlapping worker-managed paths are ignored, not enforced.
- Ignored rows are retained in snapshot metadata as `ignored_rules` with a reason.
- Ignored rows are logged by the publisher at publish time and by the worker at
  startup/refresh.
- For content paths, DA rules win over static content rules.
- Static rules should be restricted to operator-managed paths and emergency fallback.

Media remains public for the MVP. Confidential media requires a separate design.

## Default behavior

- `POLICY_SOURCE` is operator configuration for enabling or disabling DA/KV policy.
- MVP values are:
  - `auto`: use a valid signed DA/KV policy when available; otherwise fall back to the
    static worker policy.
  - `worker`: disable DA/KV policy entirely and always use the static worker policy.
  - `required`: require a valid signed DA/KV policy for content paths; if no valid policy
    or last-known-good policy is available, return `503` instead of using the static
    fallback.
- `auto` is the recommended default.
- The worker logs the active `POLICY_SOURCE` mode and whether a request is using DA/KV
  policy, last-known-good policy, or static worker fallback.
- `default_tier` remains worker/operator configuration.
- DA does not author `default_tier`.
- Unmatched paths fall back to the worker default behavior, normally
  `default_tier: "protected"` with no audience.
- Invalid or unavailable DA snapshots never fail open.

## Signed snapshot contract

The publisher writes a signed snapshot to KV. The delivery worker verifies the signature
before using it.

KV key shape for MVP:

- Current policy: `policy:current:<site-id>`
- Optional versions: `policy:version:<site-id>:<version>`
- Status: `policy:status:<site-id>`

Use the existing KV binding for MVP. A dedicated policy KV namespace can be introduced
later if needed.

Snapshot envelope:

```json
{
  "payload": {
    "schema_version": 1,
    "site_id": "org/site",
    "version": "2026-06-27T14:30:00Z",
    "published_at": "2026-06-27T14:30:00Z",
    "rules": [],
    "ignored_rules": []
  },
  "signature": "base64url(hmac_sha256(canonical_payload_json))"
}
```

Snapshot rules contain DA-authored content policy only. Operator-managed public rules are
merged locally by the delivery worker, not included in the signed DA snapshot.

The snapshot is signed with `POLICY_HMAC_KEY`, separate from `SESSION_HMAC_KEY`.

The worker rejects snapshots that are missing, malformed, signed incorrectly, have the
wrong `site_id`, or have an unsupported `schema_version`. Rejection is logged and the
worker falls back to the static policy or last-known-good behavior.

## Refresh behavior

- The worker lazily refreshes policy on requests that are not operator-managed paths.
- Each isolate keeps the last verified payload in memory.
- `POLICY_REFRESH_TTL_SECONDS` defaults to `60`.
- `POLICY_STALE_TTL_SECONDS` defaults to `900`.
- When the in-memory policy is stale, the worker attempts a KV read and signature
  verification.
- If refresh fails, the worker continues using last-known-good in-memory policy within
  the stale window.
- After the stale window, the worker falls back to static worker policy.

## Publisher design

Publishing is phased after the delivery-gate runtime work.

The normal path is automatic:

1. DA emits a published-source change notification.
2. The separate publisher Worker receives the notification.
3. The request includes a DA token.
4. The publisher uses that token to read the configured access-control document:
   `https://admin.da.live/config/{org}/{site}/`.
5. The publisher parses, validates, normalizes, signs, and writes the snapshot to KV.

The publisher does not trust the event payload as policy content. It treats the event as a
trigger and reads DA source itself.

The incoming DA token is accepted if it is good enough to read the access-control
configuration. The publisher should not store the token.

The publisher supports multiple sites in one deployment:

- Site IDs must be allow-listed in operator-managed JSON config.
- Events resolve to an allow-listed `POLICY_SITE_ID`.
- The fixed DA path is derived from the allow-listed site ID.

The publisher writes structured logs and `policy:status:<site-id>` with:

- `last_success`
- `last_failure`
- `errors`
- `warnings`
- `source_version`

If a new publish fails validation, the publisher does not overwrite
`policy:current:<site-id>`. The last known good KV policy remains active.

A manual republish command is supported as an operational fallback. Polling is not part
of the default design.

## Logging and responses

The delivery worker logs:

- policy refreshes
- invalid snapshots
- ignored rules
- `401` and `403` denials, including policy version, path, tier, and reason

It does not log every successful authorization decision by default.

Client-facing `403` responses remain generic:

```json
{"error":"forbidden"}
```

Authorization details go to logs, not response bodies.

## Implementation phases

### Phase 1: delivery gate runtime

Implement and test:

- `POLICY_SOURCE=auto|worker`, including explicit DA/KV disablement and missing-policy
  fallback to the static worker policy
- explicit `POLICY_SITE_ID`
- separate `POLICY_HMAC_KEY`
- signed snapshot verification
- KV refresh/stale behavior
- DA-style `*` and `**` matching in `policy.js`
- operator-managed/reserved paths
- local merge of static operator rules with DA content policy
- static fallback behavior
- audience mapping to normalized session `groups`
- seeded KV snapshots in tests

No DA publisher code is included in Phase 1.

### Phase 2: publisher compiler and manual republish

Implement:

- policy sheet parser
- validation and warnings
- ignored-rule metadata
- canonical payload generation
- snapshot signing
- KV write/status behavior
- manual republish command

### Phase 3: automatic DA-event publishing

Implement:

- separate publisher Worker endpoint
- DA token handling
- DA source fetch after notification
- allow-listed multi-site dispatch
- automatic publish status reporting

## References

- DA permissions guide: https://docs.da.live/administrators/guides/permissions
- DA access-control reference: https://docs.da.live/developers/reference/access-control
- Existing exploratory design: `folder-authorization.md`
