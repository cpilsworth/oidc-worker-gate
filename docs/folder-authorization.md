# Folder-scoped authorization from DA, with delegated administration

How to drive the worker's per-folder access decisions from access metadata that is
**authored and administered in DA (da.live)** — so that (a) certain folders of the
delivered site are visible only to certain groups, and (b) only certain users/groups
may *administer* those folder→group rules, with that administration itself scoped
(a "marketing admin" manages marketing's access, not everyone's).

This builds on [`README.md`](../README.md) (the worker's three-tier `ACCESS_POLICY`) and shares the philosophy of
[`../signed-preview-deep-links/da-eds-auth-plan.md`](../../signed-preview-deep-links/da-eds-auth-plan.md):
**DA is the source of truth; we don't stand up a parallel permission store.** The
difference is *where* the decision happens — that plan delegates a low-volume *authoring*
authz check by replaying the user's token to `admin.da.live`; here we need a
**high-volume delivery gate**, so per-request calls to DA are the wrong tool and we
instead distribute a snapshot of the policy to the edge.

## Three planes — keep them separate

| Plane | Question it answers | Source of truth |
| --- | --- | --- |
| **Authentication** | Who is this user? Which groups? | OIDC IdP → session `groups` claim |
| **Resource policy** | Which groups may *view* which folder? | DA-authored delivery-ACL |
| **Administration** | Who may *edit* that policy, and for which folders? | DA path-permissions (delegated `write`) |

Conflating them is the usual failure mode. Authentication is the IdP's job;
resource policy is data; administration is itself an access-control problem that DA
already solves.

## Design decision #1 — group-identity alignment (read this first)

The DA permissions model references principals as **IMS organization IDs, IMS group
names, or email addresses** (groups are created in the Adobe Admin Console, not in DA).
The worker authorizes by comparing the user's group membership against those names. The
question is how the worker *obtains* that membership.

**Confirmed (FluffyJaws / IMS internal docs, 2026-06-10):**

- **Adobe IMS is a usable OP.** It publishes a standard discovery doc at
  `https://ims-na1.adobelogin.com/ims/.well-known/openid-configuration`, JWKS at
  `/ims/keys`, issuer `https://ims-na1.adobelogin.com`, and supports authorization-code
  + PKCE (S256) for a confidential client (`client_secret_post`). The worker's
  discovery-driven config ports to IMS directly.
- **There is no `groups` claim in the IMS `id_token`.** Admin Console group /
  product-profile membership is *not* asserted in the token. To get entitlement context
  the worker must call **`GET https://ims-na1.adobelogin.com/ims/profile/v1`** with the
  **access token** after the code exchange, having requested scopes
  `read_organizations additional_info.roles additional_info.projectedProductContext`.
  This adds a post-login IMS call to the session-mint step (see README session model).
- **Caveat — product profiles ≠ user groups.** `/ims/profile/v1` returns org/role and
  **`projectedProductContext`** (product-profile entitlements), which is *not* obviously
  the same thing as the Admin Console **user groups** the DA permissions sheet references
  by name. Resolving true *user-group* membership may require a **User Management API**
  lookup (a service-token / back-end call, not the end-user token). **Q3 below.**

So even with IMS as the OP, "the groups align directly" is too optimistic: you (a) fetch
entitlements via `/ims/profile/v1` at login and stamp them on the session, and (b) must
confirm which IMS construct (product profile vs. user group) your DA ACL names, and map
accordingly. With a **non-IMS OP** (Okta/Entra/Ping/Auth0, the base README's generic
examples) you instead need a config-driven `idp_group → ims_group` mapping. Either way an
explicit mapping/lookup layer is required — it is not free.

> Reconciles with `README.md` (written for generic IdPs): folder-authz from DA requires
> IMS as the OP *plus* a post-login profile fetch, or a non-IMS OP *plus* a group mapping.

## The metadata — a delivery-ACL authored in DA

Don't overload DA's native `permissions` sheet: its `read`/`write` actions govern
*authoring* access, which is not the same question as *delivery visibility* (an author
may have authoring `read` on a draft folder that should still be gated to a narrower
audience when published — or vice-versa). Instead, author a **dedicated delivery-ACL**,
e.g. a sheet `/config/access/site` with rows:

| `path` (folder glob) | `tier` | `audience` (groups) | `comments` |
| --- | --- | --- | --- |
| `/members/**` | `protected` | `members, staff` | members area |
| `/partners/**` | `protected` | `partners` | partner portal |
| `/blog/**` | `public` | | open |
| `/api/private/**` | `secured` | `staff` | API/data route |

- `tier`: `public` (no auth), `protected` (missing session redirects to login), or
  `secured` (missing session returns `401`, serving the origin `/error/401` page or generic
  JSON if absent).
- `audience`: optional. If absent on a non-public row, any valid session is enough. If
  present, `session.groups`/entitlements must intersect the row's audience or the worker
  returns `403`.
- This is the runtime version of the README's static `ACCESS_POLICY`: same row shape,
  same **most-specific path match**, same evaluator.

## Delegated administration — the crux

DA permissions are **path-scoped**: only a principal with `write` on a given config path
may edit that document. We exploit that with **disjoint, additive grants** — each
delegated admin gets `write` on a *separate* config document, so no two grants overlap:

```
DA permissions sheet (org config):
  path                      groups            actions
  /config/access/**         super-admins      write      ← master + structure
  /config/access/marketing  marketing-admins  write      ← delegated, marketing only
  /config/access/partners   partner-admins    write      ← delegated, partners only
  /config/access/**         all-authors       read
```

- The worker reads the **union** of the per-area ACL docs. `marketing-admins` can change
  *who sees marketing folders* by editing only `/config/access/marketing`; they cannot
  touch `/config/access/partners`.
- **Use disjoint paths, not overlapping allow/deny.** The DA docs do **not** specify
  precedence for *conflicting* rules on overlapping paths, so a design that relies on "a
  narrow allow overrides a broad deny" is unsafe. Additive grants on non-overlapping
  config paths need no precedence guarantee. (See open question Q2.)
- **Group *membership*** (who is *in* `marketing-readers`) is administered in the **Adobe
  Admin Console** via IMS delegated group-admin roles — or, if you want it inside DA,
  as membership-list documents write-scoped to the same delegated admins. Either way the
  worker only ever sees the resolved `groups` claim at request time; it does not resolve
  membership itself.

This is exactly "limit access to a DA config so only certain users/groups administer the
groups that can access certain folders": the *master* config and the *folder→group map*
are locked to super-admins; each *folder area* is delegated to its own admin group; and
DA's own ACLs enforce all of it.

## Getting the metadata to the worker

The worker must not call DA on the hot path (latency + scale), and the ACL must not be
world-readable (it reveals group/folder structure — so **don't** serve it from the public
`.aem.live` tree).

### Primary — control-plane push into Worker KV

Treat ACL distribution as a control-plane event, decoupled from the request path:

```
DA edit/publish ──▶ webhook / CI job / "publish ACL" admin action
                    1. read the per-area ACL docs from DA (source API)
                    2. validate + merge into one normalized policy JSON
                    3. write it to Worker KV (Cloudflare API) under e.g. ACL:current
                            ▼
   Worker (hot path): read ACL:current from KV (cached in isolate memory), evaluate
```

- The worker has **no runtime DA dependency** — it only reads its own KV.
- The ACL never touches the public delivery tree, so **no leak**.
- The service credential that reads DA lives in the **control plane** (CI/webhook), not
  in the edge request path — a smaller, easier-to-secure trust surface.
- Push a monotonically increasing `version` + timestamp with the policy so the worker can
  log which policy version made a decision.

### Alternative — runtime pull from `admin.da.live` (OPEN — see Q1)

The worker fetches the ACL from `admin.da.live/source/{org}/{repo}/config/access/...`
with a **service token**, caches in KV with a TTL, and refreshes on a push-invalidation
signal. Simpler to wire, but: it puts a DA dependency (and a service credential) on the
edge, and **whether a worker-held token can read DA source is unconfirmed** — the existing
`da-eds-auth-plan.md` §8 lists this exact question as open. Prefer the control-plane push
unless that question resolves favorably.

### Not recommended — publish ACL to the delivery tree

Publishing `/config/access/*` so it lands on `.aem.live` would let the worker fetch it
like content (and reuse push-invalidation), but anyone who knows the origin hostname could
`GET` it directly. Rejected for information disclosure.

## Enforcement on the hot path

For a request to path `P` with a valid session:

1. Look up the **most-specific** ACL rule matching `P` in the KV policy.
2. `public` → forward without auth. `protected` / `secured` → require a valid session.
3. If the matched row has an `audience`, forward iff
   `session.groups`/entitlements ∩ `rule.audience` ≠ ∅; otherwise return **403**.
4. No matching rule → fall to the README's `default_tier` (deny-by-default `protected`).

The `/config/access/*` paths themselves must never be public in `ACCESS_POLICY`, so end
users can never fetch the policy through the worker.

### Availability — last-known-good, not hard fail-closed

If the KV policy read fails transiently, hard-denying would 403 *all* gated content on a
blip. Instead: serve the **last-known-good policy from the isolate/KV cache within a
staleness window** (e.g. 15 min); only past that window deny gated paths. Public-tier
paths never consult the ACL, so they're unaffected regardless.

## Security considerations

- **Policy integrity.** The KV policy is security-critical; only the control-plane
  pipeline may write `ACL:current`. Consider signing the policy blob and verifying in the
  worker so a KV mis-write can't silently widen access.
- **Fail-closed default.** Unmatched paths deny (`default_tier`); an *empty/absent* policy
  must not mean "allow all."
- **Audit.** DA versions every config edit (who/when) — that *is* the administration audit
  trail. Log `{ policy_version, sub, path, decision }` at the edge for the enforcement
  trail.
- **Two-key change control** for the master config is possible via DA review flows if
  edits to `/config/access/**` need a second approver.

## Open questions to confirm before building

> **These are decision gates, not background notes.** Treat each as a time-boxed
> spike with an explicit decision criterion before the phase it blocks (see
> [`README.md`](../README.md) Phasing): **Q3 + Q4 gate Phases 2–3; Q1 is moot under
> the control-plane-push design.** None of them block Phase 1. `ask-fluffyjaws` is the
> tool for Q1/Q3/Q4.

1. **Runtime DA read (Q1).** Can a worker-held service token read DA source via
   `admin.da.live`, and what credential/audience does it need? (Same open item as
   `da-eds-auth-plan.md` §8.1–8.2.) — *Moot if the control-plane-push design is used, since
   only the control plane reads DA.* Verifiable via `ask-fluffyjaws`.
2. **DA path-permission precedence (Q2).** Confirmed behavior for overlapping/conflicting
   rules on the same path. The disjoint-additive-grants design avoids depending on it, but
   confirm before any overlapping-rule shortcut.
3. **Group construct mapping (Q3).** *Confirmed:* IMS works as the OP but emits no
   `groups` claim — membership comes from a post-login `/ims/profile/v1` call returning
   roles + `projectedProductContext`. *Still open:* does the DA ACL name **product
   profiles**, **user groups**, or **org roles**? If true Admin Console *user-group*
   membership is needed, `/ims/profile/v1` likely won't give it — that requires the
   **User Management API**, which (confirmed via FluffyJaws, 2026-06-10) is a **separate
   S2S/Service integration** (`user_management_sdk` scope + Admin Console admin roles),
   *not* a scope addable to the RP's OAuth Web App client. That is a second, more-
   privileged credential to provision and a server-side call — weigh it against authoring
   the DA ACL in terms of product profiles/roles (which the RP already obtains for free).

   > **Provisioning note (Q1-adjacent):** standing up the RP's IMS client is **self-serve
   > for an org System Admin / Developer** via Adobe Developer Console — auth-code+PKCE,
   > `id_token`, and all scopes above are standard/pre-allowlisted; no IMS ticket,
   > "trusted-client" flag, or product allowlist is needed *for the RP* (the worker only
   > authenticates users and reads profile/org info; it does not call AEM author APIs).
4. **DA webhook / change signal (Q4).** What event does DA emit on a config edit/publish
   that the control-plane pipeline can subscribe to (vs. polling or an explicit admin
   action)?

## Relationship to existing docs

- [`README.md`](../README.md) — the worker; this doc replaces the static `ACCESS_POLICY`
  source with a path-scoped, DA-sourced policy and adds the identity-alignment decision.
- [`../signed-preview-deep-links/da-eds-auth-plan.md`](../../signed-preview-deep-links/da-eds-auth-plan.md)
  — same "DA is the source of truth" stance; that plan replays a token to DA for a
  low-volume *authoring* decision, this one distributes a policy snapshot for a
  high-volume *delivery* gate.
