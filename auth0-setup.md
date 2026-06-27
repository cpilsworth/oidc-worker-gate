# Auth0 Setup Guide

How to configure an Auth0 tenant as the OIDC provider for `oidc-worker-gate`.

---

## Auth0 Application

Create a **Regular Web Application** in the Auth0 dashboard.

| Setting | Value |
|---|---|
| Application Type | Regular Web Application |
| Token Endpoint Authentication | Post (`client_secret_post`) |
| Allowed Callback URLs | `https://<worker-subdomain>.workers.dev/.auth/callback` |
| Allowed Logout URLs | `https://<worker-subdomain>.workers.dev/` |
| Allowed Web Origins | `https://<worker-subdomain>.workers.dev` |

PKCE is supported by Auth0 for confidential clients and requires no extra configuration.

---

## Worker Environment Variables

Set these in `wrangler.toml` `[vars]`:

| Variable | Value |
|---|---|
| `OIDC_ISSUER` | `https://<tenant>.us.auth0.com` — no trailing slash |
| `CLIENT_ID` | Auth0 application Client ID |
| `REDIRECT_URI` | `https://<worker-subdomain>.workers.dev/.auth/callback` |
| `SCOPES` | `openid profile email` |
| `GROUPS_CLAIM` | `https://oidc.workers.dev/groups` — the single claim the worker reads for membership (see below) |

Set these as secrets via `wrangler secret put`:

| Secret | Value |
|---|---|
| `OIDC_CLIENT_SECRET` | Auth0 application Client Secret |
| `SESSION_HMAC_KEY` | Random 32+ byte string (e.g. `openssl rand -base64 32`) |

### Issuer trailing slash

Auth0 issues tokens with `iss: "https://<tenant>.us.auth0.com/"` (trailing slash). The worker normalises both sides of the issuer check, so configuring `OIDC_ISSUER` without a trailing slash is correct and intentional.

---

## Roles and Group-Gated Routes

The worker's access policy maps `audience` values in route rules to a `groups` array in the session. Auth0 does not include group/role information in the ID token by default, and silently drops any non-namespaced custom claims that are not standard OIDC fields.

### Step 1 — Create roles

In **User Management → Roles**, create one role per audience value used in `ACCESS_POLICY`. For example, a policy rule with `"audience": ["medical"]` requires a role named `medical`.

Assign users to roles via the role's **Users** tab.

### Step 2 — Add a Post Login Action

In **Actions → Library**, create a **Login / Post Login** action named `Add groups claim`:

```js
exports.onExecutePostLogin = async (event, api) => {
  const roles = event.authorization?.roles ?? [];
  api.idToken.setCustomClaim('https://oidc.workers.dev/groups', roles);
};
```

The namespace prefix (`https://oidc.workers.dev/groups`) is required — Auth0 silently drops non-namespaced custom claims from tokens. The worker reads **only** the single claim named by `GROUPS_CLAIM` (there is no silent `groups`/`roles` fallback, so an unexpected claim can't grant access), so set `GROUPS_CLAIM = "https://oidc.workers.dev/groups"` to match the claim this Action emits. The worker maps that claim's values to the session `groups` array.

Deploy the action, then wire it into the **Login flow**: **Actions → Flows → Login** → drag the action between Start and Complete → Apply.

### Step 3 — Match policy audience to role names

Role names in Auth0 must exactly match the `audience` values in the worker's `ACCESS_POLICY`. For example:

```json
{ "path": "/members/*", "tier": "protected", "audience": ["medical"] }
```

requires an Auth0 role named `medical` assigned to the user.

---

## Logout

The worker redirects to Auth0's `end_session_endpoint` on a **`POST`** to `/.auth/logout` (a cross-site `GET` is rejected with `405` to prevent logout CSRF), passing `id_token_hint` so Auth0 can identify the session. It clears the gate session and returns the user to the worker's root. No additional Auth0 configuration is needed for logout.

---

## Compatibility Notes

- **Algorithm**: Auth0 defaults to RS256 for new applications. The worker only supports RS256; do not change the signing algorithm in the Auth0 application settings.
- **PKCE**: Auth0 supports PKCE with `client_secret` for confidential clients (Regular Web Apps). No special toggle is needed.
- **Social connections**: Roles assigned in Auth0 User Management apply regardless of the upstream identity provider (GitHub, Google, etc.).
