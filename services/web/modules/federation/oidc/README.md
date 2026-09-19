# oidc/ — B-side OIDC provider

This instance acts as the **OIDC provider (OP)** for A-side federated logins,
backed by [`oidc-provider`](https://github.com/panva/node-oidc-provider) **v9**.
The provider is a singleton (`createProvider.getOidcProvider()`) mounted at
`/federation/oidc` on the web router; the *interaction forms* are the custom
bridge below (provider's built-in dev interactions are disabled).

> Bug fixes are welcome here. New behavior should be grounded in **plan 05
> (§8 OIDC provider)**.

### Files

| File | Role |
|---|---|
| `createProvider.mjs` | Singleton `oidc-provider` factory. `getOidcProvider()` builds the OP from: our leaf EC (`oidf/leaf.mjs`), approved-peer clients (`clients.mjs`), Redis-backed models (`RedisOidcProviderAdapter.mjs`), and the bridge URL (`interact/:uid`). `Settings.federation.enabled` gates it. Claims: `origin`, `localName`, `displayName`, `institution` (`institution` is `null`-safe — no user-language claim in v1). |
| `bridge.mjs` | `mountBridge(webRouter)`: serves `/federation/oidc/interact/:uid` (GET), `.../consent` (POST), `.../deny` (POST). Handles the `prompt=login` auto-approve (federated mirror sessions) and renders `app/views/consent.pug` for `openid-claims`. Redirects back via `/resume`. |
| `clients.mjs` | `buildOidcProviderClients()` — one RP client per **approved** peer (`urn:overleaf-federation:client:<origin>`, `tn:oidc` client-auth, `jwks` = the peer's pinned `anchorJwks`). |
| `RedisOidcProviderAdapter.mjs` | `oidc-provider` Models backed by Redis (interaction, session, code, user-code, authorization, grant). Key prefix `federation:oidc:*`. |

### Interaction flow (B receives A's code request)
```
A redirects user → B /federation/oidc/auth
  → oidc-provider issues interaction uid
  → 302 → B /federation/oidc/interact/<uid>
  → (bridge) logged-in B user → consent/deny → 303 /resume → code/token to A
```

### Notes
- The provider is rebuilt lazily when the approved-peer set changes
  (`_resetForTest` / admin approve path invalidates).
- Client assertions used *for* this OP come over S2S, not OIDC `client_id`
  secrets (private_key_jwt posture per plan 05 §2).
