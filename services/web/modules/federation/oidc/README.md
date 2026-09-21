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

### Redis key layout (all under `federation:oidc:*`)
| Key | Type | Content |
|---|---|---|
| `federation:oidc:<Model>:<id>` | string (JSON) | every persisted model doc (code, tokens, Session, Interaction, Grant, …) |
| `federation:oidc:sub:<uid>` | string | the Session id for `findByUid` (Session-only sub-index) |
| `federation:oidc:usercode:<code>` | string | the DeviceCode id for `findByUserCode` (CIBA off, kept for v9 routing) |
| `federation:oidc:grant:<grantId>` | SET of doc keys | token docs minted under one consent Grant (`revokeByGrantId` cascade) |
| `federation:oidc:client:<clientId>` | SET of doc keys | token docs minted for one client (`killOutstandingCodes` sweep, 04 §5) |

The two SETs are trimmed on every `destroy`/`revokeByGrantId` (and reclaimed
on their last member by real Redis); the client SET's GRANTABLE gate (token
models, never `Grant`) is what keeps the sweep from over-crossing into B's
sessions and into the consent record (06 §174/§178).

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
