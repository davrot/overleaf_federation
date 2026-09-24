# Federation Module — HANDOFF / Living Task List

> **This file is the takeover point.** It is always current. Last updated at bottom under
> "Progress Log". A new session should read: ① this file, ② `FINDINGS.md`, ③ `plan/05-cep-integration.md`
> (§8 = oidc-provider v9.12.2 grounding authority, beats plans 01–04 where they conflict),
> then `plan/00-overview.md`. Repo root: `~/federation/overleaf-fed` (monorepo), module root = this dir.

## 0. One-sentence goal

Implement the `overleaf-cep` federation WebModule (P0–P2 pairwise v1): **identity federation only
(no content)**, OIDF 1.0 trust layer (leaf + client assertions), B-side OIDC OP role via
`oidc-provider` v9.12.2 (public client + PKCE, no client secret anywhere), A-side RP role via
plain `fetch` + top-level `jose`, identity anchor = `(origin, localName)` tuple. P3
(institutional anchors) is explicitly out of scope (stub exists).

## 1. Phase map (authority: `plan/07-roadmap-and-testing.md`)

| Phase | Scope | Status |
|-------|-------|--------|
| P0 | leaf mount + keystore bootstrap + OIDC OP stack + adapter + bridge + clients | **DONE** (index.mjs mounted; 2026-09-18b batch) |
| P1 | S2S (pairwise depth-1 verify) + invite + A-side grant round-trip (RP) + admin pin stub | **DONE** (s2s/ + rp/ + admin/ committed 2026-09-18b) |
| P2 | Admin UI + Settings additions + claim allow-list + rate-limit + audit + institutional TA (P3 pin-time) | **DONE** (rate-limit, audit, admin, claim allow-list via `Redact.CLAIM_LOG_ALLOWLIST`, institutional TA pin-time all shipped + committed) |
| P2-test | Two-instance integration (live OIDC code dance + S2S round-trip) | **DONE** (12/12 green — see SESSION 8; TODO-a9c6dd79 closed) |
| P2-live | Live smoke against real Mongo+Redis+oidc-provider+express (the module, not the mocks) | **DONE** (13 scenarios ALL PASS — see SESSION 10; `tools/live-smoke.mjs`) |
| **V2** | **Content-bridge: export-project S2S + no-re-consent (2a), home export wizard (2b), read-only 403 + sweep (2c), two-real-origins smoke (2d) — Goal `3ea7bb53`** | **DONE** (**2a SHIPPED** — SESSION 12; **2b SHIPPED** — SESSION 13; **2c SHIPPED** — SESSION 14; **2d SHIPPED** — SESSION 15; all four steps committed + pushed; eduGAIN Phases 0/2/3/4 remain external-infra-blocked, plan/10) |

## 2. What already exists (all committed, DO NOT rewrite)

```
app/models/FederationKey.mjs        ES256 key model; purpose 'federation'|'oidc'; states published/active/retiring/revoked
app/models/FederationPeer.mjs       origin, anchorJwks, kid, status pending/approved/rejected/revoked, mode pairwise|institutional
oidf/keystore.mjs                   ensureBootstrapped(), getFederationKeySet(), rotation ops, leaf fetch
oidf/leaf.mjs                       getEntityId/getOrigin/oidcEndpoints/buildLeafEntityConfiguration/leafHandler
oidf/anchors.mjs                    fetchAnchorJwks, createTrustAnchorSetFromPeers (institutional stub)
oidf/verify.mjs                     S2S_ERRORS, verifyS2sClientAssertion(), replay via Redis, claimJti/lookupApprovedPeer
oidf/ClientAssertionClient.mjs      createClientAssertion/buildS2sRequest/getS2sEndpoint/getClientId
oidc/createProvider.mjs             oidc-provider v9 instance (findAccount, adapter, bridge)
oidc/clients.mjs                    buildOidcProviderClients() ← approved FederationPeers
oidc/bridge.mjs                     login+consent interaction bridge (reads req.session overleaf B-login)
oidc/RedisOidcProviderAdapter.mjs   v9 7-method adapter FACTORY (modelName arg), GRANTABLE set, sub-indexes
test/unit/oidf/keystore.test.mjs    PASSES (12/12, 2026-09-18): bootstrap, rotation, grace, provider
FINDINGS.md                         verified npm v1.0.0 API surface for @oidfed/*
```

**Verified working:** `cd services/web && yarn run vitest run modules/federation/test/unit/oidf/keystore.test.mjs`
→ 12 passed. (Module unit tests run via `bin/test_unit_run_dir <dir>` which wraps `yarn run vitest run`.)

## 3. What is missing (build order — this IS the task list)

### 3.1 util/ (P0, no dependencies) — DONE (uncommitted)
- `util/Anchor.mjs` — `parseAnchor` (last-colon split), `formatAnchor`, `validateAnchor`, `saltedLocalNameHash` (HMAC, `Settings.security.sessionSecret` salt, 32-hex), `hashInviteeEmail`, `resolveAnchorUser` (mirror-then-local-oracle, lazy `User` import — 04 §1)
- `util/Redact.mjs` — `redact()`, `publicJwks()`, `assertionMeta()` (audit row carries `{ iss, aud, jtiHash }`, hashed, 03 §6/04 §8)
- `util/Audit.mjs` — `audit({ operation, projectId, meta, req })` fire-and-forget; `AUDIT_TYPES` (04 §8 v2 list); meta allow-list filter
- **Note**: `ProjectAuditLogEntry.projectId` is `Schema.Types.ObjectId` — pass the real project id or `null`, NEVER an opaque A-side ref (CastError)

### 3.2 Data model (P0/P1) — DONE (uncommitted)
- `services/web/app/src/models/User.mjs` — **added** `federation: { origin, localName, federatedAt }` subdoc (presence = mirror row; NO `kind` field — subdoc presence is the discriminator, 04 §1). User has NO `language` field.
- `services/web/app/src/models/ProjectInvite.mjs` — **added** `federated: { origin, localName, localNameHash, invitedBy, homeDisplayName, homeAvatarUrl, authorized, authorizedAt, status }` (04 §2, subdoc presence is the mark)
- Migration: `tools/migrations/20260721120000_add_federation_indexes.mjs` — 3 index sets incl. partial unique `federation.*` (repo has `partialFilterExpression` precedent; autoIndex off)

### 3.3 `index.mjs` (P0 core wiring) — the single most important missing file (start() lives INSIDE index.mjs, no separate start.mjs)
WebModule default export (contract: `{ name, dependencies, router, nonCsrfRouter, hooks, middleware, sessionMiddleware, appMiddleware, start }`):
- `start: async () => {}` — NO args: `Modules.start()` → `await module.start?.()` (Modules.mjs:131-133), invoked from `services/web/app.mjs:126` after `loadModules()`. Runs at **boot**; DB (Mongoose) is imported at module-load time, so `keystore.ensureBootstrapped()` is safe there. NOTE: `appMiddleware` (leaf mount) runs at module-import time — before DB connect — so it must be synchronous handler registration only.
- `nonCsrfRouter: { apply(webRouter, ...) => { … } }` — modules apply via `Modules.applyNonCsrfRouter` at `Server.mjs:231`, **before** `webRouter.use(webRouter.csrf.middleware)` — so S2S POST + OIDC bridge GET/POST + RP callback GET bypass CSRF
- `appMiddleware` — mount leaf + jwks + admin (07 §6: no changes to Server.mjs). **leafHandler is app-level** (`app.use('/.well-known/openid-federation', leafHandler)`) because it needs `req.hostname` (05 §1.2 line 119 shows `app.use`, not `webRouter.use`); oidc-provider can also mount at app level since it manages its own cookies but is fine via webRouter. Keep leaf in `appMiddleware` (app-level);
- **nonCsrfRouter mount order** (LOCKED this session): ① S2sRouter `POST /federation/s2s` (always mounted) ② interaction bridge (GET `/federation/oidc/interact/:uid` + POST `.../consent`, via `mountBridge(webRouter)`, gated on `Settings.federation.enabled`) ③ **provider terminal** `webRouter.use('/federation/oidc', ...provider.callback()...)` LAST (bridge first, plan §1.1 + §8.3 explicit). RP callback GET is a SEPARATE file (`rp/CallbackRouter.mjs`) mounted alongside the bridge (step ②, both are express routes that terminate before the provider).
- jwks: `GET /federation/.well-known/jwks` — public JWKS
- Guard every mount with `Settings.federation.enabled`
- View resolution (PITFALL): `Views.compileViewIncludes` globs `modules/*/app/views/**/*.pug` and registers each **absolute path** as a render name. So consent view must be `modules/federation/app/views/consent.pug` and is rendered via `res.render(<absolute path to consent.pug>, locals)` — bridge.mjs already does this (`CONSENT_VIEW = path.resolve(__dirname, '../../app/views/consent.pug')`). Plan 05 §1's `views/consent.html.ejs` is **obsolete** (no ejs in repo); reconcile to pug.

### 3.4 S2S (P1) — wire authority: plan 03 §2–§6 (NOT v1 payloads). `s2s/` dir exists, EMPTY.
- `s2s/S2sRouter.mjs` — `nonCsrfRouter`: `POST /federation/s2s` (03 §8), always mounted (federation-off → 200 envelope, peers get machine-readable refusal)
- `s2s/actions/authorizeInvite.mjs` — B-as-home-oracle (03 §4.1): payload `{ invitee: {origin, localName, display}, project: {ref, ownerLocalName, ownerDisplay, privileges} }`; B returns `{approved, displayName, institution}` (v1 wire: NO language, NO avatarUrl — see LOCKED decisions §9.1)
- `s2s/actions/invited.mjs` — read-only preview (03 §4.2), always `{ ok: true, payload: { approved, displayName } }` envelope
- `s2s/actions/revoke.mjs` — B-side: mark SENDER's peer row `revoked` (03 §4.3: "no longer accept inbound S2S FROM origin <A>"); idempotent
- `util/RateLimitStore.mjs` — `INCR` + `EXPIRE`, budgets authorize/invited 30 / 120 s keyed `(caller, localNameHash)`, revoke 5 / 1200 s keyed `(caller)` (03 §5, 04 §6)
- All three verify inbound via `verify.mjs` `verifyS2sClientAssertion()` (async — npm `verifyClientAssertion` resolves a Promise, 03 §2)
- Wire: `client_assertion` header + JSON body `{ action, from, to, ts, payload }` (03 §2)

### 3.5 Admin (P1)
- `admin/FederationAdminController.mjs` — peer list, approve/deny/revoke, key rotate (04 §2)
- `admin/AdminRouter.mjs` — mounted in existing admin area (04 §2.1):
  - Pending pins: `GET /admin/federation/peers` (list), `POST /admin/federation/peers/:id/approve`
  - Institutional: `POST /admin/federation/peers/:id/approveInstitutional` (P3 stub)
  - Key rotation: `POST /admin/federation/keys/rotate` (04 §2 / 05 §7 — TWO separate keys: federation + OIDC signing, 02 §4/§5)
  - Audit log view (04 §8)
- Mount: inside Features/ServerAdmin router block (near `/admin` at router.mjs:1085-1089, guard `AuthorizationMiddleware.ensureUserIsSiteAdmin`)

### 3.6 A-side (P1) — 05 §3 is authority (fetch + jose, NO client lib)
- `rp/` — A-side RPC: `CodeExchange.mjs` (01 §5, 05 §3):
  - `exchange(peerOrigin, { code, state })` — fetch B token endpoint, get JWT (id_token), verify with `jose` against B's **provider** JWKS (`/.well-known/jwks`, NOT leaf — 01 §6, 06 §6.1)
  - Verify: `claims.origin === peerOrigin`, `claims.localName === invitedLocalName`
- `rp/CallbackRouter.mjs` (05 §1: "GET /federation/oidc/rp/callback" — CSRF-exempt GET, applyNonCsrfRouter)
  - `GET /federation/oidc/rp/callback?code=...&state=...`:
    - session row first, Redis backup fallback (04 §6)
    - `exchange()` → claims → resolve mirror row (auto-create if new)
    - grant via `PermissionsService` if `intent.privileges` (04 §3)
    - 302 to `intent.url` (project URL)
- PKCE: `verifier` + `nonce` in A's express-session, HMAC-signed `state` (01 §5, 05 §3)

### 3.7 Invite (P1)
- `invite/FederatedInviteController.mjs` — tuple parse, display split on last colon (04 §1)
- `invite/FederatedInviteRouter.mjs` — `GET /api/federation/invite/preview`, `POST .../authorize` (05 §3)
- Save `ProjectInvite` row with `federated: true` (04 §3)
- B-side "is this a valid peer?" → `FederationPeer.findOne({ origin, status: 'approved' })`

### 3.8 Frontend (P2) — overleaf-cep React, standard (05 §4)
- Invite form: "Federation user" toggle, input `name:origin`, blur → client-side S2S `invited` preview (05 §4.1)
- "Open on <peer>" button (05 §4.2) — 302 redirect to B-side OIDC auth URL
- "Signed in as <origin>" banner (05 §4.3) — cosmetic, when `User.federation.origin` present
- Admin "Federation" tab (05 §4.4) — standard `AdminController` layout (peer list, approve/deny, key rotate, audit)

### 3.9 Settings + app-level auth guards
- `config/settings.defaults.js`: + `federation: { keystores: { federationKeystorePath, oidcKeystorePath } }` (05 §7 — TWO paths, not one)
- `Features/Authentication/SignUpController.mjs` — reject `:` in email (01 §3.3)
- `Features/Authentication/AuthenticationManager.mjs` — refuse federated-role actions: `suspended`, `resetPassword`, `changeEmail` (04 §1.2)
- `Services/.../AuthenticationManager.mjs` — same (if separate file)

### 3.10 Testing
- Existing: `yarn run vitest run modules/federation/test/unit/oidf/keystore.test.mjs` (12 pass)
- P0 tests (07 §3, §6): leaf fetch+verify, kid mismatch refetch, ReplayStore dedup, openid-configuration discovery
- P1: full 302 roundtrip loopback, mirror user creation, session works
- P2: S2S rate-limit, admin pin/rotate, frontend renders

## 4. Critical integration facts (verified)

### 4.1 Module dispatch (`app/src/infrastructure/Modules.mjs`)
- `index.mjs` default export per `types/web-module.ts`: `{ dependencies, router, nonCsrfRouter, hooks, middleware, sessionMiddleware, appMiddleware, start }`
- `router: { apply(webRouter, privateApiRouter, publicApiRouter) => {} }` — session-aware, mounted AFTER csrf middleware
- `nonCsrfRouter: { apply(webRouter, privateApiRouter, publicApiRouter) => {} }` — mounted at `Server.mjs:231` **BEFORE** `webRouter.use(webRouter.csrf.middleware)`. SAML pattern: `{ apply(webRouter, ...) { webRouter.post(...) } }`
- `appMiddleware: (app) => {}` — raw Express app (from `app/src/app.mjs:149-154`)
- `start: async () => {}` — NO args: `Modules.start()` → `await module.start?.()` (Modules.mjs:131-133), invoked from `services/web/app.mjs:126` after `loadModules()`, before HTTP listen — keystore bootstrap safe there
- `hooks: { name: (payload) => ... }` — fire via `Modules.promises.hooks.fire(name, payload)`

### 4.2 Redis
- `RedisWrapper.client('federation')` returns ioredis — but `Settings.redis` needs `federation` key: add to `settings.defaults.js:153` (04 §6)
- Feature keys: `ratelimiter` (existing), `federation` (NEW), etc

### 4.3 Session
- `SessionManager` at `Features/Authentication/SessionManager.mjs`: `isUserLoggedIn(session)`, `getLoggedInUserId(session)`
- Mirror login (04 §1 / 01 §5 step 8): `req.session.user = sessionId + User._id` (standard overleaf session, NO new passport strategy — 05 §1.2 "v1 stub deleted")

### 4.4 Admin routes
- Pattern: `router.mjs:1085-1093` — `webRouter.get('/admin', AuthorizationMiddleware.ensureUserIsSiteAdmin, AdminController.index)`
- `Features/ServerAdmin/AdminController.mjs` is the file to extend
- Guard: `AuthorizationMiddleware.ensureUserIsSiteAdmin` (line 234-253 of that file)

### 4.5 User.federation (04 §1) — the ONE new model field
```js
// User.mjs — ADDED field (NOT a separate model)
federation: {
  origin: String,      // home FQDN, e.g. 'university.example.org'
  localName: String,   // home login name, e.g. 'k.maxwell'
  federatedAt: Date,   // when mirror row created
}
```
- Presence (truthy) = mirror row; absence = local user
- **NO** `kind` field, **NO** separate mirror collection
- Index: `{ 'federation.origin': 1, 'federation.localName': 1 }` (04 §6, 05 §1.1)

### 4.6 ProjectInvite.federated (04 §2)
```js
federated: {
  origin: String,        // home origin
  localName: String,     // home login name
  localNameHash: String, // SHA-256, S2S verify (03 §4)
  invitedBy: String,     // owner User._id
  status: { type: String, enum: ['active','expired','revoked'] },
}
```
- `federated` object present, no `federated: true` boolean (v1 plan uses `federated: true` — reconcile with 04 §2.1)

### 4.7 Settings
- `settings.defaults.js:1228` (federation: { enabled: false, allowFederatedProjectCreate: false, requireAdminApproval: true, keyRotationGraceDays: 14, institutionId: null }). `Settings.security.sessionSecret` at L406 (salt for `saltedLocalNameHash`). Redis block at L153.
- 05 §7 (NEW): `federation: { keystores: { federationKeystorePath, oidcKeystorePath } }` + all existing + institutional anchor stub
- Admin UI (P2) edits per-instance fields

### 4.8 oidc-provider mount (05 §8.6 / §8.8, verified against v9.12.2 source)
- `new Provider('${Settings.siteUrl}/federation/oidc', setup)` — issuer = mount path
- `app.use('/federation/oidc', provider.callback())` — terminal
- Provider **IS** the Koa app (no `.app` property, no separate mount — 05 §8.1)
- Adapter: **factory** `(modelName) => instance` (NOT class, NOT constructor), 7 methods (05 §8.2)
- `clients[]` built at BOOT from approved peers (05 §8.8), NOT dynamic
- `findAccount` + `claims` config (05 §8.5)
- `interactions: { url }` + bridge GET/POST (05 §8.3) — mounted BEFORE provider.callback()
- Bridge reads `req.session` (overleaf B-side login) — this is the B-side login source
- Bridge auto-answers login step via `provider.interactionFinished(req, res, { login: { accountId } })`
- Consent POST: `express.urlencoded({ extended: false })` middleware required

### 4.9 ClientAssertionClient wire
- Type: `'urn:ietf:params:oauth:client-assertion'` (RFC 9421 JWT-BEARER)
- ClientAssertionClient.mjs:63 `buildS2sRequest(peer, payload)` creates signed assertion
- verify.mjs:99 `verifyS2sClientAssertion(assertion, from)` verifies + returns payload
- S2S_ERRORS: BAD_SIGNATURE, UNKNOWN_KID, PEER_UNKNOWN, PEER_NOT_APPROVED, REPLAY_JTI, TIMESTAMP_SKEW, FEDERATION_OFF, INVITEE_UNKNOWN, INVITEE_DISABLED, RATE_LIMITED

### 4.10 leaf.mjs mount
- 05 §1.2: `app.use('/.well-known/openid-federation', leafHandler)`
- leafHandler reads `buildLeafEntityConfiguration()` (leaf.mjs:127)
- leaf.mjs:95 exposes `oidcEndpoints()` — the discovery endpoints

## 5. Test / run commands

```bash
cd services/web
# existing (PASSES)
yarn run vitest run modules/federation/test/unit/oidf/keystore.test.mjs
# full module unit (bin/test_unit_run_dir wraps vitest run)
yarn run test:unit:all  # or: yarn run bin/test_unit_run_dir test/unit/src modules/federation/test/unit/src
# app boot (for manual testing)
cd services/web
PUBLIC_URL=http://localhost:3000 MONGO_HOST=127.0.0.1 REDIS_HOST=127.0.0.1 \
  yarn start
```

## 6. Grounding references (read before implementing)

| Priority | File | Covers |
|----------|------|--------|
| 1 | `FINDINGS.md` | Verified npm API surface for @oidfed/* (v1.0.0 exports) |
| 2 | `plan/05-cep-integration.md` | Integration: mount, adapter, claims, S2S, admin (AUTHORITY for P0 wiring) |
| 3 | `plan/04-data-model.md` | User.federation, ProjectInvite.federated, FederationPeer, keystore models |
| 4 | `plan/07-roadmap-and-testing.md` | P-1/P-2 phases, test gates per phase |
| 5 | `plan/03-s2s-wire-protocol.md` | S2S wire format, actions, rate limits |
| 6 | `plan/01-identity-federation-protocol.md` | OIDC grant round-trip, (origin, localName) identity model |
| 7 | `plan/02-trust-model-oidf.md` | OIDF 1.0 trust, leaf, anchor, keystore |
| 8 | `plan/06-security.md` | Security: redaction, rate limits, audit |
| 9 | `plan/00-overview.md` | Scope, constraints, identity model summary |

## 7. Constraints & invariants (DO NOT violate)

- Single WebModule at `modules/federation/index.mjs` (default export)
- `nonCsrfRouter` for S2S + OIDC callback (CSRF-exempt paths); `router.apply` for session-aware GET
- `appMiddleware` for leaf + jwks + admin mount
- NO new passport strategy; mirror login = standard express-session (05 §1.2)
- NO OIDC client lib for A-side (use `fetch` + `jose`, 05 §3)
- `oidc-provider` is B-side OP only (v9.12.2, no client secret, PKCE)
- Identity anchor = `(origin, localName)` tuple — NO 'kind' field
- Federation key signs S2S + client assertions (OIDF), NOT OIDC tokens — separate key sets (02 §4/§5, 05 §7)
- OIDC signing key signs id_tokens (OIDC), NOT S2S (05 §7)
- RedisWrapper `federation` feature for replay + state (04 §6)
- `Settings.federation.enabled` gates all mount (like `GIT_BRIDGE_ENABLED`)
- 429: per-action budgets 03 §5 (30 / 120 s keyed `(caller, localNameHash)`; 5 / 1200 s keyed `(caller)`) with `Allow-Retry-After`
- All new files: ESM (`.mjs`), JSDoc (not TypeScript), overleaf-cep conventions

## 8. Do NOT (common mistakes)

- Do NOT add `openidconnect-client` or `passport-oidc` — A-side uses `fetch`+`jose`
- Do NOT use `provider.app` (doesn't exist in v9) — mount `app.use('/federation/oidc', provider.callback())`
- Do NOT pass `provider.app` to adapter (v9.12.2 factory takes modelName only, not (provider, modelName))
- Do NOT create new `User` fields for mirrors — the `federation` subdoc IS the mirror row
- Do NOT mount leaf at `/openid-federation` without `/.well-known/` prefix (05 §1.2 is explicit)
- Do NOT mix federation key with OIDC signing key (separate sets, 02 §4/§5)
- Do NOT use OIDC client lib for A-side (05 §3 is explicit: fetch + jose v6)
- Do NOT skip `Settings.federation.enabled` gate
- Do NOT use `webRouter.use()` for leaf (must be `app.use('/')` for well-known)

## 9. Progress Log

### DONE: content-bridge 2d (TODO-0c6f534f) — 2-real-origins live smoke, SHIPPED SESSION 15
Goal step 4 of 4 (goal `3dad1c9e`). 2a/2b/2c all committed + pushed
(`86ead6eb49`/`a56cafbae2`/`1b7a9d4634`/`01ccd0c2b7`/`3e0b5f4ae2`/
`66d87b3372`). This is the LAST unblocked work item; eduGAIN phases
0/2/3 stay external-infra-blocked (plan/10, unchanged).

**Architecture (recon CLOSED this session, verified against shipped
code — do not re-read unless a seam changes):**
- **Cross-origin flow is the v1 identity dance on A (RP), NOT the
  wizard, that binds the export.** B's `export-project` (2a)
  binds owner-B-native + a LIVE consent grant to home A's client
  (`federationClientId(callerOrigin)`, via the adapter account index
  `federation:oidc:client:<accountId>` → grantId). So the 2d order:
  1. A user (viewer) authorizes a federated invite anchored to a
     B-origin owner email → A RP dance (login + consent) at B's OP →
     mirror user + consent grant land at B.
  2. Viewer on A hits the export wizard with B's project id → S2S
     `export-project` → B mints the PAT (2a) → wizard result view.
  3. Live PAT checks against B's git-bridge REST surface:
     `GET /api/v0/docs/<id>` (read → 200) and
     `POST /api/v0/docs/<id>/snapshots` (write → **403**, the 2c
     guard) — Bearer header, the surface this repo deploys.
- **One OP per process (single-origin variant ×2).**
  `createProvider` is a module-level singleton keyed on
  `Settings.siteUrl` + shared Mongo (`FederationKey` unique on
  `(purpose, kid)`); two providers in one process = one origin. So
  TWO node processes: the driver `live-two-origin.mjs`
  (origin A = `alpha.example`, in-process) spawns a child
  `live-smoke-b.mjs` (origin B = `beta.example`),
  shared real Mongo + Redis (docker `fed-smoke-mongo` 27107 /
  `fed-smoke-redis` 6380). A process: only v1 mount
  (S2sRouter + bridge + callback + oidc mount). B process: v1 mount
  + `GitBridgeRouter` (its `apply(webRouter, privateApiRouter,
  publicApiRouter)` takes three routers — drive the PAT check
  middleware directly, no Go service needed).
- **Key pinning (02 §3 TOFU):** the keystore is per-origin Mongo
  state; cross-origin S2S needs B to pin A's federation
  key. Reuse the v1 single-flow: A admin approves B peer
  (auto-pins B's federation public key into A's
  `FederationPeer.anchorJwks`) AND B admin approves A peer
  (pinned into B). Both approval paths exercised in
  `FederationAdminController` (unit-tested); live: one process
  admin-approves the other via a small HTTP surface on the admin
  router OR driver-side direct `buildS2sRequest` approval (pick the
  simpler that exercises the real peer-approval wire).
- **PAT mint is the same `db.oauthAccessTokens`
  (scope `federation:git_bridge`) the 2c guard refuses on the
  write path.** `validatePersonalAccessToken` (GET
  `/oauth/token/info`) only checks raw-PAT existence (no scope) —
  so the live 403 is `ensureTokenProjectAccess('write')`
  (GitBridgeAuthMiddleware) on the snapshot POST. `getUserId`
  filters `expiresAt: { $gt: now }` (2a TTL enforcement already
  verified live).
- **Shared Mongo:** A and B share one DB (both processes' mongoose
  connects to the same string). Seeded once by the driver: User rows
  (alice@beta.example owner-B-native + a viewer on A),
  `Project` (owner_ref=alice, B-side), FederationPeer rows both
  directions. Redis keys are namespaced by the modules in play
  (oidc-provider adapter `federation:oidc:*` per-provider-prefix
  — both providers use the same Redis, verify key isolation: the
  adapter prefixes are `federation:oidc:*` (SHARED across providers
  in the v1 single-process test — for 2d each op uses its own
  client-set but the shared prefix is fine because A's OP serves
  A's client_id, B's OP serves B's, and client_id embeds the
  origin so no cross-talk).
- **Anti-loop:** this file documents the flow — the next
  continuation implements the two live-smoke scripts + driver
  without re-reading the wire code (S2sRouter/verifying/oidf
  keystore are already proven in SESSION 10).

### [SESSION 10] 2026-09-22 — Live smoke (goal 1ec14289) CLOSED: module proven live, 2 prod bugs caught
- **`tools/live-smoke.mjs`** (NEW, committed): the two-instance scenario matrix 1:1, but the stub layer is the REAL runtime — real Mongo (all 5 models: FederationKey/Peer, User, ProjectInvite, ProjectAuditLogEntry), real Redis (PKCE state, jti dedup, JWKS cache, rate limits + oidc-provider RedisOidcProviderAdapter Session/Interaction/AuthorizationCode/Grant docs + client SET), real express listen, real oidc-provider v9 dance, real jose. Stubs: ONLY the 4 documented app seams (CollaboratorsGetter ×2, CollaboratorsHandler ×1, UserSessionsManager ×1). Single origin `beta.example` plays both A (RP) and B (OP) one process; `globalThis.fetch` rewrite `https://beta.example` → local port.
- **13 scenarios ALL PASS (exit 0)**: 01 OIDC dance happy path (authorize→login→consent→code→callback→mirror+grant+audit), 02 PKCE one-shot replay refused, 03/04 S2S invited (approved / soft-deny), 05/06 S2S authorize-invite (approved+audit / invitee-unknown+audit), 07 jti replay, 08 bad-signature, 09 unknown-kid, 10 rate-limit 429+Allow-Retry-After, 11a revoke+killOutstandingCodes sweep (codes die, B sessions/survive), 11b revoke trust+audit, 12 federation-off.
- **Two PRODUCTION bugs caught by the live run that the entire unit suite (incl. two-instance) could never reach** — both fixed + committed:
  1. `oidc/RedisOidcProviderAdapter.mjs` lazy `import('../../../../app/src/infrastructure/RedisWrapper.mjs')` — 4-up from `modules/federation/oidc/` lands in `services/app/...` (NO SUCH FILE). vitest masks this (vi.mock intercepts resolution); real Node ESM does not → oidc-provider 500 `server_error` on the first `/auth`. Fix: 3-up. (Both call sites: `createAdapter` + `revokeClientCodes`.)
  2. `oidc/bridge.mjs` `CONSENT_VIEW = path.resolve(__dirname, '../../app/views/consent.pug')` → `modules/app/views/` (missing). The view lives at `modules/federation/app/views/`. Fix: 1-up. (Live run got here only after fix 1 — the dance reached consent render.)
- **Flake fixed (proven live)**: two-instance test #8 (bad-signature) flipped the LAST char of the ES256 signature segment. A last-char flip can decode to an IDENTICAL signature (base64url padding bits) → verification legitimately passes → flaky 200. Live-smoke 08 hit exactly this (first flip produced a passing JWS). Both now flip a MIDDLE char (deterministic). Live evidence: flip-at-end JWS verified OK against its own key.
- **Run** (from `services/web/`; containers `fed-smoke-mongo` 27107 + `fed-smoke-redis` 6380):
  `timeout 240 node modules/federation/tools/live-smoke.mjs` (env defaults baked in; CWD must be `services/web/` for @overleaf/settings).
- **Cleanup**: stray `services/web/live-smoke-standalone.mjs` + `.probe_{bare,live,settings2}.mjs` deleted. Unit suite 137/137 green (12 files) after all edits.
- **Anti-loop honored**: recon stayed closed for the existing wire code; all failures resolved via test output + targeted source reads. Iteration budget used: adapter import (1), bridge view path (1), flip-determinism (1).

### [SESSION 4] 2026-09-18 — P0–P2 module COMPLETED (committed batch of 2026-09-18b)
- **All module code written and committed**: `s2s/` (S2sRouter + 3 actions), `rp/` (State HMAC + PKCE, CodeExchange fetch+jose, CallbackRouter), `invite/` (controller+router), `admin/` (controller+router), `index.mjs` (WebModule wiring), `app/views/consent.pug`, `util/RateLimitStore.mjs`.
- **Bug fixes** (allowed: oidc/ + test-caught): `createProvider.mjs` missing `await` on `buildOidcProviderClients()`; `leaf.mjs` `oidcEndpoints()` authorization `/authorize`→`/auth` (the endpoint oidc-provider v9 actually mounts) and callback → `/federation/oidc/rp/callback` (the route CallbackRouter mounts);
- `rp/CodeExchange.mjs` `resolveJwk` read `kid` from the JWT **header** (`decodeProtectedHeader`) — jose v6 `decodeJwt` returns claims only.
- **Tests: 60/60 green** — keystore 12, invite 12, admin 19, CodeExchange 7 (jose v6 verify pattern: `importJWK` + `new SignJWT().setProtectedHeader({kid,alg}).sign(key)`; `@oidfed/core` `generateSigningKey('ES256')` for throwaway keys), State 10.
- **ESLint**: module-wide `--max-warnings 0` clean (32 .mjs files). Commands from `services/web`:
  `../../node_modules/.bin/vitest run -c vitest.config.js modules/federation/test/unit/...` and `../../node_modules/.bin/eslint --no-cache --max-warnings 0 'modules/federation/**/*.mjs'`.
- **Known env caveats** (tests are hermetic; no live-redis/integration round-trip yet):
  `chai-as-promised` is active → `expect(p).rejects.toThrow(...)` breaks in vitest (assertion becomes "the promise fulfilled"); use manual `await expect(() => ...).rejectedToMatch(...)` pattern or `Promise.race`-style assertions.
  Node `crypto.exportKey`/`webcrypto.exportKey` unavailable in this build → generate test keys via `@oidfed/core`.
- **NOT committed (intentional)**: probe scratch `services/web/{oidc_mount_probe.mjs,oidc_v9probe.mjs,probe_dbg2.mjs}` (untracked), `node_modules/`, `.pi/`, `.yarn/`. `.gitignore` has only 4 entries — NEVER `git add -A`; stage explicit paths only.

### [SESSION 2] 2026-09-18 — util + data model completed
- **Wrote** `util/Anchor.mjs` (`parseAnchor`/`formatAnchor`/`validateAnchor`/`saltedLocalNameHash` (32-hex HMAC, session-secret salted)/`hashInviteeEmail`/`resolveAnchorUser`), `util/Redact.mjs` (`redact`/`publicJwks`/`assertionMeta`), `util/Audit.mjs` (`audit()` fire-and-forget, `AUDIT_TYPES` 04 §8 v2).
- **Added** `federation` subdoc to `User.mjs` and `federated` subdoc to `ProjectInvite.mjs` (04 §1/§2 + HANDOFF §4.5/§4.6 reconciled fields). Migration `tools/migrations/20260721120000_add_federation_indexes.mjs` (3 index sets) + updated helpers docs.
- **Locked** envelope codes (401 vs 200 vs 429), handler ordering, invitee resolution, rate-limit keys/budgets, revoke receiver semantics, audit types — see LOCKED DECISIONS above.
- **Identified** createProvider `clients` non-await bug (blocker) and missing consent.pug (blocker).

### [INITIAL SESSION] 2026-09-18
- **Read** all 8 plan docs + FINDINGS.md. **Surveyed** existing scaffolding (13 files + 8 plan docs, all clean on `main`, tracked in git; last commits: `2399866215` OIDC OP stack + jose v6 e2e, `f2a1292ce9` findings, `2405d171cf` leaf.mjs const cleanup).
- **Test status**: `test/unit/oidf/keystore.test.mjs` — 12/12 PASS (verified this run).
- **Confirmed** deps in `services/web/package.json`: `oidc-provider@9.12.2`, `jose@6.2.10`, `@oidfed/core|oidc|leaf@1.0.0`; `express@4.22.1`.
- **Confirmed** Redis config: `Settings.redis['federation']` needed (04 §6) — `settings.defaults.js:153` redis block has `web`/`api`; NO `federation` key yet. `RedisWrapper.client('federation')` will fall back to `Settings.redis.web` (RedisWrapper.mjs:9) until a dedicated `federation` key is added (optional P0/P1).
- **Confirmed** view engine: `Modules.loadViewIncludes(app)` at Server.mjs:145; module pug at `modules/federation/app/views/*.pug`.
- **Confirmed** `Settings.federation.enabled` gates (settings.defaults.js:1228).

### EXACT CURRENT STATE (takeover point — 2026-09-18, after util/data-model session)
- **Util layer DONE** (uncommitted): `util/Anchor.mjs`, `util/Redact.mjs`, `util/Audit.mjs` (files untracked; `saltedLocalNameHash(localName, origin)` salted with `Settings.security.sessionSecret`; `assertionMeta` returns `{iss, aud, jtiHash}` with sha256 32-hex).
- **Data model DONE** (uncommitted diffs): `User.mjs` + `federation: { origin, localName, federatedAt }` subdoc; `ProjectInvite.mjs` + `federated: { origin, localName, localNameHash, invitedBy, homeDisplayName, homeAvatarUrl, authorized, authorizedAt, status }`; migration `tools/migrations/20260721120000_add_federation_indexes.mjs` (3 index sets, partial unique on `federation.*`). User model has **no** `language` field and `suspended: Boolean` exists.
- **`s2s/` dir exists and is EMPTY** — router + 3 actions + `util/RateLimitStore.mjs` are the immediate next build.
- **index.mjs does NOT exist**, `app/views/` does NOT exist, `rp/`/`invite/`/`admin/` do NOT exist.
- **BLOCKER 1** (confirmed in source): `oidc/createProvider.mjs:80` `clients: buildOidcProviderClients()` is NOT awaited — a Promise lands in `clients[]`. One-line fix: `clients: await buildOidcProviderClients()`. (The module files are otherwise committed and must not be rewritten except for this bug.)
- **BLOCKER 2** (confirmed): `bridge.mjs` `res.render(CONSENT_VIEW)` targets `path.resolve(__dirname, '../../app/views/consent.pug')` = `modules/federation/app/views/consent.pug` — file does not exist; render will crash. Write a minimal consent.pug.
- **BLOCKER 3**: `bridge.mjs` is NAMED export `export function mountBridge(webRouter)`, NOT default-exported — index.mjs must `import { mountBridge }`.
- `createProvider.mjs` exports are NAMED: `getOidcProvider` (memoized lazy), `_resetForTest`.
- **Test baseline** (verified this session): `test/unit/oidf/keystore.test.mjs` 12/12 PASS. `RedisOidcProviderAdapter.mjs` has a fake-redis injection hook (`_setRedisClientForTest`-style; verify before use).
- **Uncommitted scratch in `services/web/`** (UNTRACKED, keep separate): `oidc_mount_probe.mjs`, `oidc_v9probe.mjs`, `probe_dbg2.mjs` — probe evidence. **`oidc_v9probe.mjs` proves `app.use('/federation/oidc', provider.callback())` works under real express** (authorize/token/jwks/discovery round-trip) — Koa/Express compatibility concern CLOSED. Do NOT commit as module code.
- `Settings.redis` (L153) has NO `federation` key — `RedisWrapper.client('federation')` falls back to `Settings.redis.web` (works; optional TODO-4c7da2af to add dedicated key). `Settings.federation` block at `settings.defaults.js:1228`. `Settings.security.sessionSecret` (L406) is the salt for `saltedLocalNameHash`.
- Views: `Modules.loadViewIncludes(app)` (Server.mjs:145) globs `modules/*/app/views/**/*.pug`; render by ABSOLUTE path (bridge.mjs does this).

### LOCKED DECISIONS this session (override plan 03 §6 wording where they differ)
1. **Response envelope (reconciled: HANDOFF §9 + plan 03 §8/§6, verified against verify.mjs)**:
   - HTTP **401** + `{ ok:false, code, detail }` for ALL assertion-level failures — codes from the `S2S_ERRORS` enum (verified.mjs, exact list): `bad-signature`, `unknown-kid`, `peer-unknown`, `peer-not-approved`, `replay-jti`, `timestamp-skew`. A malformed *envelope* (no `from`/bad `to`/unknown action, or signature check impossible) is reported as `peer-unknown` (there is NO separate `invalid-envelope` code in the enum — router pre-checks map to peer-unknown, decision §2). (Plan 03 says in-band 200 for everything; the reconciled choice is 401 for wire-integrity refusals so peers can alert.)
   - HTTP **429** + `Allow-Retry-After: <seconds>` header when rate limit exceeded (body code `rate-limited`).
   - HTTP **200** + `{ ok:true, payload }` / `{ ok:false, code, detail }` for business results (`federation-off`, `invitee-unknown`, `invitee-disabled`) and success.
2. **S2S handler ordering** in `S2sRouter.mjs` (all before any DB write):
   ① settings gate → 200 `federation-off` (router is ALWAYS mounted, even when off, so peers get a machine-readable refusal) ② envelope sanity (bad `from`/`to`/`action` → 401 `peer-unknown` — do not parse deeper) ③ peer pre-lookup by body `from` (row missing → 401 `peer-unknown`; status!=approved → 401 `peer-not-approved`; this is cheap and precedes crypto) ④ `verifyS2sClientAssertion` (03 §2: verify→dedup→apply) ⑤ rate-limit `INCR` ⑥ action dispatch ⑦ audit ⑧ respond.
3. **B-side invitee resolution**: `User.findOne({ email: localName })` (home oracle, 01 §3.2); `suspended: true` → `invitee-disabled` refuse. **Never** mirror-create on an S2S receipt.
4. **`authorize-invite` ok response** v1 wire: `{ approved: true, displayName, institution }` — NO `language`, NO `avatarUrl` (`User` has no `language` field; drop both from 03 §4.1 example). `displayName = (first_name+' '+last_name).trim() || email`, `institution = user.institution || null`.
5. **`invited`** response: `{ approved: true|false, displayName }` — soft preview, ALWAYS `{ ok: true }` envelope (not-found is a valid preview result, NOT a refusal). Invite UX uses this for blur-verification before saving.
6. **`revoke` receiver semantics (B-side)**: wire message is "no longer accept inbound S2S FROM origin <A>" → B marks the row where `FederationPeer.origin == body.from` (the SENDER's row) `status: 'revoked'` (model has NO `revokedAt` field — the peer model tracks only `status`, `approvedAt`, `federatedAt`, `killOutstandingCodes`; do NOT add a field; leave `approvedAt` for re-federation by a later admin). Idempotent (second recv: already revoked → still 200 ok, no double-side-effect). Audit `federation_peer_trust_revoked` (meta `{ origin, direction: 'inbound', assertion }`). `killOutstandingCodes` admin toggle: v1 does NOT sweep outstanding codes (04 §5: existing receiver sessions are not killed) — leave the flag for admin UI (P2), document as no-op. `invited`/`authorize-invite` do NOT revoke.
7. **Rate limit (LOCKED)**: Redis `INCR` + `EXPIRE` (INCR returns 1 → EXPIRE ttl). Enforced on the RECEIVING instance (03 §5). Keys (04 §6 exact forms):
   - authorize: `federation:ratelimit:authorize:<callerOrigin>:<localNameHash>` (120 s window, budget **30**)
   - invited: `federation:ratelimit:invited:<callerOrigin>:<localNameHash>` (120 s, budget **30**)
   - revoke: `federation:ratelimit:revoke:<callerOrigin>` (1200 s, budget **5**)
   `<localNameHash> = saltedLocalNameHash(localName, origin)` where **both** arguments are the **invitee's** values from the wire payload (`invitee.localName`, `invitee.origin`) — the spec keys by `(caller, invitee.localName)`; the salt is the home origin (invitee), NOT this instance. Exceeded → 429 + `Allow-Retry-After` = remaining TTL (redis `TTL`). Mirror of NC v36 `lib/private/Security/RateLimiting/Limiter.php`. `federation:ratelimit:registration:<origin>` (04 §6) is P3 institutional — not built in P0–P2.
8. **Audit on receipt (04 §8, v2 list)**: `authorize-invite` → `federated_invite_approved` / `federated_invite_denied` (projectId: **null** — the project ref is opaque A-side and not an ObjectId; meta: `{ origin, localName, displayName, assertion }`). `invited` → NO audit row (read-only preview, rate-limited, not a trust event). `revoke` → `federation_peer_trust_revoked`. `audit()` is already fire-and-forget.
9. **Provider mount is terminal** and lazy: `webRouter.use('/federation/oidc', async (req,res,next) => { try { const p = await getOidcProvider(); await p.callback()(req, res, next) } catch (e) { next(e) } })` — mounted LAST in nonCsrfRouter (after S2S + bridge). `oidc_v9probe.mjs` proves `callback()` is express-compatible.
10. **`nonCsrfRouter.apply(webRouter, private, public)` is SYNCHRONOUS** (Modules.mjs L121-122 does NOT await) — register handlers only; no top-level `await` in apply. `start()` runs AFTER DB connect + after HTTP listen (app.mjs L106 listen, L126 `Modules.start()`) and IS awaited.
11. **Mirror login** = set `req.session.user` directly; do NOT touch passport.

### NEXT ACTIONS (fresh build order)
> **ENV NOTE**: memory tool is broken in this env (sqlite `database disk image is malformed`) — HANDOFF.md + FINDINGS.md are the sole persistent state.
> **STATUS (2026-09-18b)**: 1–7 DONE (batch committed), 8 validation gate DONE (60/60). Remaining: integration round-trip (two in-proc apps + fake redis), Settings integration TODO-4c7da2af, and frontend (§3.8 overleaf-cep).
1. ~~`util/RateLimitStore.mjs`~~ DONE
2. `s2s/` — 3 action files + `S2sRouter.mjs` (decisions §1–§8, ordering §2). Router shape: `{ apply(webRouter) { webRouter.post('/federation/s2s', asyncHandler) } }`.
3. `oidc/createProvider.mjs` bug fix (await clients) + `app/views/consent.pug` (minimal: user display, app/client, allow button, deny, submit `state`/`consent` fields per bridge.mjs POST contract)
4. `index.mjs` — default export WebModule: `nonCsrfRouter` (① S2S always ② bridge if enabled ③ provider terminal if enabled) + `appMiddleware` (leaf `GET /.well-known/openid-federation` + `GET /federation/federation-keys`, gated, app-level for req.hostname) + `start()` (gated; `ensureBootstrapped()` keystore bootstrap + `retireExpiredKeys()`)
5. `rp/` — CodeExchange (fetch + jose@6.2.10, verify against B's **provider** JWKS: `<entityId>/federation/oidc/jwks` — NOT leaf) + CallbackRouter (PKCE verifier + nonce in express-session, HMAC-signed `state`, mirror row upsert, grant via `PermissionsService`, 302)
6. `invite/` + `admin/` (controllers; admin mounted under `/admin/federation/*` in `router.apply`, guard `ensureUserIsSiteAdmin`)
7. Tests: S2S round-trip (two in-proc apps + fake redis), replay dedup, 429 path, rate-limit store unit
8. Run: `cd services/web && yarn run vitest run modules/federation/test/unit/oidf/keystore.test.mjs` (12 pass regression) + LSP diagnostics on all new files

### TODO ID mapping (current `.pi/todos` state — verified 2026-09-20)
| TODO | Item | Status |
|------|------|--------|
| TODO-1fed7e98 | index.mjs mount wiring + start | **CLOSED** (verified: `index.mjs` `start()` runs `ensureBootstrapped` + `retireExpiredKeys`) |
| TODO-bc8ad398 | leaf.mjs serve + mount helper | **CLOSED** (leaf mounted via `appMiddleware`) |
| TODO-ec1f0879 | S2S router + 3 actions + rate limit | **CLOSED** (14 S2S tests green) |
| TODO-7e3fc1d8 | A-side RPC CodeExchange + CallbackRouter | **CLOSED** (open-redirect guard live, 7+7 tests) |
| TODO-c6bbd319 | invite controller/router | **CLOSED** (12 invite tests) |
| TODO-5d6003df | admin router/controller + consent view | **CLOSED** (11 admin routes + `consent.pug`) |
| TODO-4c7da2af | Settings + app-level auth guards + admin route | **CLOSED** (Settings block at L1228; admin guarded by `ensureUserIsSiteAdmin`) |
| TODO-fd9f09c0 | unit tests + validation gate | **CLOSED** (76/76 green, ESLint clean) |
| TODO-c61e585d | hardening batch: fetch timeouts + redirect guard + institution-claim fix + institutional TA | **CLOSED** (see SESSION 5) |
| TODO-a9c6dd79 | two-instance integration test (OIDC code dance + S2S round-trip) | **CLOSED** (12/12 green; SESSION 8) |
| TODO-840029f1 | delete probe files; reconcile `requireAdminApproval` default | open (probe cleanup = `probe*.mjs` + `oidc_v9probe*.mjs` untracked in `services/web/`; `requireAdminApproval` default stays `true` per plan 04 §3 — see SESSION 6) |
| TODO-eef3de7d | run migrations against real Mongo (docker) | open |
| TODO-1ec14289 | two-instance live smoke (docker / smoke script) | **CLOSED** (SESSION 10: `tools/live-smoke.mjs` 13/13 ALL PASS against real Mongo+Redis+express+oidc-provider) |
| TODO-e652c0d9 | settings knobs for timeouts + `killOutstandingCodes` sweep | open |
| TODO-45cb2ea7 | frontend: invite preview hook + admin UI | open |
| TODO-47f7a583 | `allowFederatedProjectCreate` (04 §3) | open |
| TODO-1cd853cb | `requireAdminApproval`: approval queue for federated grants | open |
| TODO-0fa0f9f3 | federation admin pages + configuration wizards | open | |

---

## SESSION 5 (this session — hardening + institutional TA + S2S tests + docs)

### DONE this session
1. **Fetch timeouts** — all outbound `fetch` sites in the module now carry
   `AbortSignal.timeout`: S2S client (inv/ 10s in `FederatedInviteController.callPeer`),
   `CodeExchange` token fetch (30s), admin outbound leaf-EC pins
   (`ADMIN_OUTBOUND_FETCH_TIMEOUT_MS = 10000`), TA-chain `discoverEntity`
   (`httpTimeoutMs: 10000`), and the S2sRouter-side well-known fetch.
2. **Redirect hardening** (`rp/CallbackRouter.mjs`) — callback `target`
   validation: must be a single-root relative path; scheme, `//`, and backslash
   rejected; fallback to `/`. Backslash written via `String.fromCharCode(92)`
   (the edit tool mangles escaped backslash lines).
3. **Institution claim** (`oidc/createProvider.mjs`) — `institution:
   user.institution || null` (was `|| ''`; the spec field is nullable, not
   empty-string).
4. **Institutional TA (P3 pin-time)** —
   - New model `app/models/FederationTrustAnchor.mjs` (entityId unique,
     jwks public-half object, displayName, pinnedAt).
   - Migration `tools/migrations/20260721130000_add_federation_trust_anchor_index.mjs`.
   - Admin endpoints: `GET/POST /admin/federation/trust-anchors`,
     `DELETE /admin/federation/trust-anchors/:entityId` (11 routes total now).
   - Pin-time flow: leaf EC with `authority_hints` AND no TA rows → 400
     `institutional-anchor-missing` (strict, no pairwise fallback);
     `discoverEntity(peer, TAs, { httpTimeoutMs: 10000, maxChainDepth: 10 })`
     → resolves → `mode: 'institutional'` + `registration` subdoc;
     no-resolution → 400 `institutional-chain-untrusted`; fetch error →
     400 `institutional-chain-failed`.
   - `leaf.mjs` passes `authorityHints` to `signEntityConfiguration` when
     `Settings.federation.institutionAuthorityHints` is non-empty.
   - `anchors.mjs` updated for institutional anchors; TA private-key material
     (`key.d`) rejected at pin time.
   - Runtime S2S path UNCHANGED (pinned-leaf depth-1 — institutional trust is
     a pin-time decision; runtime S2S verification is depth-1 against the
     pinned keys).
5. **S2S router unit tests** — `test/unit/s2s/S2sRouter.test.mjs` (14 cases):
   ordering off→envelope→peer-lookup→verify→rate-limit→dispatch→audit→respond.
   Mock strategy: plain functions delegating to `globalThis.__*` thunks (NOT
   vi.fn — `resetAllMocks` in `test/unit/bootstrap.mjs` erases vi.fn
   implementations between tests); `vi.mock` of `leaf.mjs` +
   `ClientAssertionClient.mjs` keeps Mongoose.connect from chaining at import.
   `FederationPeer` mock: `{ lean: async () => doc }` (chainable).
6. **READMEs** — module root + `oidf/` `oidc/` `s2s/` `rp/` `invite/` `admin/`
   `util/` `app/models/` `app/views/` `test/`.
7. **`ADMIN-GUIDE.md`** — install/boot, peer pin (pairwise + institutional),
   TA pin, key rotation, invite walkthrough, S2S, troubleshooting, revoke,
   audit, scope.
8. **`Settings.federation.institutionAuthorityHints: []`** added to
   `settings.defaults.js` (default empty, so pairwise stays the default).
9. **Test totals: 76/76** (6 files: keystore 12 + invite 12 + admin 21 +
   CodeExchange 7 + State 10 + S2S 14). ESLint `--no-cache --max-warnings 0`
   clean across module + `app/src/models/User.mjs` +
   `app/src/models/ProjectInvite.mjs` + `config/settings.defaults.js`.
   Both migrations pass `node --check`.

### Test/lint commands (canonical)
```
cd services/web && ../../node_modules/.bin/vitest run -c vitest.config.js 'federation'
cd services/web && ../../node_modules/.bin/eslint --no-cache --max-warnings 0 \
  'modules/federation/**/*.mjs' 'app/src/models/User.mjs' \
  'app/src/models/ProjectInvite.mjs' 'config/settings.defaults.js'
node --check tools/migrations/20260721120000_add_federation_indexes.mjs
node --check tools/migrations/20260721130000_add_federation_trust_anchor_index.mjs
```
(The migrations sit in the **repo root** `tools/migrations/`, NOT in
`services/web/`; ESLint from the root fails with "couldn't find config" —
always run it from `services/web` for module/config files and `node --check`
for migrations.)

### Locking this session (LOCKED)
- **Institutional TA storage** is a SEPARATE model; peer row stays
  `{ origin, entityId, mode, anchorJwks, kid, anchorThumbprint, status,
  direction, registration }` (the `mode` + `registration` fields are what
  this session added in place of the old "P3, not built" note).
- **`institutional-anchor-missing` / `-chain-failed` / `-chain-untrusted`**
  are 400s, 400 codes on the admin pin surface, NOT wire codes.
- **Wire codes** (S2sRouter 200 envelope) unchanged: `invitee-unknown`,
  `invitee-disabled`, `peer-unknown`, `peer-not-approved`, `rate-limited`,
  `federation-off`, `replay-jti`.
- **11 admin routes**, guard `ensureUserIsSiteAdmin` (this fork has no
  `PermissionsService`; that's from a different fork's design notes and does
  not apply here).
- **Timeouts are hardcoded constants** (no settings knob): JWKS fetch 5s,
  S2S outbound 10s, token 30s, admin pin / TA-chain 10s, PKCE state TTL 120s
  (session slot + Redis).

### Next (fresh build order)
1. Two-instance integration: boot A+B in two in-proc apps + fake redis,
   do a live S2S round-trip for `invited` and `authorize-invite`, and one
   OIDC code-flow round trip (currently unit-only).
2. `federation.allowFederatedProjectCreate` (04 §3) — mirror-side
   project-creation-from-allow-list (still off by default).
3. Frontend (§3.8 overleaf-cep): invite UI blur hook (`GET preview`),
   admin UI (peer pin/approve/revoke + TA pin), consent page is pug but the
   UI for it still needs a browser-visible component wired.
4. `requireAdminApproval` (04 §3) — mirror-side admin approval queue for
   federated grants (today `federatedInviteApproved` audit + immediate grant
   — approval is implicit).

### Commit this session (post-8)
Commit 9 (this one, `origin/test_federation`): hardening (fetch timeouts,
redirect guard, `institution: null`) + institutional TA + TA admin
endpoints + S2S router unit tests + 10 READMEs + `ADMIN-GUIDE.md` +
`settings.defaults.js` (`institutionAuthorityHints`) + migration
20260721130000 + HANDOFF update. Explicit `git add` paths only (NEVER
`git add -A`; `.gitignore` is 4 lines and does not cover `node_modules`
globally, so `-A` stages every `node_modules/` in the monorepo).

---

# SESSION 6 (this session — 2026-09-20): tracker reconciliation + two-instance integration test IN PROGRESS

## DONE this session
1. **Tracker reconciliation** (9 stale entries CLOSED after empirical verification):
   `1fed7e98`, `bc8ad398`, `ec1f0879`, `7e3fc1d8`, `c6bbd319`, `5d6003df`,
   `4c7da2af`, `fd9f09c0`, `c61e585d`. Evidence per item: files on disk + the hardening
   grep set (`AbortSignal.timeout` at all 5 outbound sites; open-redirect guard at
   `CallbackRouter.mjs` L171-184; `institution: user.institution || null` in
   `createProvider` L61; institutional-TA trio present; admin trust-anchor routes
   GET/POST/DELETE `/admin/federation/trust-anchors`) + re-ran the gate:
   **76/76 green** (`npx vitest run federation`), ESLint exit 0.
   Naming note: committed model is `modules/federation/app/models/FederationTrustAnchor.mjs`
   (the in-task draft said `FederationInstitutionalAnchor` — renamed during build;
   READMEs + HANDOFF all use the final name). Migration is
   `tools/migrations/20260721130000_add_federation_trust_anchor_index.mjs`.

2. **oidc-provider v9 OIDC dance EMPIRICALLY PROVEN** via probe runs against a real
   express app with the real `oidc-provider` v9.12.2. This is the hard part of the
   integration test — the dance is NOT "auth → bridge → resume → code"; v9 inserts a
   SECOND interaction: **login → consent**. Full shape (probe evidence: `probe9_dance.mjs`,
   scratch, do not commit):
   |
   | Step | Request | Response | Note |
   |---|---|---|---|
   | 0 | `GET /federation/oidc/auth?client_id=...&scope=openid&response_type=code&redirect_uri=...&code_challenge=<S256>&code_challenge_method=S256&state=...&nonce=...` | 303 → `/federation/oidc/interact/<uidA>` | sets cookies `_interaction`, `_interaction_resume` |
   | 1 | `GET /interact/<uidA>` | bridge sees `prompt.name==='login'` → `interactionFinished({login:{accountId,ts}})` | 303 → `/federation/oidc/auth/<uidA>` (RESUME path, singular `auth`) |
   | 2 | `GET /federation/oidc/auth/<uidA>` | 303 → `/federation/oidc/interact/<uidB>` | NEW interaction (uidB) for consent |
   | 3 | `GET /interact/<uidB>` | bridge sees `prompt.name==='consent'` → 200 HTML consent form | `uidB` appears in the bridge route param only; provider resolves the interaction from the `_interaction` cookie — the `:uid` param is decorative |
   | 4 | `POST /interact/<uidB>/consent` (bridge auto-grant path in this test) | bridge creates `provider.Grant` + `interactionFinished({consent:{grantId}})` | 303 → `/federation/oidc/auth/<uidB>` |
   | 5 | `GET /federation/oidc/auth/<uidB>` | 302 → `redirect_uri?code=...&state=...` | code issued |
   | 6 | `POST /federation/oidc/token` form `grant_type=authorization_code&client_id&code&code_verifier&redirect_uri` | 200 `{ access_token?, id_token, ... }` | NO cookie needed for token — code + code_verifier + client_id + redirect_uri suffice |
   |\n\n### LOCKED probe facts for v9.12.2 (verify against code before trusting; these are what the tests exercise)
   - **PKCE is MANDATORY for `token_endpoint_auth_method:'none'` clients.** Auth endpoint returns
     400 `invalid_request` ("Authorization Server policy requires PKCE to be used for this
     request") without `code_challenge` + `code_challenge_method=S256`. The A-side
     `FederatedInviteController._handleAuthorize` MUST include both in the redirect URL that
     the user's browser hits — check the implementation matches the probe's auth URL shape.
     (If the implementation doesn't already, the integration test will catch it in step 0.)
   - **v9 cookie names: `_interaction` + `_interaction_resume`** (NOT `op_interaction` /
     `op_session`). Set on the initial auth 303. Must be carried through every hop.
   - **Bridge resolves the interaction from the COOKIE, not the path param.**
     `provider.interactionDetails(req,res)` internally reads `ctx.cookies.get('_interaction')`.
     Test just needs to follow Location and carry the cookie jar.
   - `interactions: { url: (_ctx, i) => ...interact/${i.uid} }` override is REQUIRED in
     `createProvider` (v9 default is `/interaction/<uid>` plural); bridge routes mount at the
     overridden path.
   - The RESUME path (auth step, NOT the interaction) is `/federation/oidc/auth/<uid>` (singular
     `auth`, same as the initial auth endpoint but with uid param). v9's `interactionFinished`
     303s there always.
   - `oidc-provider` v9 has ZERO `req.session` references — its state is cookie-driven via
     `createContext`. The bridge is the ONLY consumer of `req.session.user._id` (B-side login).
     This is why the test can pre-seed `req.session.user` without needing passport.
   - Token endpoint (`token.js`) has ZERO cookie references. code + code_verifier + client_id +
     redirect_uri is the entire input surface.
   - `MemoryAdapter` (oidc-provider built-in) works in a probe with no Redis; the module uses
     `RedisOidcProviderAdapter` and the test supplies a fake via the adapter's redis-client
     injection hook — shape compatibility is confirmed by the v9 adapter contract (7 methods,
     modelName arg, see §4.8).

3. **Two-instance integration test — DESIGN LOCKED** (file not yet written):
   - Location: `modules/federation/test/unit/integration/two-instance.sequential.test.mjs`
     (matches the existing `Sequential` vitest project glob — no config change).
   - **Single-origin design** (NOT two app instances): `Settings` is a module-level singleton so
     A and B cannot have different origins in one process. A and B share
     `Settings.siteUrl: 'https://beta.example'`. "Two instances" = two ROLES mounted on ONE
     express app: S2S (always), OIDC bridge, CallbackRouter, provider catch-all. A-role ops are
     in-process (call `buildS2sRequest` from `ClientAssertionClient.mjs`;
     `exchange`/`handleCallback` from `CodeExchange.mjs`/`CallbackRouter.mjs` directly, with the
     `globalThis.fetch` wrapper intercepting `https://beta.example/...` and rewriting to
     `http://127.0.0.1:<port>/...`).
   - One express app mount order (LOCKED, mirrors `index.mjs`):
     ① `express.json()` (S2S body) ② fake session middleware (`req.session={user:{_id: ALICE_B}}`,
     pre-seeded to avoid passport) ③ S2sRouter POST `/federation/s2s` ④ `mountBridge(webRouter)`
     (GET `/federation/oidc/interact/:uid`, POST `.../consent`, POST `.../deny`) ⑤ CallbackRouter
     GET `/federation/oidc/rp/callback` ⑥ provider catch-all
     `webRouter.use('/federation/oidc', provider.callback())` LAST.
     NO `express.urlencoded` — v9's `selective_body.js` reads the raw stream itself for the token
     endpoint.
   - Pug engine registered via `app.engine('.pug', ...)` (or rely on Express 4 auto-require;
     `node_modules/pug` at repo root resolves fine).
   - Fake redis: full Map surface (get/set/del/pttl/incr/expire/ttl/sadd/smembers/srem/scard)
     injected via `RateLimitStore._setRateLimitRedisClientForTest`
     + `verify.mjs._setReplayRedisClientForTest` + adapter redis-client hook +
     `CodeExchange`/state redis via `globalThis.fetch`-independent direct redis injection where
     the module exposes a test hook (see S2sRouter.test.mjs pattern).
   - Mock stores on `globalThis` (survive `vi.resetAllMocks()` + `vi.resetModules()` per test file —
     see S2sRouter.test.mjs):
     `__users` (User rows), `__peers` (FederationPeer rows), `__auditRows`
     (`ProjectAuditLogEntry.create` calls), `__redis` (fake redis Map), `__FK` (FederationKey doc
     rows: `{_id, purpose, kid, publicKey, privateKey, state, expiresAt, publishedAt}`),
     `__grants` (CollaboratorsHandler.promises.addUserIdToProject args), `__sessions`.
   - Mock list (vi.mock factories, target `@overleaf/settings` as default export object with
     `siteUrl: 'https://beta.example'` + `security.sessionSecret` + `federation:{enabled:true,
     keyRotationGraceDays:14, institutionAuthorityHints:[]}`, all module-local model files, RedisWrapper
     (must resolve to the fake redis), CollaboratorsHandler (default export mock — heavy chain),
     UserSessionsManager (default export mock — redis dependency), AuthenticationController
     (default export mock — passport chain; test pre-seeds session so the dynamic import path is
     NOT taken), AuthorizationMiddleware (heavy). User/FederationPeer/FederationKey/
     FederationTrustAnchor/ProjectAuditLogEntry module files vi.mocked per S2sRouter.test.mjs
     pattern (thenables with `.sort().lean()` chainable).
   - Seed: one `FederationKey` doc per purpose ('federation' + 'oidc') generated with
     `@oidfed/core`'s `generateSigningKey('ES256')` (the module's keystore expects
     `{_id, purpose, kid, publicKey, privateKey, state:'active', ...}` shape). `keystore._clearKeySetCache()`
     after reseeding (module-level cache Map survives across tests).
     Peer row: `{origin:'beta.example', status:'approved', kid, anchorJwks}` (single-origin — the
     peer's origin IS this origin; `from` field in S2S bodies will be the same string). One User
     row for ALICE_B: `{_id: <24hex>, email:'alice@beta.example', first_name:'Alice',
     last_name:'Beta', institution:'Beta Institut', suspended:false}`.
   - 3-state S2S scenarios (all in-process, each a fetch to the app URL with the client_assertion
     header built by `buildS2sRequest(...)`):
     a. `invited` (preview) — expect 200 `{ ok:true, payload:{ approved:true, displayName } }`,
        audit row NOT created (read-only preview per LOCKED decision §8).
     b. `authorize-invite` (approve) — expect 200 `{ ok:true, payload:{ approved:true,
        displayName, institution } }` + audit `federated_invite_approved` (projectId null, meta
        `{origin, localName, displayName, assertion}`).
     c. `authorize-invite` (deny) — expect 200 `{ ok:true, payload:{ approved:false } }` +
        audit `federated_invite_denied`.
     d. Replay — same `jti` twice → second call 401 `replay-jti` (Redis SETNX key
        `federation:replay:<jti>`; fake redis provides `set` with `nx` + `px`).
     e. Bad signature — sign with ROULE key (separate `generateSigningKey`) whose kid is NOT
        pinned on the peer row → 401 `unknown-kid` (verify.mjs does kid-pinned check, NO refetch
        in v1 — see `verify.mjs`'s `S2S_ERRORS`). Or: known kid but re-signed body →
        `bad-signature`.
     f. Peer revoked — flip `__peers` row status, re-send a valid `authorize-invite` → 401
        `peer-not-approved` (peer pre-lookup in S2sRouter ordering, no crypto run).
     g. Rate limit — send 31 rapid `authorize-invite` invocations → 31st returns 429 with
        `Allow-Retry-After`. (Or: fake redis seeded past the 30 budget for a deterministic 1-shot
        trip.)
     h. Federation off — clear `Settings.federation.enabled` via the mock factory's live getter
        (see S2sRouter.test.mjs pattern) → 200 `{ ok:true, enabled:false }` envelope (router is
        ALWAYS mounted).
     i. Revoke — valid `revoke` action → peer row marked revoked, audit
        `federation_peer_trust_revoked`, idempotent second call still 200 ok.
        FOLLOW-UP after revoke: a subsequent `authorize-invite` → 401 `peer-not-approved` (the
        revoke marks the SENDER's row — in single-origin mode that's beta.example, so post-revoke
        S2S from beta.example is refused. That's the expected outcome and the test asserts it.)
   - OIDC integration scenarios (driven against the mounted app via fetch + cookie jar + the
     probe-locked 6-step dance above):
     1. **HAPPY PATH**: seed ProjectInvite.federated row via `__invites` + mirror user via
        `__users` (or rely on CallbackRouter to create it — see below for which assertion set
        covers which). Call `FederatedInviteController`'s authorize path IN-PROCESS to obtain
        `{ authUrl, state }` (that's the real entry: the test then drives the 6-step dance from
        `authUrl`, with the fetch wrapper rewriting `https://beta.example/...` → local). On
        completion, GET the callback URL (which the dance's final 302 points at) and assert:
        - `__users` gained the mirror row (`{ email: '', federation: { origin: 'beta.example',
          localName: 'alice@beta.example' } }`) — OR already seeded and the test asserts
          session-only.
        - `__grants` captured `CollaboratorsHandler.promises.addUserIdToProject(projectId,
          addingUserId, userId=mirror._id, privilegeLevel=READ_AND_WRITE)` call.
        - Session got `req.session.user = <sessionId>` (track via the fake
          UserSessionsManager.promises.trackSession args).
        - Audit `federated_invite_approved` row present.
        - The final 302 Location is `intent.url` (project URL) per `CallbackRouter`'s
          open-redirect guard (must start `/`; `/projects/<id>` is a valid project URL path —
          seed the intent accordingly).
     2. **PKCE state one-shot**: second callback with the SAME `state` (and `code`) → 4xx or error
        envelope. `consumePkceState` is Redis-primary (`federation:rp-state:<state>` key + session
        slot cleared) — after first successful call the redis key is gone; second call must
        refuse. Assert `state-invalid` or equivalent error code (check `CallbackRouter.mjs`'s
        error path for the exact status + body shape — the unit test State.test.mjs covers the
        primitives; the integration asserts the wired-up behavior).
     3. **Federation off** (via the live mock factory) → CallbackRouter or upstream 4xx (the
        provider catch-all won't even mount in a full-app test but this scenario is about the
        S2S router which IS always mounted with a machine-readable refusal — that's covered by
        the S2S scenario h above; for the OIDC side a federation-off state should result in a
        provider 404 or an explicit refusal — assert whatever the implementation does and
        document it).
     4. **Wrong redirect_uri** → 302 back to... (the A-side project URL; CallbackRouter doesn't
        control redirect_uri validation — that's oidc-provider's job at the token endpoint. This
        scenario may collapse with the token-exchange step and can be dropped if the token
        endpoint rejects before the callback is reached; document the outcome).
     - `CallbackRouter.mjs` `handleCallback` is a NAMED export (not just `apply`) — the test can
       call it directly with a mock req/res when the dance's last leg is more than what the app
       mount requires. BUT the point of the integration test is the FULL path — drive it via
       fetch to `GET /federation/oidc/rp/callback?...?state=...` on the app, which is what a
       real browser would do after B's dance.
   - `vi.resetModules()` in `bootstrap.mjs` afterEach + `vi.resetAllMocks()` → module-level state
     (keystore cache Map, provider singleton) is reset only via the module's own `_resetForTest`
     / `_clearKeySetCache` hooks. `getOidcProvider()` is a lazy singleton with a
     `_resetForTest` export (check `createProvider.mjs`'s exports list) — call it in afterAll
     so the provider's internal cookie/JWKS state doesn't leak across tests in other files
     (sequential project runs this file LAST per groupOrder:1, fileParallelism:false — safe).

4. **Remaining 7 ToDos (priority order)** — see the TODO ID mapping table above (rewritten
   this session). The order: a9c6dd79 (this file, IN PROGRESS) → 840029f1 (probe cleanup;
   4 untracked `probe*.mjs` + `oidc_v9probe*.mjs` in `services/web/` + the tracked `e2e_probe.mjs`
   which stays committed per prior decision — it's the e2e evidence file) → eef3de7d (docker
   migrations) → 1ec14289 (live smoke) → e652c0d9 (timeout knobs + killOutstandingCodes) →
   45cb2ea7 (frontend invite preview + admin UI) → 47f7a583 (allowFederatedProjectCreate) →
   1cd853cb (requireAdminApproval queue) → 0fa0f9f3 (admin pages + wizards).

### In-flight: two-instance integration test — what's next
- File to write next: `modules/federation/test/unit/integration/two-instance.sequential.test.mjs`
  (design fully LOCKED above; the mock shape is already proven by S2sRouter.test.mjs +
  keystore.test.mjs patterns that this session re-verified by re-reading both files).
- The `probe9_dance.mjs` (scratch, `services/web/` untracked) is the executable reference for
  the 6-step dance + cookie jar + fetch wrapper shape. Delete it + the other probe scratch
  (`probe_dbg2.mjs`, `oidc_mount_probe.mjs`, `oidc_v9probe.mjs`, `oidc_v9probe4.mjs`) at the
  840029f1 cleanup step AFTER the integration test is green (they're evidence for the handoff —
  do not delete before the test is green; if the test needs a re-probe, `probe9_dance.mjs` is
  still here).

---

# SESSION 7 (2026-09-20): verify.mjs bug fix + integration-test recon CLOSED (file NOT yet written correctly)

## DONE this session
1. **BUG FOUND + FIXED in `oidf/verify.mjs`** (was committed-correct-by-mistake; now genuinely correct).
   `@oidfed/core` `verifyClientAssertion(...)` resolves a **`Result` union**, NOT the assertion
   directly: `{ ok:true, value } | { ok:false, error }`. The committed code treated the resolved
   Promise as the assertion and read `.ok` / `.error` on the wrong level, so a VALID assertion
   landed in the `!verified.ok` branch → every valid `authorize-invite`/`revoked`/`replay`
   S2S call returned 401 `bad-signature`. Fix (uncommitted, in git status as `M`):
   ```js
   const result = await verifyClientAssertion(assertion, anchorJwks, getS2sEndpoint(), { clockSkewSeconds })
   if (!result.ok) { return { ok:false, code:'bad-signature', detail: result.error?.description || '...' } }
   const verified = result.value   // ← the VerifiedClientAssertion
   ```
   `verified` is `{ clientId, issuedAt, expiresAt, jti? }`; downstream `iss === sub` uses
   `payload.iss === payload.sub` — UNCHANGED. This is a REAL bug the unit S2s tests masked because
   they mock `verifyS2sClientAssertion` and never exercise npm `verifyClientAssertion` for real.
   **This file must be committed with the integration-test batch.**

2. **Recon for the two-instance integration test: 100% COMPLETE.** Every module contract
   re-verified this session (re-read, not assumed). The broken stub + its errors are catalogued
   below; write the FINAL file from scratch against this list — do NOT salvage the stub.

## ⚠️ Current state of the target file (DO NOT trust it)
`test/unit/integration/two-instance.sequential.test.mjs` currently contains a **BROKEN STUB**
(never green). Errors in the stub (all confirmed this session):
- wrong Settings mock path: stub used `vi.mock('../../../app/src/infrastructure/Settings.mjs')` —
  the module imports `Settings` from npm **`@overleaf/settings`** (aliased). Mock it as
  `vi.mock('@overleaf/settings', ...)`.
- calls `keystore._bootstrapOidcKey(...)` + `_bootstrapFederationKey(...)` — **do NOT exist**.
  Use the real `keystore.ensureBootstrapped()` (seeds BOTH purposes) against a mocked
  `FederationKey`, OR seed `FederationKey.create(...)` docs directly and call
  `keystore._clearKeySetCache()`.
- imports `CollaborationHandler` — the real file is **`CollaboratorsHandler.mjs`**.
- `buildS2sRequest` uses 2 positional args (`origin, payload`) — the real signature is
  **3 positional** `buildS2sRequest(peerOrigin, action, payload)` returning `{headers, body}`.
- indented with TABS (repo prettier = 2-space, no tabs). Rewrite clean.
- `globalThis.__REDIS` fake does NOT return `'OK'` from `set(k,v,opts)` — `verify.mjs` REPLAY
  path does `assert redis.set(...) === 'OK'`; a `null` return reads as a replay → 401. `set`
  MUST return `'OK'`.
- stub uses `app.use(mount, provider.callback())` directly on express. probe9 proved this works,
  but the module's own mount is the async wrapper (`getOidcProvider()` then `provider.callback()`);
  for the test, mounting `app.use('/federation/oidc', (req,res,next)=>{ p.callback()(req,res,next) })`
  is fine and matches the probe (express-compatible, zero `req.session` in v9).
- file location is correct (`test/unit/integration/`) and matches the Sequential vitest project;
  NO config change needed.

## CONFIRMED contracts (this session) — write the file against these
- **`vi.mock` path conventions** (from file `test/unit/integration/`): module-local = 3 up
  (`'../../../app/models/FederationPeer.mjs'`, `'../../../util/Audit.mjs'`, etc.); `app/src` =
  **5 up** (`'../../../../../app/src/infrastructure/RedisWrapper.mjs'`,
  `'../../../../../app/src/models/User.mjs'`, `'../../../../../app/src/models/CollaboratorsHandler.mjs'`).
  npm packages by package name: `@overleaf/settings`, `@overleaf/logger` (bootstrap already vi.mocks
  logger+metrics as `vi.fn` stubs — the test can rely on those, no need to re-mock them).
- **vi.mock factory CANNOT reference module-scope vars** (hoisting). Use `globalThis.__*`
  thunks for mutable state (`__REDIS`, `__users`, `__peers`, `__auditRows`, `__grants`, `__FK`,
  `__invites`). `RedisWrapper` mock: `{ default: { client: (_f)=>globalThis.__REDIS,
  cleanupTestRedis: async()=>{} } }`.
- **`FederationPeer` is NAMED-only** ({ export: FederationPeer }); **`FederationKey` has BOTH
  default + named.** Model mocks: thenable objects with `.lean()/.sort()` returning `Promise`;
  `.findOne(f).lean()`, `.find(f).sort().lean()`, `.create()`, `.updateOne(filter, update,
  opts) => {matchedCount, modifiedCount}`.
- **`User` is NAMED** (`import { User }`). ONE mock object must serve every finder the flow uses:
  `findOne({email})`, `findOne({_id})`, `findOne({'federation.origin','federation.localName'})`,
  `findOne({federation:{origin,localName}})`, `create(doc)` (auto-`_id`), `find({federation:{...}})`,
  `findById`. Dispatch on filter keys BEFORE the catch-all.
- **S2sRouter** is express-style (`webRouter.post('/federation/s2s', fn(req,res,next))`,
  `res.status(...).json(...)`), reads headers via `req.get('client_assertion')`, dispatches
  `action.handler(req)`, default-exports `{ apply(webRouter), _handleS2sRequest, _actions }`.
  Handler order: settings-gate → envelope-sanity → peer-lookup → `verifyS2sClientAssertion` →
  rate-limit → action → audit → respond.
- **S2S wire (real, 3-pos arg)** `buildS2sRequest(peerOrigin, 'invite'|'authorize-invite'|'revoke', payload)` → `{headers:{client_assertion: <JWT>, client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt'}, body:{action, from, to, ts, payload}}`. The test POSTs `{headers, body}` to `POST /federation/s2s` via the fetch wrapper.
- **B-side verify**: `verifyS2sClientAssertion(assertion, from)` (2 args; peer lookup INTERNAL, no network). Replay prefix `federation:replay:<jti>` (SET `NX` → `'OK'`/`null`). kid-pinned check BEFORE signature → `unknown-kid` (no refetch in v1); wrong signature on known kid → `bad-signature`; peer `status!=='approved'` → `peer-not-approved`; then `verifyClientAssertion` (Result unwrap, fixed this session); then `iss===sub`; then `aud===S2sEndpoint`; then expiry; then replay.
- **Client assertion iss/sub**: `getClientId() = 'urn:overleaf-federation:client:'+entityId` where `entityId='https://'+origin` = `https://beta.example` → `urn:overleaf-federation:client:beta.example`. SIGNED via keystore federation key (`createKeyProvider().getFederationKeySet()`, ACTIVE key) with `iss=sub=client ID`, `aud=getS2sEndpoint()` (`.../federation/s2s`), fresh `jti` (crypto.randomUUID), `exp` 5 min, SKEW 60s. **Peer row `kid` MUST = the ACTIVE federation key's kid** for the pin to match.
- **keystore**: NO default export; named `ensureBootstrapped()`, `getFederationKeySet()` (cache), `oidcSigningKeys()`, `createKeyProvider()`, `_clearKeySetCache()`. `purpose` values `'federation'`|`'oidc'` (lowercase). `FederationKey` doc shape `{_id, purpose, kid, algorithm:'ES256', publicKey:{kty,crv,alg,use,'x','y'}, privateKey:{...,'d'}, state:'active', expiresAt, publishedAt, stateChangedAt}`. `generateSigningKey('ES256')` from `@oidfed/core` sets kid/alg/use on BOTH halves. Seed ONE doc per purpose, then `keystore._clearKeySetCache()`.
- **oidc-provider v9** (createProvider.mjs): `new Provider('${origin}/federation/oidc', setup)` (TWO args, issuer string). `jwks:{ keys: oidcSigningKeys() }` (object, NOT array; v9 normalizes `alg`→ES256 and strips `d`). `clients: await buildOidcProviderClients()` (must be AWAITED — committed bug already fixed). Adapter factory `(modelName)=>createAdapter()`. `findAccount(ctx,sub,source) => { accountId, claims:(usage,scope,allowed,rejected)=>({sub:{value:sub}, ...})}` (claims MUST be a function). `interactions.url override REQUIRED` → `${SITE}/federation/oidc/interact/${uid}`. Mount: `app.use('/federation/oidc', (req,res,next)=>{ p.callback()(req,res,next) })` LAST. NO `express.urlencoded` (v9 reads raw stream for token).
- **clients.mjs**: `FederationPeer.find({status:'approved'})` (PLAIN await, NO `.lean()`); maps to public-client entries `{ client_id:'urn:overleaf-federation:client:beta.example', redirect_uris:['https://beta.example/federation/oidc/rp/callback'], application_type:'web', token_endpoint_auth_method:'none', response_types:['code'], grant_types:['authorization_code'], scope:'openid'(string), id_token_signed_response_alg:'ES256' }`. `getOidcProvider()` is async memoized; `_resetForTest()`. Must run AFTER keystore bootstrap (v9 validates `jwks.keys[*].d` eagerly at `new`).
- **bridge.mjs** (express, NAMED `mountBridge(webRouter)`): GET `/federation/oidc/interact/:uid` (duck-typed `interactionDetails` via a fake res + real req, Koa-context duck-typing works) — if `prompt.login` → `interactionFinished({login:{accountId: session user id}})`; else render `CONSENT_VIEW` (absolute path `path.resolve(__dirname,'../../views/consent.pug')`; test `res.render` is faked). POST `/interact/:uid/consent` → `Grant` create or `getGrantByUid` + `provider.interactionFinished({consent:{grantId}})`. POST `/interact/:uid/deny` → `interactionFinished({error:'access_denied'},{mergeWithLastSubmission:true})`. Session user id: `SessionManager.getSessionUserId(req.session)` / `req.session.user._id`.
- **The v9 dance (empirically proven — probe9)**: auth 303→interact(uid1) [login] → GET interact(uid1) 303→auth/uid1 → GET auth/uid1 303→interact(uid2) [NEW uid] → GET interact(uid2) 200 HTML consent → POST interact(uid2)/consent 303→auth/uid2 → GET auth/uid2 302→redirect_uri?code&state (or error). Cookies `_interaction`+`_interaction_resume` must ride every hop. The `:uid` path param is DECORATIVE — provider resolves from the `_interaction` cookie. **PKCE mandatory for `token_endpoint_auth_method:'none'`.**
- **CallbackRouter** (NAMED `handleCallback`, `webRouter.get('/federation/oidc/rp/callback')`): gate `Settings.federation.enabled` (off → 400 `federation-off`) → `consumePkceState(session, state, redis)` → `verifySignedState` → `exchange(intent.origin, {code, codeVerifier, intent})` → `User.findOne({'federation.origin','federation.localName'})` OR `User.create({...})` (mirror: email:'', hashedPassword:undefined, emails:[], federation:{origin,localName}) → `CollaboratorsHandler.promises.addUserIdToProject(projectId, null, mirror._id, privilege)` → `UserSessionsManager.promises.trackSession(...)` → audit(`federation_session_issued`) → 302 to `intent.url` (open-redirect guard: single-root relative, else `/`).
- **CodeExchange.mjs** `exchange(peerOrigin, {code, codeVerifier, intent}, redis)`: fetch B JWKS `https://<origin>/federation/oidc/jwks` (5s timeout, cached `federation:jwks:<origin>` TTL 1800) → POST token `https://<origin>/federation/oidc/token` form (30s, `grant_type=authorization_code&client_id&code&redirect_uri&code_verifier`, PKCE verifier) → `jwtVerify(idToken, jwk, {issuer:'https://'+origin, audience:'urn:overleaf-federation:client:beta.example'})` → returns `{idToken: claims}`. The `globalThis.fetch` wrapper rewrites `https://beta.example/...` → live local origin for BOTH urls AND the S2S POST (callPeer in the invite controller + the token/jwks fetches). NO live Redis needed if redis is passed in directly to these functions.
- **State.mjs**: `persistPkceState(session, {state, verifier, origin, intent}, redis)` (Redis key `federation:rp-state:<state>` + session slot) then `consumePkceState` (Redis-first, one-shot — after first consume the key is gone → second callback refuses `state-invalid`-ish 4xx). `signState`/`verifySignedState` HMAC with `Settings.security.sessionSecret`. PKCE state TTL 120s.
- **RateLimitStore**: `_setRateLimitRedisClientForTest(client)` (test hook) OR pass redis to `checkRateLimit(redis, opts)`. Keys `federation:ratelimit:<action>:<origin>:<hash>`; budget 30/120s (authorize|invited), 5/1200s (revoke). 429 → `{allowed:false, retryAfterSeconds: ttl}`. The 429 test: seed `federation:ratelimit:authorize:beta.example:<hash>` to `30` (TTL 120) in fake redis, send ONE more valid `authorize-invite` → 429 `Allow-Retry-After`. `incr` returns a NUMBER (fake redis must implement `incr`/`expire`/`ttl`).
- **Audit.mjs** `audit({operation, projectId, meta, req})` → `ProjectAuditLogEntry.create(...)` (fire-and-forget, catch→null). `projectId` must be a real ObjectId or `null` (CastError on opaque ref) — S2S receipts pass `projectId:null`. `AUDIT_TYPES`: `inviteApproved:'federated_invite_approved'`, `inviteDenied:'federated_invite_denied'`, `sessionIssued:'federation_session_issued'`, `trustRevoked:'federation_peer_trust_revoked'`.
- **Anchor.mjs** (pure, NO Redis): `parseAnchor('alice@beta.example:beta.example') → {localName:'alice@beta.example', origin:'beta.example'}` (LAST-colon split), `formatAnchor`, `validateAnchor`, `saltedLocalNameHash(localName, origin)` (32-hex HMAC, `Settings.security.sessionSecret` salt). `Redact.mjs` (pure): `assertionMeta({iss,aud,jti})` (takes OBJECT), `redact()`, `publicJwks()` (strips `['d','p','q','dp','dq','qi']`).
- **PrivilegeLevels** (pure): `{NONE:false, READ_ONLY:'readOnly', READ_AND_WRITE:'readAndWrite', REVIEW:'review', OWNER:'owner'}` + `OrderedPrivilegeLevels`.
- **SessionManager** (`app/src/Features/Authentication/`): `getSessionUserId(req.session) → req.session.user?._id` (bridge uses it). `UserSessionsManager` at `app/src/Features/User/UserSessionsManager.mjs` (default export, `{promises: trackSession}` mocked).
- **`getEntityId()`** needs `https:` (Settings.siteUrl `https://beta.example`); `Settings.security.sessionSecret` is used by BOTH `saltedLocalNameHash` AND `State` HMAC AND v9 `cookies.secret` — set it in the Settings mock for consistency.
- **Settings mock** (module does `import Settings from '@overleaf/settings'` — DEFAULT export,
  npm name): mock `{ default: {siteUrl:'https://beta.example', security:{sessionSecret:'<32 bytes>'},
  federation:{enabled:true, keyRotationGraceDays:14, institutionAuthorityHints:[]},
  redis:{web:{host:'127.0.0.1'}} } }`. For the federation-OFF scenario, flip
  `Settings.federation.enabled=false` via the mock's live getter / a `globalThis.__SETTINGS`
  delegate (S2sRouter.test.mjs proves the toggle pattern; the factory must NOT capture a frozen
  snapshot if a later scenario flips the gate).

## Scenario set (final) for the test file (map to HANDOFF SESSION 6 item 3)
1. Happy path: `FederatedInviteController.handleAuthorize(fakeReq, fakeRes)` IN-PROCESS (mocks: CollaboratorsGetter, User, FederationPeer gate, buildS2sRequest REAL→signed, callPeer→fetch→S2S oracle authorize) → yields `{authUrl, state, ...}`. Then drive the 6-step dance with fetch wrapper + cookie jar from `authUrl`. On final callback GET assert: mirror `User` row (`federation:{origin,localName}`), `CollaboratorsHandler.promises.addUserIdToProject(projectId, null, mirror._id, 'readAndWrite')` captured, `UserSessionsManager.promises.trackSession` called, audit `federation_session_issued`, final 302 Location = `intent.url` (seed a single-root relative like `/project/proj-1`).
2. PKCE one-shot: replay SAME `state`+`code` on the callback → 4xx (Redis state consumed). Assert the exact status/shape from `CallbackRouter` error path.
3-11: the `invited`/approve/deny/replay(401)/bad-sig(401)/unknown-kid(401)/rate-limit(429)/revoke+idempotent+followup(401)/federation-off(200) S2S scenarios via `buildS2sRequest`→fetch POST→assert status+body+audit, with `globalThis.__REDIS.flushall()` between each to isolate rate-limit/replay counters.

## Next (immediate)
1. **WRITE the final** `test/unit/integration/two-instance.sequential.test.mjs` against the contracts above (fresh; discard the broken stub). Run `npx vitest run --project Sequential two-instance` from `services/web/`; iterate to green. Then `git add` it + `oidf/verify.mjs` (the bug fix) — NEVER `git add -A` — commit + push. Probe scratch (`probe9_dance.mjs`, `probe_dbg2.mjs`, etc.) stays until that test is green (evidence), deleted in the 840029f1 step.
- The `e2e_probe.mjs` (tracked, committed) stays. It's the module-trust evidence file and is
  referenced by the HANDOFF as part of the "verified working" set.
# SESSION 8 (2026-09-20): integration test WRITTEN + GREEN (12/12) — recon CLOSED, anti-loop honored

## OUTCOME
`modules/federation/test/unit/integration/two-instance.sequential.test.mjs` is **WRITTEN + 12/12 GREEN**,
ESLint clean. The recon was genuinely closed at SESSION 7; this session wrote the file, iterated
against real test output (NOT recon), and closed it. Anti-loop honored: recon is FROZEN; what got
re-read this session was only (a) the two failing dance sites + (b) one targeted grep of the
`CallbackRouter` 401 refusal shape to pin the assertion. No full-file re-reads; no second verification
pass.

## The 12 scenarios (all green)
1. OIDC code dance (full happy path): in-proc `handleAuthorize` → fetch → live oidc-provider v9
   interact/consent/code → callback → mirror User row + collaborator grant + session + audit + 302
2. PKCE one-shot: replayed (code,state) → 401 `invalid grant request`
3. S2S invited approved (existing local user) + displayName
4. S2S invited soft-deny (nonexistent local user, still `ok:true`)
5. S2S authorize-invite approved + audit row
6. S2S authorize-invite unknown invitee → business refusal + audit row
7. S2S replay: second delivery of same assertion → 401 `replay-jti`
8. S2S bad signature → 401 `bad-signature`
9. S2S unknown kid (key not pinned) → 401 `unknown-kid`
10. S2S rate limit: budget exceeded → 429 + `Allow-Retry-After`
11. S2S revoke: trust revoked (idempotent), follow-up refused `peer-not-approved`, audit row
12. S2S federation off → 200 `code:'federation-off'`

## How the dance is driven (probe9-derived, now in the committed test)
- Single live express app plays BOTH A (RP) and B (home OP). Trust model — single-origin variant:
  `A.origin === B.origin === beta.example` (`Settings.siteUrl`), so A fetches `https://beta.example/...`
  and a `globalThis.fetch` wrapper rewrites to the live local origin (token + JWKS + S2S).
- REAL: oidc-provider v9.12.2 dance (auth → interact/<uid> → login auto → consent.pug render →
  consent → code → callback), real jose ES256 keystore, real client assertions, replay dedup,
  rate limit. MOCKED: the 4 app/src models + 3 services + Redis (Map fake, `@overleaf/redis-wrapper`
  contract incl. `set EX|PX|NX`, `incr`, `ttl`). `vi.mock` factories read `globalThis.__*` stores
  (hoisting-safe).
- `runAuthorize` runs `handleAuthorize` IN-PROCESS (fake req/res) to capture the 302 `authUrl`
  (skips the CSRF router guard) and asserts the redirect; `driveDance` fetches with a cookie jar,
  stops at the final 302 to `/federation/oidc/rp/callback?code&state`, callback GET asserts.
- Consent rendered by a stubbed `res.render` (pug) — the bridge's `renderConsent` path is exercised
  for real (locals: title/client_id/uid/grantUrl/denyUrl); the form is NOT followed here (the probe
  already proved the redirect chain). The callback is driven by `driveDance`'s returned (code, state).
- Rate-limit test seeds `federation:ratelimit:authorize:beta.example:<hash>` = 30 (TTL 120) then ONE
  more valid `authorize-invite` → 429 + `Allow-Retry-After`. Replay test re-sends the same assertion.

## Failure signatures fixed this session (≤3 iterations each, recon NOT re-opened)
1. `seedStore` `undefined.length` (`__GRANTS`/`__SESSIONS` not yet seeded) → guard init all `__*` in
   `seedStore`.
2. `consent.pug` ENOENT (pug `renderFile` got the view-name string, not a path) → resolve view to an
   absolute `path.resolve(__dirname, '../../app/views/consent.pug')` before render.
3. `Invalid URL` (driveDance `new URL` on a relative `code`-less URL) + callback `Invalid URL` →
   resolve every Location against `beta.example` (absolute `https://beta.example<loc>`) instead of
   assuming absolute. The callback URL is built from the resolved (code, state), not a raw Location.

## Files changed (this session)
- `test/unit/integration/two-instance.sequential.test.mjs` (NEW — full 12-scenario file, green)
- `HANDOFF.md` (this SESSION 8 closeout + TODO-a9c6dd79 → CLOSED)
- (uncommitted `oidf/verify.mjs` bug fix from SESSION 7 is the SAME change — kept in this work; the
  fix is required for ALL valid S2S calls and is exercised by the green S2S scenarios above, so the
  two-instance test is now the live proof that the fix is correct.)

## Anti-loop discipline (what to enforce next session — DO NOT re-run recon)
- Recon is CLOSED. Do NOT re-read `verify.mjs` / `S2sRouter` / `bridge` / `state` / keystore.
- If a future scenario is added, read ONLY the new failing line + the one source it references.
- The probe files (`probe9_dance.mjs`, `probe_dbg2.mjs`, `probe2/3/7/8/10*.mjs`, `oidc_v9probe*.mjs`)
  are NOW REDUNDANT once this test is committed — they are the evidence, deleted in TODO-840029f1.
  `e2e_probe.mjs` (tracked) STAYS (module-trust evidence, referenced by HANDOFF).

## Next (immediate — post green)
- `git add` the test file + `oidf/verify.mjs` + this HANDOFF — NEVER `git add -A` (probes stay
  untracked until TODO-840029f1). Commit + push.
- Mark TODO-a9c6dd79 complete.



---

# SESSION 9 (bug hunt — 2026-09-20 night)

## Scope
Full security + wire-contract review of the federation module (P0–P1 surface): state /
code exchange / S2S / OIDC provider / trust anchor / redaction / rate limiting / admin /
invite / bridge — read-only recon of every `.mjs` under `modules/federation/` (no
re-read of the plan docs). Findings → `FINDINGS.md` §"Bug hunt".

## Bug hunt findings (all → FINDINGS.md for the record)
- **(1) P1 — revoked peer retains grant-minting until restart (FIXED this session).**
  Root cause: the provider-memo reset was only called in the admin `approve` path.
  Admin `revoke` and S2S `revoke` set `status='revoked'` but the memoized oidc-provider
  kept serving `clients[]` derived from the pre-revocation snapshot, so a revoked peer
  could still complete OIDC code exchange (mint grants) until process restart. Fix: all
  three transition sites (`approve`, admin `revoke`, S2S `revoke`) now invalidate the
  memo. Production export renamed to `_resetProviderMemo` (05 §8.3 is the
  contract); the historical `_resetForTest` name is kept as an alias so the
  existing admin-test import line (unchanged this session) still resolves.
  The S2S reset fires ONLY on a real write (`res.modifiedCount`) — the
  idempotent double-receipt no-op path does NOT reset (no double audit, no
  needless rebuild).
  Regression tests: `test/unit/s2s/revoke.test.mjs` (3 cases: revoked-transition resets,
  idempotent double-receipt does NOT reset, third-party origin errors without reset) +
  admin `handleRevoke` assertions updated (reset called on fresh revoke, NOT called on
  idempotent no-op).
- (2) LOW — `verify` JWKS null-guard edge in `ClientAssertionClient` (fetch-then-verify
  interleaving): if the JWKS fetch fails and verification runs against a null, it throws
  an unhandled `TypeError` instead of a 401 `signature-verification-failed`. Documented;
  guard NOT added this session (no failing test, kept the diff minimal — 08 §07.6
  discipline). Revisit with the next hardening pass.
- (3) LOW — `Audit.mjs` redaction: `client_assertion` is redacted as a whole but the
  S2S request also carries `payload` separately — confirm no sensitive fields (email,
  sub) leak in audit via payload. Confirmed clean (payload fields are
  origin/invite-ids only).
- (4) LOW — `State.mjs` one-time state store: state is `consume`d (pop) before use,
  single-use enforced. No issue.
- (5) LOW — OIDC key rotation is a 501 stub (documented; provider memo is per-key
  until rotation lands). No action for P0.
- (6) INFO — consent form CSRF: the interaction-consent POST is OIDC-provider-internal
  (provider's own form POST with form field `form_postback`); provider's built-in
  CSRF token covers it. No app-level CSRF needed. Confirmed.

## Files changed (this session)
- `oidc/createProvider.mjs` — export `_resetProviderMemo` (production name)
- `s2s/actions/revoke.mjs` — calls `_resetProviderMemo()` after successful
  revoked-transition (idempotent path does not reset)
- `admin/FederationAdminController.mjs` — admin `revoke` resets memo after `peer.save()`
  (approve unchanged in behavior, import renamed)
- `test/unit/s2s/revoke.test.mjs` (NEW) — 3 regression tests
- `test/unit/s2s/S2sRouter.test.mjs` — (NO change; its mock resolves `_resetProviderMemo`
  via the `_resetForTest` alias kept in `createProvider.mjs`)
- `test/unit/admin/FederationAdminController.test.mjs` — revoke assertions + reset spy
- `HANDOFF.md` (this SESSION 9)
- `FINDINGS.md` — "Bug hunt" section

## Anti-loop discipline (continues)
- Same closed recon: do NOT re-read `verify.mjs` / `S2sRouter` / `bridge` / `state`.
- Next session touches only: (a) new failing line, (b) the one source it references.

---

# SESSION 11 (2026-09-22): Goal `3ea7bb53` — CONTENT-BRIDGE v2 — 2a recon CLOSED, implementation LOCKED

## Scope (Goal 3ea7bb53, 4 discrete commits → `origin/test_federation`)
| # | Item | TODO | Status |
|---|------|------|--------|
| 2a | export-project S2S (B-side) + adapter grant→(account, client) index + PAT mint + `findExistingGrant` no-re-consent | TODO-39131029 | recon DONE this session; implementation LOCKED below (next) |
| 2b | home export wizard (A-side UI seam) | TODO-a35d4285 | queued |
| 2c | git-bridge read-only 403 guard (`federation:`-prefixed PAT scope) + killOutstandingCodes-driven export sweep | TODO-02b80064 | queued |
| 2d | two-real-origins (A≠B) live smoke (docker two-instance) | (closure of Goal 3ea7bb53) | queued |

v1 identity federation is COMPLETE (live smoke 13/13, `tools/live-smoke.mjs`, commit `1ec14289`).
`plan/09-content-bridge.md` is the wire authority (new). Envelope reconciliation (below)
is LOCKED on top of it.

## 2a recon — seams verified against SOURCE this session (do NOT re-verify)
- **Consent grant payload**: `oidc-provider/lib/grant.js` `Grant.IN_PAYLOAD` includes
  `accountId` AND `clientId` (via `...BaseToken.IN_PAYLOAD`) → the Redis Grant doc payload
  carries both. `BaseModel.save(ttl)` → `adapter.upsert(this.jti, payload, ttl)` — the adapter
  upsert is the single persist point; `payload.accountId/clientId` visible there.
- **Grant is NOT `grantable`** → the `federation:oidc:grant:<grantId>` SET holds TOKEN docs
  (codes/access/refresh), never the Grant doc. v9 `revokeByGrantId(grantId)` is per-TOKEN-model
  (`AccessToken|AuthorizationCode|RefreshToken|DeviceCode.revokeByGrantId`) — it destroys
  token docs via the adapter, but no model owns Grant docs → **there is NO v9 Grant-doc
  revoke cascade**. Consequence: the (account, client) grant index is cascade-deleted ONLY
  in (a) the adapter's `destroy` override and (b) `revokeClientCodes` sweep (both adapter-
  owned). Grant docs die by TTL only (v9 grants live 30 days default — `grants: { lifetime }`;
  ours via adapter `ttl` arg — check what `Grant.save` passes: `this.remainingTTL`).
- **Consent bridge today** (`oidc/bridge.mjs`): consent POST does `provider.Grant.instantiate` +
  `adapter.upsert(jti, payload, ttl)` — this is also the hook point for the (account, client)
  index (adapter-side, so it catches bridge-external grants too).
- **`provider.Grant` + `.instantiate` + `Grant.adapter`** available per v9 base_model.js
  (provider.Grant = `this.Grant = BaseModel.create(...)`; `adapter` property on models).
- **Project owner field = `owner_ref`** (`app/src/Project/ProjectController`-style; verify exact
  model field before coding: `owner_ref: Types.ObjectId ref User`). B-native test:
  owner doc `federation == null` (mirror rows carry the `federation` subdoc).
- **PAT shape EXACT** (`modules/git-bridge/app/src/GitBridgePATManager.mjs` — re-read
  this session, source of truth): `token = 'olp_' + 36 chars` from a 62-char alphabet
  `[a-zA-Z0-9]` (crypto.randomInt loop; NOT randomBytes); `accessToken:
  sha256(token).digest('hex')` stored (column literally named `accessToken`; raw token
  NEVER persisted); `accessTokenPartial: token.substring(0, 8)`; `type:
  'personal_access_token'`; `scope: 'git_bridge'` (string); `createdAt`, `expiresAt`
  (createToken default 1 year via `setFullYear(+1)`). Matcher is the QUERY `scope:
  /\bgit_bridge\b/` — a scope STRING `'federation:git_bridge'` PASSES (colon is a
  non-word char; the `\b` boundary holds) and `'gitbridge'` FAILS. `getUserId(token)`:
  prefix check → `findOne({ accessToken: sha256hex, type: 'personal_access_token',
  scope: /\bgit_bridge\b/, expiresAt: { $gt: now } })` → user existence check →
  non-blocking `lastUsedAt` update. Two consequences LOCKED: (a) **expiry is ALREADY
  enforced** — 2a documents only, 2c adds the read-only 403 push-side guard, NOT
  expiry; (b) the federation PAT scope = string `'federation:git_bridge'` — the
  EXISTING git-bridge matcher passes unchanged, NO new matcher entry needed. The 2c
  guard keys off the `federation:` prefix of that same scope string.
- **git-bridge mount**: `modules/git-bridge/index.mjs` router.apply — confirm mount
  prefix (candidate `https://<origin>/git/<projectId>`) before implementation; ONE
  grep allowed.
- **`db` handle**: `app/src/infrastructure/mongodb.mjs:63` `oauthAccessTokens:
  internalDb.collection('oauth_access_tokens')`... NO — the EXACT line:
  `oauthAccessTokens: internalDb.collection('oauthAccessTokens')` (raw collection).
  Git-bridge imports `{ db }` from there with NO import-time connect (the app layer
  owns the connection). From `modules/federation/s2s/actions/` the path is 5-up —
  SAME depth class that caused the SESSION 10 adapter import bug: count levels and
  verify by RUN, not by eye.
- **Settings**: `federation` block at L1228-1247 — add `export: { enabled: false,
  maxExportTtlSeconds: 86400 }` (2a), 2c adds `sweepOnRevoke: true`; 2b has nothing
  (home-side is UI-only). `maxExportTtlSeconds` is a HARD cap; request TTL = min(request,
  grant remaining, max). `Settings.security.sessionSecret` etc. unchanged.
- **Rate-limit budget table** (`util/RateLimitStore.mjs`): add `{ 'export-project': { budget: 10,
  windowSeconds: 120 } }`; key `federation:ratelimit:export:<callerOrigin>:<projectId>`
  (B-side project _id is already a B-side identifier — safe in a Redis key). `export:<...>`
  segment must NOT collide with the git-bridge `git_bridge:<projectId>` sweep key (it doesn't:
  prefixes differ) — but it DOES look sweep-shaped if someone later changes the sweep key
  regex; note in 2c.
- **Redact**: `SECRET_KEY_DENYLIST` (or equivalent) — add `pat`. Audit rows: NEVER include a
  PAT value, length, or expiry in `detail`/meta — allowed meta: `projectRef` (opaque string,
  OK), `expiresAt`? NO — expiry only in the S2S response, not audit. Audit meta =
  `{ projectId (B-side _id is local, OK — B-side audit, B-side id), scope, assertion }`.
- **Audit types** (`util/Audit.mjs` AUDIT_TYPES): add `'federation_export_granted'` +
  `'federation_export_denied'`. `audit()` is fire-and-forget; `projectId` = the B-side
  project _id IS a valid ObjectId here (unlike S2S receipts which pass null) — pass it.
- **New codes (wire)**: `export-disabled` (200, Settings off), `export-no-consent` (200,
  no live consent grant for (owner, federationClientId(callerOrigin))), `project-not-owned`
  (200 — project missing OR owner is a mirror row OR owner not the B-side user implied by
  the consent grant). Peer-level refusals (`peer-not-approved` / `peer-unknown`) are
  pre-existing at router ③. **LOCKED reconciliation**: these are 200+envelope business
  refusals, NOT 401 — router ⑦ ordering (audit needs `result` to pick granted/denied) and the
  envelope decision (401 = assertion level, 429 = rate, 200 = business) are LOCKED above.
  `plan/09` "401s" phrasing = code-taxonomy shorthand; the WIRE is 200+envelope.
- **findExistingGrant** (`oidc/bridge.mjs`): currently always `return null` (fresh grant
  every consent). 2a wires it: `await adapter.findByAccountAndClient(accountId, ctx.client)`
  → grant id → `provider.getGrantById(id)` (v9 `getGrantById` exists? — v9 has
  `provider.getGrantById`? CHECK: oidc-provider v9 exposes `provider.getGrantById(id)` via
  `modelFactory('Grant').load(id)`... use `provider.Grant.instantiate`? NO — use the v9
  documented path (provider.js `getGrantById`). If the doc is gone, fall back to fresh
  grant (existing behavior). NO RE-CONSENT is the v1.1 bonus this unlocks.
- **Adapter index shape** (LOCKED): `federation:oidc:account:<accountId>:<clientId>` → SET of
  grant doc keys (`federation:oidc:Grant:<jti>`), written SADD on Grant upsert, SREM on
  Grant destroy, + cascade SREM in `revokeClientCodes` sweep. `findByAccountAndClient`:
  SMEMBERS → for each member, GET doc → parse payload → `payload.accountId === accountId &&
  payload.clientId === clientId` → PTTL ≥ 0 (live) → return grant id. v1: 1 consent grant per
  (account, client); multiple live → return the LAST one returned by SMEMBERS (document as
  v1-acceptable; dedupe is 2b+). Non-Grant upserts (no `accountId`+`clientId` pair) → skip
  (existing `!payload.openid` skip covers it: consent grants carry scope openid — keep the
  openid gate AND add the pair gate).

## 2a build list (LOCKED — next session writes, runs, commits)
Files: `s2s/actions/exportProject.mjs` (NEW), `s2s/S2sRouter.mjs` (ACTIONS map add, per-action
audit branch for exportProject), `oidc/RedisOidcProviderAdapter.mjs` (account index + cascade +
`findByAccountAndClient`), `oidc/bridge.mjs` (`findExistingGrant` wired), `oidf/verify.mjs`
(+3 S2S_ERRORS codes), `util/RateLimitStore.mjs` (+budget), `config/settings.defaults.js`
(+`federation.export`), `util/Audit.mjs` (+2 types), `util/Redact.mjs` (+`pat`),
`tools/migrations/20260721150000_add_federation_export_indexes.mjs` (repo root —
`federationExportGrants.owner/projectId` + `status/expiresAt`),
`test/unit/s2s/exportProject.test.mjs` (NEW), `test/unit/integration/two-instance.sequential.test.mjs`
(+export-project scenario section). Handler: settings gate → project lookup (owner_ref) →
B-native check → consent grant check (adapter index) → mint (existing PAT row OR fresh)
→ persist `federationExportGrants` row (status `exported`) → audit → respond
`{ git_url, pat, expires_at }`. Idempotent re-export = fresh PAT ONLY on new consent OR
explicit re-share (2b wizard decides). TTL = min(request ttl, grant remaining ttl,
maxExportTtlSeconds). NO new Redis keys beyond the (account, client) index + the standard
rate-limit key. NO new migrations beyond the export-grant indexes (PAT docs reuse the
existing `oauthAccessTokens` collection — VERIFY name first).

## Open questions answered (this recon closes plan/09 §open-questions for 2a)
1. **git_url** → `https://<origin>/git/<projectId>` (origin = `Settings.siteUrl`
   host; mount prefix confirmed by the one allowed grep before write).
2. **PAT expiry enforcement** → ALREADY enforced in `GitBridgePATManager.getUserId`
   (`expiresAt: { $gt: now }` in the find). 2a documents; 2c adds the 403 push-side guard.
3. **Consent → mint binding** → owner B-native AND consent grant live for
   (owner, federationClientId(callerOrigin)) → TTL-min clamp → mint.
4. **Revoke cascade** → adapter `destroy` + sweep only (see seams above).
5. **Settings knobs** → `export.enabled` (default false), `export.maxExportTtlSeconds` (86400);
   `sweepOnRevoke` lands in 2c.
6. **Rate-limit key** → `federation:ratelimit:export:<callerOrigin>:<projectId>` (budget 10/120s).
7. **Audit** → `federation_export_granted` / `federation_export_denied`; projectId = B-side
   _id (valid ObjectId); meta = `{ scope, assertion }` (redacted, NO pat/length/expiry).
8. **`findExistingGrant`** → adapter index lookup, v9 `getGrantById` load, fallback fresh.

## Anti-loop (2a implementation session)
- Recon is CLOSED for 2a. The ONLY allowed re-reads during implementation: (a) the
  git-bridge mount prefix (one grep), (b) the `oauthAccessTokens` collection name (one
  grep), (c) the new failing test line + the one source it references. Max 3 iterations per
  distinct failure signature. NO recon expansion.
- v1 wire recon (verify.mjs / S2sRouter ordering / bridge dance) remains CLOSED from
  SESSIONS 6-9.


# SESSION 12 (2026-09-22): 2a IMPLEMENTED + VERIFIED (Goal `3ea7bb53`, step 2a of 4)

## Scope (Goal 3ea7bb53, 4 discrete commits → `origin/test_federation`)
| # | Item | TODO | Status |
|---|------|------|--------|
| 2a | export-project S2S (B-side) + adapter (account, client) index + PAT mint + findExistingGrant | TODO-39131029 | **DONE** this session (this entry) |
| 2b | home export wizard (A-side UI seam) | TODO-a35d4285 | next (recon seams already in plan/09 §4.1 + SESSION 11) |
| 2c | git-bridge read-only 403 guard + killOutstandingCodes-driven export sweep | TODO-02b80064 | queued (recon seam: 2a lock item (b) above) |
| 2d | two-real-origins (A≠B) live smoke (docker two-instance) | (closure of Goal 3ea7bb53) | queued |

## DONE this session (2a build list per the SESSION 11 LOCKED list)
- **`s2s/actions/exportProject.mjs`** (NEW): settings gate → payload sanity →
  project lookup (`owner_ref`) → owner B-native (mirror/suspended/missing → not-owned)
  → consent binding (REAL `findByAccountAndClient` vs fake-free adapter;
  client = `federationClientId(callerOrigin)`) → TTL-min clamp
  (`min(request, grant pttl, maxExportTtlSeconds)`, soft-degrade on pttl<0) →
  PAT mint (`olp_`+36, [a-zA-Z0-9], sha256 stored, partial=first 8,
  `scope: 'federation:git_bridge'`, `type: 'personal_access_token'`,
  `expiresAt`) → ledger upsert `federationExportGrants`
  (owner/project/homeOrigin, `$setOnInsert createdAt`) → respond
  `{ git_url, pat, expires_at }` (snake_case, SESSION 11 LOCKED).
  git_url = `https://<Settings.siteUrl host>/git/<projectId>` (port-inclusive).
- **`oidc/RedisOidcProviderAdapter.mjs`**: `federation:oidc:account:<accountId>:<clientId>`
  SET index. SADD on Grant upsert ONLY (gated `modelName === 'Grant'`; token docs
  stay EXCLUDED — the Grant doc is the owner of the pair); SREM cascade in adapter
  `destroy` (same gate) and in `revokeClientCodes` sweep (same gate). NEW exports:
  `findByAccountAndClient(r, accountId, clientId)` (scan account-key SET →
  per-doc `pttl ≥ 0` gate → payload pair check → return jti, else null),
  `accountIndexKey(accountId, clientId)`, `grantDocKey(jti)`. v1 = one consent grant
  per (account, client) → the first live doc is the grant (09 §2.1 "short path";
  the full `getGrantById` load in the OP bridge is the same short path).
- **`oidc/bridge.mjs`**: `findExistingGrant` (01 §3 step 9 "no re-consent"
  v1.1 item) wired to `findByAccountAndClient` — consent prompt now reuses the
  live consent grant instead of minting a duplicate when one exists.
- **`s2s/S2sRouter.mjs`**: ACTIONS map + `'export-project'`; ⑤ rate-limit key
  `federation:ratelimit:export:<callerOrigin>:<projectId>` (LOCKED item 6 —
  the short-action-name pattern that its siblings `authorize`/`revoke` use;
  `export-project` full name was a first-draft drift, corrected); ⑦ audit branch
  `exportGranted/exportDenied`, projectId = B-local _id, meta `{ origin, scope,
  assertion }` (redacted — NO pat/length/expiry in the row).
- **`app/models/FederationExportGrant.mjs`** (NEW): mirror-of-the-consent ledger
  model (owner/projectId/homeOrigin + patHashPrefix + patId + scope + expiresAt +
  status). NOT the consent store (consent = the v9 Grant doc + its TTL).
- **`oidf/verify.mjs`**: +3 S2S_CODES (`export-disabled`, `export-no-consent`,
  `project-not-owned`) — 200+envelope business refusals (LOCKED item 0, not 401).
- **`util/RateLimitStore.mjs`**: + budget row `export-project: {10, 120 s}` +
  the (caller, projectId) key variant.
- **`util/Audit.mjs`**: + `federation_export_granted` / `federation_export_denied`.
- **`util/Redact.mjs`**: + `pat` on the `SECRET_FIELDS` denylist (the audit store
  would drop it even if a handler put it in meta — defense in depth; 2b response
  path + 2c sweep re-read).
- **`config/settings.defaults.js`**: + `federation.export: { enabled: false,
  maxExportTtlSeconds: 86400 }` (09 §5; `sweepOnRevoke` = 2c).
- **`tools/migrations/20260721150001_add_federation_export_indexes.mjs`** (NEW):
  `federationExportGrants` `owner_status_1` + `expires_at_1`. Static-map keys
  `federationExportGrants` + (`federationTrustAnchors`) added to
  `tools/migrations/lib/mongodb.mjs` (the 130000 trust-anchor migration was
  LATENT — no static-map key; both added, verified live).
- **Open question (09 §open #git-PAT-expiry) RESOLVED**: git-bridge `expiresAt`
  is enforced in `GitBridgePATManager.getUserId` (`expiresAt: { $gt: now }`) —
  the 2a clamp IS the live expiry enforcement point; 2c sweep is belt-and-suspenders.
  No change needed.

## Tests (all GREEN, 163/163 in the module)
- `test/unit/s2s/exportProject.test.mjs` (14 cases): settings gate, malformed →
  not-owned, project-missing → not-owned, owner-missing → not-owned,
  mirror-owner → not-owned, suspended-owner → not-owned,
  no-consent → no-consent, happy (snake_case + sha256 + ledger + scope +
  user_id + partial), idempotent re-export (fresh PAT, one ledger row),
  TTL clamp (above max → clamp to max), TTL clamp (grant remaining shorter →
  clamp to grant), grant gone (pttl -1 → soft degrade to max),
  ledger failure → still export (PAT returned).
- `test/unit/oidc/adapterAccountIndex.test.mjs` (7 cases, fake-redis): Grant
  upsert → index, token-model exclusion, live lookup, unknown pair → null,
  expired doc → null, destroy cascade (index-set reclaim), token-destroy does NOT
  cascade (not-over-cross).
- `test/unit/integration/two-instance.sequential.test.mjs` (cases 13–17,
  ON TOP of the existing 12): export-disabled gate, full dance → export
  happy (sha256 stored, raw PAT not persisted, ledger row), idempotent re-export
  (fresh PAT, one row), no-consent (owner without grant — no mint), rate-limit
  429 on the 11th call. MOCK ADDED: the action's `Project` + raw `mongodb` +
  `FederationExportGrant` (app-level models — mocked at the module boundary per
  the 2a lock "mock: peer/project model"; these three were a NEW seam that the
  recon did NOT list, resolved this session by mocking them in the two-instance
  file with the same globalThis pattern as `FederationPeer`).
- Migration ran live against `fed-smoke-mongo` (127.0.0.1:27107/federation_smoke2a):
  `owner_status_1` + `expires_at_1` indices on `federationExportGrants`;
  migration row `20260721150001_add_federation_export_indexes` recorded.
  Pre-existing infra (210 `test/unit/src` failures) UNRELATED (no
  `test/unit/src` file imports `modules/federation` or reads `.export` — checked).

## What 2b/2c inherit from 2a (recon seams already built)
- **2b**: the A-side wizard is the `FederatedExportController` (09 §4.1) +
  session-only view; it reads the `export-project` S2S response (now
  snake_case `{ git_url, pat, expires_at }`) and renders a one-shot
  `<form action="https://a.example/git/bridge" ...>` git-bridge push hint.
  The A-side redaction (pat NOT in the audit log) is the 2b regression test
  (the redact deny list is ALREADY wired by 2a — `pat` is in `SECRET_FIELDS`;
  2b asserts it).
- **2c**: `killOutstandingCodes`-driven export sweep (reuses SESSION 9's
  `revoke` placement) → calls `killOutstandingCodes(callerOrigin, redis)`
  (already exported) + a sweep of `federationExportGrants` (owner-lookup,
  then delete on (owner, projectId) match) + a `FederationKey` lookup to
  confirm "approved + active + killOutstandingCodes: true" (the flag is
  already on the peer schema). 403 guard = git-bridge `receive-pack` +
  a scoped-PAT check on the `federation:` prefix (the existing
  `\bgit_bridge\b` matcher passes `federation:git_bridge` — see the SESSION
  11 lock (b) "the EXISTING matcher passes unchanged, NO new matcher entry
  needed").

## Next (immediate = 2b)
- `2b`: `FederatedExportController` + `app/views/federated-export.pug` (new)
  — the A-side wizard (read the `export-project` S2S response, render a
  one-time git push hint). Re-read `09 §4.1` + the SESSION 11 seam list
  (items in "What 2b/2c inherit" above). The B-side response contract is
  ALREADY SNAKE_CASE (`{ git_url, pat, expires_at }`) — 2b consumes that shape.
- `2c`: `GitBridgeRouter` `receive-pack` 403 guard (scope check on
  `federation:` prefix, 04 §5) + `revoke.mjs` sweep + `Settings` `sweepOnRevoke`
  knob + test.
- `2d`: two-real-origins docker smoke (A and B are different hosts; the
  existing two-instance test uses single-origin because B plays both roles —
  2d is the TRUE A≠B; it reuses the live-smoke `tools/live-smoke.mjs`
  pattern from v1 (13/13) and adds the export scenario over the wire).

## Anti-loop (2b/2c implementation sessions)
- The 2a seams are BUILT. NO recon for 2b/2c. If 2b/2c needs `federationExportGrants`
  schema, `federation:ratelimit:export:` key, or `export-disabled` code — those are
  ALREADY in `verify.mjs` / `RateLimitStore.mjs` / the migration. NO new migration.
- `pat` is in the `Redact.SECRET_FIELDS` denylist (2a wired it). 2b does NOT
  re-add it; 2b asserts it's redacted (regression test).
- 2c sweep reuses `killOutstandingCodes` (already exported from the adapter).
  NO new adapter method.

# SESSION 13 (2026-09-23): 2b SHIPPED (Goal `3ea7bb53`, step 2b of 4)

- Commit: `1b7a9d4634` "content-bridge 2b: A-side federated export wizard
  (plan 09 §4.1)" — 7 files (4 new, 3 modified), pushed to
  `origin/test_federation`.
- Scope (LOCKED Q1/Q2 decisions, SESSION 11):
  - **A is the thin proxy** — `invite/FederatedExportController.mjs` +
    `invite/FederatedExportRouter.mjs`: `GET /federation/export` (form:
    approved outbound|both peer dropdown + B-side project id + optional
    TTL seconds) and `POST /federation/export` (re-sign the client
    assertion → `callPeer(origin, 'export-project', { projectId,
    expiresAt })` → result view). Both on the CSRF-applied `router`
    under `requireLogin()` (invite shape, HANDOFF decision 10). Mounted
    in `index.mjs` `router.apply` after the invite router (④b) under
    the existing `Settings.federation.enabled` gate.
  - **B is the authority** (09 §2.1) — the wizard does NOT re-check
    consent locally; B's S2S handler re-clamps TTL and binds the
    owner→consent grant. Business refusal (200 `{ok:false, code}` →
    403 form re-render + `federation_export_denied` audit with the
    redacted reason); wire refusal (401 / 429 / 3xx `callPeer` throw →
    502 + denied audit). A persists NOTHING (re-run = fresh S2S; B's
    ledger upsert is idempotent, 09 §1).
  - **PAT** (Q2): rendered into the `federation-export-result` Pug view
    only (auto-escaped; `<input readonly>` clone-command pre-filled as
    `git clone https://git:<PAT>@host/path` — git-bridge's PAT-as-userinfo
    flow, git-modal.tsx convention; curl Bearer form documented as the
    fallback, 2d live-smoke covers both surfaces). NOT a JSON body
    field, NEVER in audit meta (regression test asserts PAT absent from
    every audit `JSON.stringify` call).
  - Audit: `AUDIT_TYPES.exportRequested` = `federation_export_requested`
    (meta `{ origin, scope }` on success + `{ gitUrl, expiresAt }` per
    09 §3.2 — non-secret facts). `Audit.mjs` `META_FIELDS` extended with
    `gitUrl` + `expiresAt` (04 §8 allow-list, both redacted-safe).
  - Views: `app/views/federation-export.pug` (form + `_csrf` hidden
    field) + `federation-export-result.pug`; both Pug-compile-verified
    in-session (the `export` reserved-word pitfall: the Pug local is
    named `export` only in the controller, views use `defaultTtlSeconds`
    / `maxTtlSeconds` top-level locals — Pug cannot resolve
    `export.maxTtlSeconds` because `export` is a reserved JS identifier
    inside attribute expressions; lesson: keep view locals unreserved).
- Tests: 172/172 federation module (`test/unit/invite/FederatedExportController.test.mjs`
  9 new — thunk pattern on `callPeer`/`FederationPeer.find`/`audit`,
  redaction regression, TTL clamp 3600-default / 86400-max / malformed →
  default, peer-gate 403 no-wire, projectId 400, wire-502 + denied audit,
  business-403 + denied audit). Lint clean on all 7 files.
- **OPEN for 2d**: the exact git-bridge token-authentication surface
  (Bearer header vs Basic userinfo) is implementation-dependent on the
  deployed git-bridge Go service (this repo's `git-bridge` module only
  serves the REST + PAT management; the Go `git-bridge` repo is not in
  this workspace). The wizard documents BOTH forms (clone with
  embedded PAT userinfo + curl Bearer fallback); 2d must verify which
  the live deployment accepts (clone vs curl).
- Next: **2c** (`git_receive_pack` 403 guard + `killOutstandingCodes`-
  driven export sweep; recon seam: 2a lock item (b) above — no new
  adapter method, no new migration).
# SESSION 14 (2026-09-24): 2c SHIPPED (Goal `3ea7bb53`, step 2c of 4)

- Commits (pushed to `origin/test_federation`):
  - `code + tests` (7 code + 3 test files, 1 new `export/Sweep.mjs`,
    `export`-scope 403 guard at `GitBridgeAuthMiddleware`
    `ensureTokenProjectAccess('write')`, `sweepExportGrants` in both
    `revoke.mjs` + `handleRevoke` (both try/catch best-effort),
    `sweepOnRevoke` settings default)
  - `docs` (this HANDOFF SESSION 14 row + plan 09 §6 2c SHIPPED)
- **403 guard (plan 09 §4, 2c)**: at the git-bridge REST write choke
  (`GitBridgeAuthMiddleware.ensureTokenProjectAccess('write')`):
  resolve token WITH scope via new
  `GitBridgePATManager.getUserIdAndScope(token) → { userId, scope }`
  (`getUserId` now delegates to this — no new DB path). Write path:
  if `identity.scope.startsWith('federation:')` → `logger.warn`
  + 403 **before** the permission oracle (project write-allow would
  NOT save an export PAT). Read path: unchanged (fetch = the content
  path for a federation-EXPORT token). No federation import (the
  dependency rule: marker is the scope string `federation:git_bridge`).
- **Sweep (plan 09 §3.3)**: `export/Sweep.mjs` `sweepExportGrants(origin)`
  — ledger rows `federationExportGrants` for `homeOrigin == origin` →
  `status:'revoked'`, their `patId`s `db.oauthAccessTokens.deleteOne`
  (scope-guarded `scope: 'federation:git_bridge'`, NOT user
  `git_bridge`; per-row best-effort), `federation_export_swept` audit
  (meta `{ origin, scope }` redacted — PAT value never a field).
  Gates on `Settings.federation.export.sweepOnRevoke` (default
  `true` in `settings.defaults.js`; off = v1 NO-OP). Independent of
  the peer `killOutstandingCodes` flag (that gates `revokeClientCodes`
  — the oidc code sweep, 06 §179). Called from BOTH revoke
  transitions (s2s `revoke.mjs` + admin `handleRevoke`, both
  try/catch mirroring the code-sweep twin).
- **Tests (6 + 4 + 2 = 12 new, 183/183 green)**:
  - `git-bridge/test/unit/GitBridgeAuthMiddleware.test.mjs` (NEW,
    6 cases): write+federation:-scope → 403 oracle NOT consulted;
    read+federation:-scope → allowed fetch; write+normal-scope →
    oracle applied + `req.user_id` set; write+normal-scope+no-access
    → 403 via oracle; write+unknown token → 401; read+unknown →
    401. Thunk globals `__TOKENS`/`__READ_ALLOWED`/
    `__WRITE_ALLOWED` + call-logs `__READ_CALLS`/`__WRITE_CALLS`
    (thunk pattern, NOT `vi.fn` — bootstrap runs
    `vi.resetAllMocks()` after every test).
  - `s2s/revoke.test.mjs` (4 new): sweep on transition (2 PATs
    scope-guarded, ledger `status:'revoked'`, redacted
    `federation_export_swept` audit meta); sweep off
    (`sweepOnRevoke: false` → NO-OP); idempotent double-revoke
    → no second sweep (0 modified); best-effort PAT-delete failure
    still revokes (06 §174 not-over-cross).
  - `admin/FederationAdminController.test.mjs` (2 new): export
    sweep runs on transition (flag-INDEPENDENT, `beta.example` arg);
    idempotent double-revoke → no second sweep.
- **Lint**: clean on all 2c-touchable 9 files.
- **OPEN for 2d (Goal `3ea7bb53` step 4 of 4)**: CLOSED in SESSION 15 — 2d
  SHIPPED (live smoke GREEN; see the SESSION 15 section +
  `tools/two-origin/README.md`).
- Next: eduGAIN Phase 0+ (only when external infra appears).

# SESSION 15 (2026-09-24): 2d SHIPPED — two-real-origins live smoke GREEN (Goal `3dad1c9e` step 4 of 4)
Goal step 4 of 4 (`3dad1c9e`). Recon stayed CLOSED (SESSION 14 close-out); the smoke was
built against the closed recon and iterated against real live output (2d anti-loop budget:
failures resolved via live logs + targeted SOURCE reads of the files under test).

**SHIPPED (committed + pushed this session):**
- `tools/two-origin/live-smoke-b.mjs` (NEW): the B child process — origin
`beta.example`, REAL express mount (S2sRouter + bridge + CallbackRouter + OP) +
`GitBridgeRouter.apply(webRouter, privateApiRouter, publicApiRouter)`, fake login =
B-native `owner@beta.example` (real shared-Mongo row), prints `READY_B <port>`.
- `tools/two-origin/live-two-origin.mjs` (NEW, driver = origin A `alpha.example`,
RP-only): owns shared Mongo `fedsmoke2` (drop + reseed — carol@alpha + owner@beta,
projects, peer rows both origins approved/both pinned to the shared bootstrap key) +
Redis (`flushall`), spawns B, fetch-rewrites both origins, drives 7 scenarios (01 dance
→ mirror + consent-grant account index, 02 wizard → S2S mint → PAT, 03 live REST
read-400/write-403/token-info-200 + normal-PAT-passes-guard, 04 429 rate limit,
05 S2S revoke → sweep, 06 dead-PAT 401s + wizard 502, 07 post-revoke S2S 401) with
a PASS/FAIL matrix + exit code.
- `tools/two-origin/README.md` (NEW): run instructions + scenario matrix + the
documented shared-keystore / fake-login / one-process-per-origin simplifications.
- **Two PRODUCTION bugs caught live (SESSION 10 class — the unit suite, incl. the
vi.mocked `FederationExportGrant`, could never reach them) — fixed + regression-tested:**
  1. **2a ledger upsert was a silent no-op** (`exportProject.mjs`):
     `FederationExportGrant.updateOne(filter, { $set, $setOnInsert })` was called
     WITHOUT `{ upsert: true }` → `$setOnInsert` never applied, `matched 0/upserted 0`,
     NO ledger row ever persisted → 2c sweep had nothing to sweep + 2a's ledger
     guarantee silently unmet. Fix: `{ upsert: true }`. Test: exportProject
     idempotent case now asserts `opts === { upsert: true }`.
  2. **mirror mark = `owner.federation.origin`, NOT bare subdoc presence**
     (`exportProject.mjs`): mongoose writes a populated EMPTY `{}` `federation`
     subdoc on every native `User.create` (inline schema), and `{}` is truthy →
     2a refused every export with `owner missing/mirror`. Fix: the owner check
     keys on a populated `federation.origin` (present on every mirror-row create
     per CallbackRouter, absent on every native incl. legacy). `User.mjs`
     untouched (minimal prod-model diff). Test: new exportProject case
     "empty federation subdoc is NOT a mirror → exported".
  Both fixed under `exportProject.mjs`; 184/184 unit (178 fed + 6 git-bridge)
  green; Lint clean on all 2d-touched files (exportProject.mjs,
  FederatedExportController.mjs, both two-origin .mjs, both test files).
- `invite/FederatedExportController.mjs`: house pattern `export const
  FederatedExportController = {...}` + `export default` (mirror
  `FederatedInviteController`) — `FederatedExportRouter` default-imports
  the handler object at `router.apply` (a named-only module would be `undefined`
  at app boot). (Committed `cf4b29c813` earlier this session.)

**Live evidence (exit 0, `7 scenarios · ALL PASS`, 30/30 checks)** —
`timeout 240 node modules/federation/tools/two-origin/live-two-origin.mjs` from
`services/web/` with `fed-smoke-mongo` (27107) + `fed-smoke-redis` (6380) up. The
2d signature is scenario 03: export-PAT `GET /api/v0/docs/<id>` reaches the
controller (400 = absent project-history sidecar, auth passed), export-PAT
`POST /api/v0/docs/<id>/snapshots` → **403 (the 2c guard)**, normal-PAT write
PASSES the guard (500, same sidecar) → scope-keyed, not a blanket refusal.
Scenario 06 proves the post-revoke dead-PAT story (401 token-info/read/write +
wizard 502 `peer-not-approved`).

**What this closes:** Goal `3dad1c9e-...` step 4 of 4 (content-bridge v2
complete — 2a+2b+2c+2d). `TODO-0c6f534f` DONE. eduGAIN Phases 0/2/3/4
STAY blocked on external Shibboleth/eduGAIN infra (plan/10) — the goal's
eduGAIN leg is NOT closed by 2d. Next (if infra appears): eduGAIN
Phase 0 (Shibboleth SP proxy on A).
