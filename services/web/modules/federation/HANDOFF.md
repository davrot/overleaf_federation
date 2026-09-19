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
| P2 | Admin UI + Settings additions + claim allow-list + rate-limit + audit | rate-limit + audit + admin **DONE**; claim allow-list + live Settings integration open |

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

### TODO ID mapping (for session handoff via .pi/todos)
| TODO | Item | Phase | Status (2026-09-18) |
|------|------|-------|------|
| TODO-1f4e6ae5 | util layer (Anchor, Redact, Audit + RateLimitStore) | P0 | **util trio DONE**; RateLimitStore pending (in ec1f0879) |
| TODO-c7238651 | User.federation + ProjectInvite.federated schema | P0 | **DONE** (incl. migration) |
| TODO-bc8ad398 | leaf.mjs serve + mount helper | P0 | leaf committed; mount wiring = index.mjs (1fed7e98) |
| TODO-ec1f0879 | S2S router + 3 actions + rate limit | P1 | **DONE** (committed 2026-09-18b) |
| TODO-7e3fc1d8 | A-side RPC CodeExchange + CallbackRouter | P1 | **DONE** (committed 2026-09-18b) |
| TODO-c6bbd319 | invite controller/router | P1 | **DONE** (committed 2026-09-18b) |
| TODO-5d6003df | admin router/controller + consent view | P2 | **DONE** (committed 2026-09-18b) |
| TODO-1fed7e98 | index.mjs mount wiring + start | P0 | **DONE** (committed 2026-09-18b) |
| TODO-4c7da2af | Settings + app-level auth guards | integration | open |
| TODO-fd9f09c0 | unit tests + validation gate | testing | **DONE** (60/60 green, ESLint clean) committed 2026-09-18b |

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
