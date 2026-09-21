# Findings — npm v1.0.0 verification (2026-09-17, OIDF 1.0)

All verified against npm v1.0.0 (`@oidfed/core`, `@oidfed/oidc`,
`@oidfed/leaf`), the reproducible artifact (the git checkout at
`~/federation/oidfed` is a superset, v0.4.x-era in its own package.json —
a different API surface).

## What npm 1.0.0 actually exports

**`@oidfed/core`** (162 exports — verified list): the full OIDF trust
machinery. Key surface this plan uses:
- `signEntityConfiguration`, `verifyEntityStatement`, `signEntityStatement`,
  `signSubordinateStatement`, `buildEntityConfigurationPayload`,
  `buildSubordinateStatementPayload`
- `createFederationSigningKey(privateKey)` → JWKS signer
- `generateSigningKey` (**async**, returns
  `{ publicKey, privateKey }` JWK pairs)
- `createTrustAnchorSet([{ entity_id, jwks }])` → `Map`
- `discoverEntity(entityId, trustAnchors, options)` (async)
- `refreshTrustChain` (async — the "re-fetch kid-mismatch" path)
- `ReplayStore` via `MemoryReplayStore` (npm ships a memory impl; we wrap
  Redis with the same interface)
- `JWT_BEARER_CLIENT_ASSERTION_TYPE`, `DEFAULT_*_TTL_SECONDS`, clock-skeg
  defaults, `fetchJwkSet`, `fetchExtendedSubordinatesList`,
  `fetchHistoricalKeys`, `fetchResolveResponse`, `fetchSubordinateStatement`,
  `fetchSignedJwkSet`
- `verifyClientAssertion` (async)

**`@oidfed/oidc`** (7 exports — verified):
- `OidcRelyingPartyRole` — `constructor(config)`, `initialize(context)`,
  instance `createClientAssertion(audience, options?)`,
  `automaticallyRegister(params, options?)`,
  `explicitlyRegister(opEntityId, options?)`,
  `createAuthorizationRequest(requestObject, params, options?)`.
  **Static** `createClientAssertion(clientId, audience, signer, options)`
  is exported as `static createClientAssertion`; both forms work.
- `OidcProviderRole` — `constructor(config)`, `initialize(context)` which
  **mounts the explicit-registration POST route** on
  `opRole.routes.get(registrationPath)`; instance
  `processExplicitRegistration(requestObjectJwt, options?)`,
  `processAutomaticRegistration`. The OP role **injects
  `federation_registration_endpoint` into its own metadata** on initialize
  (so our `OidcProviderRole` metadata must be merged into the leaf EC
  under `metadata.openid_provider`; see below).
- `StaticProtocolSigningKeyProvider` (used for tests/fixtures)
- `OIDCRegistrationAdapter` — `validateClientMetadata`,
  `enrichResponseMetadata`
- `OAuthClientRole`, `OAuthResourceRole`,
  `OAuthAuthorizationServerRole` (OIDF OAuth role classes — same initialize/
  requestObject pattern; not needed for v1 pairwise but exported)

**`@oidfed/leaf`** (1 export — verified): `Leaf` class. **This is the
critical correction to v0/v1 plan claims:**
- `Leaf` constructor requires `authorityHints` to be **non-empty** — throws
  `"authorityHints MUST NOT be empty for leaf entities"` otherwise.
- `Leaf.handleRequest(request)` is a fetch-time handler:
  `buildEntityConfiguration` → `isEntityConfigurationExpired` →
  `refreshEntityConfiguration` (fetches the subordinate statement from
  a trusted higher tier, signs the leaf EC, caches).
- Therefore `@oidfed/leaf`'s `Leaf` class is **institutional-only** (P3).
  For P0–P2 pairwise leaf serving we use `@oidfed/core`'s
  `signEntityConfiguration` directly (already planned, §2).

**`jose` 6.2.10** (repo top-level, single physical copy): `jwtVerify` + `compactVerify` exist.
Use `jwtVerify` in new code. The pre-2021 `4.15.5` pin in `resolutions` was a
runtime lie: `oidc-provider@9.12.2` declares `jose: ^6.2.10` and `@oidfed/core`
declares `jose 6.2.3`, both satisfied by 6.2.10; v9 is written against the v6
API (`new CompactSign(...).sign(key)` accepts a plain private JWK), so the repo
now resolves `jose` to 6.2.10 everywhere (see `FINDINGS.md`, "jose bump").

## The pairwise-works, registration-fail finding

Empirically verified (bridge_test.mjs under /tmp/oidfed-npm-check):
- **Pairwise sign → verify → validateTrustChain works** end-to-end for a
  depth-1 chain where the leaf itself is a trust anchor.
- **`OidcRelyingPartyRole.explicitlyRegister` FAILS for pure pairwise**
  configurations. The npm class resolves *both* the RP's and the OP's
  chains from a single anchor set and requires a shared anchor
  ("No shared Trust Anchor between RP and OP" — matches the OIDF 5.4 "MUST
  share a trust anchor" rule). With mutual pinning (each side pins the
  other), neither side is the other's anchor from *the other side's* point
  of view, so the flow cannot complete.
- Consequence: **pairwise trust establishment is the per-direction admin
  pin, not OIDF explicit registration**. P3 institutional deployments use
  the shared TA and the registration flow works (verified in that same
  empirical run: registration EC min(1) `authority_hints`, OP-side
  response Content-Type `application/explicit-registration-response+jwt`,
  typ `explicit-registration-response+jwt`).

## Wire contract verified on both sides (institutional mode)
- Registration POST: `Content-Type: application/entity-statement+jwt`
  (strict), body is a single EC JWT.
- `ExplicitRegistrationRequestPayloadSchema` requires
  `authority_hints` min(1).
- OP's registration response: Content-Type
  `application/explicit-registration-response+jwt` (**exact match**; the
  `isExactContentType` check in the built output refuses non-exact match).
- Registration response `claims`: `iss = <issuer-of-registration-EC>`,
  `sub = <OP entity id>` (verified from `ExplicitRegistrationResponseSchema`),
  `aud = <RP entity id>` (not present in the v0 draft claim list).
- `metadata.openid_relying_party` is **required** in the registration EC's
  `metadata` object (Zod `required`); `redirect_uris` inside it is also
  required when `client_registration_types_supported` includes
  `"explicit"` (superRefine).
- Registration EC **must** have `authorityHints` (min 1), else wire-schema
  reject.

## `federation_registration_endpoint` is REQUIRED when
`client_registration_types_supported` (in the leaf EC) contains
`"explicit"`. Our pairwise leaf EC does **not** advertise an explicit
registration service, so the field is absent from the leaf EC itself —
but institutional mode (P3, `federationInstitutionalMode: true`) MUST
expose it, and it becomes `metadata.openid_provider.federation_registration_endpoint`
once the OP-side role is initialized. The OP-side role's `initialize`
injects it; we merge `OidcProviderRole.metadata` into the leaf EC we serve.

## `createClientAssertion` static method is verified
- `OidcRelyingPartyRole.createClientAssertion(clientId, audience, signer,
  options)` works without `initialize` (pure signer + audience).
- Instance method `createClientAssertion(audience, options)` resolves the
  signer via `config.protocolKeyProvider.getClientAssertionSigner` (falls
  back to `getRequestObjectSigner`) and pulls `clientId` from
  `context.entityId` (set during `initialize({ entityId, ... })`).
- `OIDCRegistrationAdapter` is exported (for institutional
  client-metadata validation on OP-side receive).

## Leaf metadata issuer (verified npm 1.0.0, 2026-09-18)
- FINDINGS v1 claimed "`openid_provider.issuer` MUST equal the entity id
  (leaf check 16)" — that is a **git-source/v0 draft claim, NOT enforced by
  npm v1.0.0** (`verifyEntityStatement` accepts both `issuer=<entity id>` and
  `issuer=<entity id>/federation/oidc`; both pass end-to-end —
  issuer_check.mjs). OIDF v1.0 treats the metadata `issuer` as the OP
  server's issuer, so we set the OIDC OP issuer
  (`<entity id>/federation/oidc`) — self-consistent with oidc-provider's
  own issuer and the peer-side OP role issuer. Both pass npm
  verify; the OP role (peer-side, P3) is what consumes it.
- Required in `openid_provider`: `issuer` (URL),
  `authorization_endpoint` (URL), `response_types_supported` (array),
  `subject_types_supported` (array),
  `id_token_signing_alg_values_supported` (array).
- `federation_registration_endpoint` (conditional: required if
  `client_registration_types_supported` contains `"explicit"`,
  superRefine in `OpenIDProviderMetadataSchema`).
- **NOT required** for leaf: `token_endpoint`, `userinfo_endpoint`, etc.
  (all optional in `OpenIDProviderMetadataSchema`).

## `validateTrustChain` is ASYNC (verified)
- `await validateTrustChain(chain, options)` →
  `{ valid: true, chain: {...}, errors?: [...] }` |
  `{ valid: false, errors: [...] }`.
- `chain.validatedChain: [...]` on success; `trustAnchorId` is the anchor's
  entity id.
- For pairwise depth-1 chains (leaf is its own anchor, admin-pinned),
  `chain.trustAnchorId === leaf entityId` (verified empirically).

## `OidcProviderRole.initialize` throws on empty anchor set (verified)
- `initialize(context)` →
  `assertNonEmptyTrustAnchors(config.trustAnchors ?? context.trustAnchors)`.
  On empty set: `throw new Error("No trustAnchors configured")`.
  **Pairwise instances (no TA at all) MUST NOT construct/instantiate the
  OP role**; institutional instances construct it with the shared TA.

## `performFetch` httpClient contract (verified from built output)
- Discovery fetch (leaf EC): `fetchFn(url_string, { signal, headers, ... })`.
- Registration POST (`performRegistrationRequest`):
  `httpClient(request_object)` where `request_object` is a **native**
  `Request` (with `URL`, `method`, `headers`, `body`).
- A single `fetch`-based impl handles both: `fetch(url, init)` accepts
  both a string arg and a `Request` arg.

## Concrete plan fixes (applied to plan/*.md this session)
1. **00-overview.md** — "trust layer: OIDF 1.0" wording: pairwise = admin
   pin, institutional = registration (no "explicit registration
   everywhere").
2. **01-identity §4** — "Trust establishment is OIDF explicit client
   registration" → clarified as pairwise-per-direction pin (P0–P2);
   institutional is P3 with registration (02 §4).
3. **02 §4** — rewritten:
   - title: "Trust establishment — admin pin (pairwise) and explicit
     registration (institutional)"
   - the pairwise paragraph now leads
   - explicit registration code shows `OidcRelyingPartyRole` +
     `initialize` and notes "institutional, P3"
   - the "authorityHints absent for pairwise" claim is **removed**
     (registration ECs require min(1); leaf ECs omit hints)
   - the "No shared Trust Anchor between RP and OP" empirical finding is
     recorded here (02 §4 bullet + §8 appendix)
   - consequences list updated (no registration statement in pairwise;
     admin approval screen shows entity_id, thumbprint (TOFU); institutional
     adds registration statement fields)
4. **02 §8** — Grounding appendix rewritten against **npm 1.0.0** (not git
   source): exports per package, `Leaf` institutional-only note,
   `explicitRegistration` free function does NOT exist in npm v1.0.0
   (role-class only), `createTrustAnchorSet` is a Map, `validateTrustChain`
   is async.
5. **03 §2** — `createClientAssertion` import: now
   `OidcRelyingPartyRole.createClientAssertion(clientId, audience, signer)`
   (static) + instance `createClientAssertion(audience)` alternative, and
   `verifyClientAssertion` (name corrected; the v0 "Sync" form is
   not exported as such).
6. **05 §3.2** — jose v4: `jwtVerify` (not `compactVerify`), import path
   `import { jwtVerify } from 'jose'`.
7. **04 §2** — `FederationPeer` schema: `registration` subdoc is
   **institutional-only** (P3) and the v1 `raw` (registration JWS) field
   dropped for pairwise (no registration statement exists in pairwise
   mode); `clientMetadata` field replaced by `registration.child*.
   Jwks/Kid`; `mode: 'pairwise' | 'institutional'` added.
8. **04 §2.1** — pending approval flow reframed: pairwise is
   admin-triggered (fetch leaf + click-confirm); institutional is
   `onRegistration`-hook-driven.
9. **04 §6** — removed the `federation:leafe` typo key name (now
   `federation:leaf:`); clarified `federation:replay:<jti>` keys by jti
   alone (no `aud` claim in a leaf EC).
10. **04 §7** — `clients[]` reconstruction: for pairwise, `client_id` is the
    deterministic URN (no registration subdoc); for institutional,
    `registration.clientId`.
11. **04 §8** — audit types: `federation_peer_trust_revoked` (was
    "federated_invite_denied... re-federate" — clarified),
    `federation_peer_registered` (pairwise = pin, institutional =
    registration).
12. **05 §4 (feature list)** — admin "Federation" tab lists pin vs
    registration by mode.
13. **05 Settings** — `Settings.federationPeers[]` (pairwise, optional)
    vs `Settings.federationInstitutionalAnchorPath` (P3) are additive,
    not mutually exclusive.
14. **06 §1 (table)** — trust establishment row: "pin (pairwise) /
    registration (institutional, P3); `onRegistration` hook writes the
    pending row".
15. **07 (roadmap)** — P1 deliverables updated: `oidf/anchors.mjs`,
    `oidf/registration.mjs` (institutional-only, stubbed until P3),
    `ClientAssertionClient` uses static `OidcRelyingPartyRole.
    createClientAssertion` + `verifyClientAssertion`; the two-container
    "pairwise explicit registration" test is renamed to "peer
    pinning + leaf fetch + verify" (no registration in pairwise).

## Dependencies to add to `services/web/package.json` (P0)
- `@oidfed/core@1.0.0`     (trust chain, key, replay, client assertion)
- `@oidfed/oidc@1.0.0`     (roles, static `createClientAssertion`)
- `@oidfed/leaf@1.0.0`     (the `Leaf` class, institutional-mode only)
- (P3 adds `@oidfed/authority` **not** a published v1.0.0 package — the
   authority code is not in npm v1.0.0 per the exports list; it is in git
   source. If institutional P3 is pursued, the npm v1.0.0 `@oidfed/oidc`
   `OidcProviderRole` is enough OP-side; the TA-side is out of
   overleaf-cep scope.)

## Module file map to create (P0)
- `index.mjs` — default WebModule export
- `modules/index.d.ts` — JSDoc types for `{ router, apply, start, stop }`
- `app/src/index.mjs` — module registration / router mount
- `app/src/Settings.mjs` — Settings extension
- `oidf/leaf.mjs` — our GET leaf serve (signEntityConfiguration)
- `oidf/anchors.mjs` — `createTrustAnchorSet` from Mongoose +
  institutional file
- `oidf/verify.mjs` — `OidcRelyingPartyRole` for peer discovery + client
  assertion verification
- `oidf/reverify.mjs` — revalidate peer leaf on kid-mismatch
- `oidf/registration.mjs` — institutional-only (P3 stub for P0–P2)
- `oidc/adapter/mongoose-adapter.mjs` — 7-method contract
- `oidc/adapter/keystore/redis-key-provider.mjs`
- `oidc/adapter/redis-adapter.mjs`
- `oidc/adapter/create-provider.mjs`
- `oidc/adapter/bootstrap.mjs` — key material bootstrap (federation +
  OIDC keys)
- `oidc/router.mjs` — `/auth`, `/token`, etc.
- `oidc/interaction-bridge.mjs`
- `S2sRouter.mjs` — `/federation/s2s` (+ rate limit)
- `AdminRouter.mjs` — `/api/federation/*` + `.well-known` GET (admin)
- `test/...` — unit (sign/verify, anchors, leaf fetch, verify, S2s
  rate-limit)

### Remaining recon (not done)
- `rate-limiter-flexible` usage pattern for the `/federation/s2s`
  rate-limit (existing `Services/web/infrastructure/RateLimiter.mjs` wraps
  it — reuse, don't re-implement).
- How `Modules` discovers a module (Settings.moduleImportSequence +
  `Modules.mjs` `MODULE_BASE_PATH`) — **confirmed** the pattern
  (`history-v1`, `launchpad`, `server-ce-scripts`, `sandboxed-compiles`,
  `symbol-palette`, `reference-picker`, `track-changes`,
  `authentication/*`, `admin-tools`, ..., `git-bridge`, etc. — see
  `config/settings.defaults.js:1207 moduleImportSequence`). The
  federation module goes in `modules/moduleImportSequence` as its own
  entry, with its own `index.mjs`/`index.mts`.
- ~~`Settings.origin` (not `Settings.siteUrl`)…~~ — **RETRACTED**: `settings.defaults.js`
  defines `siteUrl` and has no `origin` field; entity id derives from
  `new URL(Settings.siteUrl).hostname` (code as committed).

---

## Bug hunt (2026-09-20 night, SESSION 9)

Security + wire-contract review of the whole P0–P1 surface. One P1 fixed (revoke
provider-memo invalidation, see HANDOFF SESSION 9 + `test/unit/s2s/revoke.test.mjs`).
Residuals (documented, no code change this session):

- (LOW) `ClientAssertionClient` JWKS null-guard: fetch-fails-then-verify interleaving
  throws `TypeError` instead of a 401 `signature-verification-failed`.
- (LOW) `resolveJwk` (rp/CodeExchange): a failing initial JWKS fetch + successful
  token response leaves `jwks=null`; exchange errors out today, but a null-guard
  would be cleaner.
- (LOW) `handlePin` fetch: undici default is `redirect: 'follow'`; a malicious
  redirect could serve a different EC. Mitigated by `iss`/`sub` validation of the
  returned EC before pin. Recommend `redirect: 'manual'` next hardening pass.
- (INFO) OIDC key rotation is a documented 501 stub (provider memo frozen;
  rotation requires restart).
- (INFO) Consent-form POST relies on oidc-provider's built-in interaction CSRF
  token + `op_interaction` cookie; no app-level token needed (standard OIDC).
- (INFO) `findExistingGrant` always returns null (v1): consent always re-prompted;
  documented v1 limitation.
- (INFO) Keystore `expiresAt` on active keys is the publish-time 48h stamp and is
  never refreshed — cosmetic, no security impact.
- (INFO) `State.mjs` session slot ("session first, Redis backup" docstring) is
  written but only Redis is read — nonce + single-use code + 120s TTL still bound.

---

## Shared-client-row analysis (B4 — worth writing down, zero code)

Question: is the "shared provider-memo across all approved peers" a grant-
forging hole? **No — bounded, by oidc-provider v9's own mint gating.** The
shared memo holds ONE provider instance whose `clients[]` is the live
reconstruction from `approved` peers (04 §7). Each mint is bound to:

1. **A live `clients[]` row** for the minting origin. oidc-provider v9
   mint-gates on `client_id` membership in `clients[]` — a revoked peer's
   row is removed by the SESSION 9 P1 fix (memo invalidation on
   transition), so its next mint (and every mint after) is
   `invalid_client` from the token endpoint, regardless of cookie or
   session state.
2. **PKCE public client, no secret** (`token_endpoint_auth_method: 'none'`)
   on every row — a forged `client_id` for a revoked origin is still not
   in `clients[]`, so membership is the whole gate (there is no secret to
   steal). A validly-PKCE'd request for a *non-removed* origin cannot be
   attributed to a revoked origin because the client_id string encodes
   the origin (`urn:overleaf-federation:client:<origin>`).

The OIDF **client assertion** (S2S wire, `iss`/`aud`/signature checked
against the pinned anchor JWK, `verify.mjs` 02 §3) and the **OIDC
mint** (PKCE `clients[]` membership) are two separate enforcement layers:
control-plane S2S vs token-plane mint. Defense in depth — a revoked
origin fails the S2S `peer-not-approved` (pre-lookup, S2sRouter ③)
AND the OIDC `invalid_client` (memo reset) independently.

Residual (not a hole, recorded): pre-revoke **codes already minted**
redeem until their 120 s TTL (the `killOutstandingCodes` NO-OP, 04 §5).
That is the *only* true post-revoke residual and it is a bounded 120 s
window (AuthorizationCode TTL, single-use per 05 §8.2), never a grant
secret. This is what `TODO-e652c0d9`'s sweep would close.
