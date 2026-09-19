# oidf/ — OIDF building blocks

OIDF 1.0 (OpenID Fed, Final 2026-02-17) primitives, built on the `@oidfed/core`
v1.0.0 npm package (ESM, `Result`-typed errors).

> **Rule:** these files are the cryptographic spine. Do **NOT rewrite** unless a
> reproducible defect forces it.

| File | Responsibility / exports |
|---|---|
| `leaf.mjs` | This instance's **leaf** entity configuration. `getEntityId()`, `getOrigin()`, `oidcEndpoints()` (issuer/auth/token/jwks/callback/session-end — used by `oidc/` and `S2sRouter`), `buildLeafMetadata()`, `buildLeafEntityConfiguration()` (signs a 48h leaf EC; adds `authority_hints` when `federation.institutionAuthorityHints` is non-empty), `leafHandler` (serves the signed EC at the well-known path). |
| `keystore.mjs` | OIDF **signer/key management**: `ensureBootstrapped()`, `createKeyProvider()`, `historicalKeySetPayload()`, `retireExpiredKeys()`, `leafJwksPayload()`, `oidcSigningKeys()`, `listPublicKeys()`. Rotation grace is `federation.keyRotationGraceDays`. The npm signer is used; we never hand-construct tokens. Backed by `app/models/FederationKey.mjs`. |
| `verify.mjs` | **Inbound S2S client-assertion verification**: `verifyS2sClientAssertion(assertion, from)`, `lookupApprovedPeer(origin)`, `claimJti(jti, expiresAt)` (replay store, Redis `federation:replay:` key), and the `S2S_ERRORS` machine-code map (03 §6). |
| `anchors.mjs` | Trust-anchor helpers: `createTrustAnchorSetFromPeers()`, `institutionalAnchorsFromDb()` (loads `FederationTrustAnchor` rows), `createTrustAnchorSetForInstance()`. |
| `ClientAssertionClient.mjs` | **Outbound** S2S assertion builder: `getClientId()`, `getS2sEndpoint()`, `buildS2sRequest(peerOrigin, action, payload)` → `{ headers: { client_assertion }, body }` per plan 03 (fetch peer JWKS, sign `aud=peerOrigin`, 10s timeout). |

### Notes
- `leaf.mjs` **signs only** (no fetch). `verify.mjs` **fetches** the peer JWKS
  (5s timeout) — this is the one network path in `oidf/`.
- Key material emitted by `keystore.mjs` is **public halves only**.
- JWKS cache is Redis `federation:jwks:*` (1h) to avoid hammering peers.

### Tests
`test/unit/oidf/keystore.test.mjs` (12 cases).
