# app/models/ — Mongoose models (module-local)

The module owns three models registered from here (they live in the module
directory, not the app's `models/`, because they are federation-internal and
never imported by the generic app layer).

| File | Collection | Key fields |
|---|---|---|
| `FederationKey.mjs` | `federationkey` | `entityId`, `jwk` (public), `kid`, `thumbprint`, `status` (published/active/retiring/retired), `publishedAt`, `retiredAt`. |
| `FederationPeer.mjs` | `federationpeer` | `origin` (unique), `entityId`, `mode: 'pairwise'\|'institutional'`, `anchorJwks` (a JSON string — multi-key), `kid`, `anchorThumbprint`, `status: 'pending'\|'approved'\|'revoked'`, `direction: 'inbound'\|'outbound'\|'both'`, `federatedAt`, `registration` subdoc (institutional: `clientId`, `expiresAt`, `trustChainExpiresAt`). |
| `FederationTrustAnchor.mjs` | `federationtrustanchor` | `entityId` (unique), `displayName`, `jwks` (public halves), `pinnedAt`. Institutional TA (P3). |

### Notes
- `autoIndex` is globally off in this app; **indexes come from
  repo-root `tools/migrations/`** (the two `20260721*` migration files).
- `anchorJwks` is a JSON string (not an object) so it round-trips through
  JSON and `jwksThumbprint` checks without silent hydration surprises.
- `FederationTrustAnchor.jwks` is a plain object (public halves only);
  private material is rejected at pin time.
