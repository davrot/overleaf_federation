# admin/ — federation admin surface

Site-admin surface (guard: `AuthorizationMiddleware.ensureUserIsSiteAdmin`),
mounted on the CSR `webRouter` at `/admin/federation/*`. All routes are
**per-direction, admin-mediated** (plan 02 §4 / 04 §2: "the admin decides what
happens on THEIR machine").

### Routes
| Method | Path | Handler | Effect |
|---|---|---|---|
| GET | `/admin/federation/peers` | `listPeers` | List peer rows (with `mode`, no secret material) |
| POST | `/admin/federation/peers` | `handlePin` | TOFU pin: fetch leaf EC → depth-1 **or** institutional → `pending` |
| POST | `/admin/federation/peers/:origin/approve` | `handleApprove` | `pending → approved` (invalidates OIDC-provider memo) |
| DELETE | `/admin/federation/peers/:origin` | `handleDeny` | Delete a `pending` row (trust never established) |
| POST | `/admin/federation/peers/:origin/revoke` | `handleRevoke` | `approved → revoked` + best-effort S2S `revoke` |
| GET | `/admin/federation/keys` | `listKeys` | Key metadata (public halves only) |
| POST | `/admin/federation/keys/rotate` | `handleRotate` | Rotate the federation signing key |
| GET | `/admin/federation/audit` | `auditList` | `federation_*` / `federated_*` rows |
| GET | `/admin/federation/trust-anchors` | `listTrustAnchors` | Institutional TA rows |
| POST | `/admin/federation/trust-anchors` | `handlePinTrustAnchor` | Pin institutional TA (entityId + JWK set) |
| DELETE | `/admin/federation/trust-anchors/:entityId` | `handleDeleteTrustAnchor` | Delete a TA row |

### `handlePin` (the interesting one)
1. Fetch `https://<origin>/.well-known/openid-federation` (OIDF well-known;
   timeout `ADMIN_OUTBOUND_FETCH_TIMEOUT_MS = 10000`).
2. Decode + schema-validate the EC; **iss/sub must equal** the requested origin.
3. If the leaf EC carries `authority_hints`:
   - No TA rows configured → 400 `institutional-anchor-missing` (strict; no
     silent pairwise fallback).
   - `discoverEntity(...)` over the configured TAs (10s, `maxChainDepth: 10`):
     - Error → 400 `institutional-chain-failed`
     - Not resolved to a configured TA → 400 `institutional-chain-untrusted`
     - Resolved → `mode: 'institutional'`, `registration` subdoc filled
       (`clientId`, `expiresAt`, `trustChainExpiresAt`).
4. Otherwise → `mode: 'pairwise'`.
5. Store `pending` row (`origin`, `entityId`, `mode`, `anchorJwks`, `kid`,
   `thumbprint`, `direction`).
6. Audit: `federation_peer_registered` + `federation_trust_anchor_pinned`.

### Notes
- TOFU is deliberate: admin pins *before* the peer row exists. Runtime depth-1
  verification (`verify.mjs`) uses the `thumbprint` for cache invalidation on
  kid-mismatch.
- Institutional TA rows are stored in `app/models/FederationTrustAnchor.mjs`
  and are the pin-time ground truth.
