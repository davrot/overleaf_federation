# rp/ — A-side OIDC relying party

The **relying party (RP)** for when *this* instance initiates a federated login
against an approved peer (the peer is B / provider, we are A).

### Files
| File | Role |
|---|---|
| `State.mjs` | HMAC-signed PKCE state (`b64url(JSON).b64url(HMAC-SHA256)`, `timingSafeEqual`), 120s TTL. `createPkceVerifier()`, `signState(intent)`, `verifySignedState(state)`, `persistPkceState(...)`, `consumePkceState(...)` (single-use, Redis `federation:rp-state:*`). |
| `CodeExchange.mjs` | `exchange(peerOrigin, { code, redirectUri, pkceVerifier }, redis)` — POST `{code, grant_type, client_assertion}` to peer's token endpoint (30s timeout), returns `{ idToken, accessToken }`. |
| `CallbackRouter.mjs` | `GET /federation/oidc/rp/callback` (non-csrf). Verifies the signed state, consumes PKCE, exchanges the code, provisions the mirror user (`app/models/User.mjs` `federated` subdoc), logs in via `UserSessionsManager.trackSession`, and 302s to the project URL (open-redirect-hardened: only root-relative paths accepted). |

### State intent (what the HMAC protects)
`{ origin, localName, projectId, url, ... }` — owner-set, but the HMAC makes it
tamper-evident end-to-end: minted at invite time, consumed at callback.

### Notes
- The PKCE verifier lives in **both** the session slot and Redis (for cookie-less
  callback edge cases), single-use on either path.
- `CallbackRouter` must be mounted **between** the OIDC bridge and the OIDC
  provider on the web router (see `index.mjs`).
