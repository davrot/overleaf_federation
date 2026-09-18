# Runtime S2S wire protocol — client assertions on HTTPS

> Grounding: `@oidfed/oidc` `client-auth/assertion.ts`, `@oidfed/core`
> `ReplayStore` (verified 2026-09-17). This file is the authority for
> every machine-to-machine call that is *not* trust establishment
> (that is `02`).

## 1. What crosses a machine at runtime (and what does not)

Only four things cross at runtime, and they are small:

| # | Transfer | Direction | Mechanism |
|---|----------|-----------|-----------|
| 1 | S2S action `authorize-invite` | A (RP) → B (home) | client assertion, §2–§3 |
| 2 | S2S action `invited` (read-only preview) | A → B | client assertion, §2–§3 |
| 3 | S2S action `revoke` | A → B | client assertion, §2–§3 |
| 4 | OIDC grant (auth-code + id_token) | browser: B → A | `oidc-provider` v9, `01 §5` |

**No RFC 9421. No custom canonicalization. No `federate` action.** Trust
establishment is admin pinning (pairwise) / institutional registration (P3) (`02 §3–§4`); the *only*
signing primitive in runtime S2S is the **OIDF client assertion** — the
same JWT that OIDF 1.0 uses for client authentication in token requests.
There is deliberately no separate S2S signature scheme: one signing key
(the federation key, `02 §5`), one JWT shape, one replay store.

The v1 plan's `federate` S2S bootstrap (`01 v1 §7.2`) is **deleted**.
The S2S envelope that remains is a JSON body inside an *unsigned* HTTPS
POST, plus a **signed `client_assertion` header** (JWT, ES256,
`application/entity-statement+jwt` is NOT used for S2S; see §4).

## 2. The client assertion (wire format)

"**One library call (npm v1.0.0 — STATIC, verified):**

```js
import { OidcRelyingPartyRole } from '@oidfed/oidc'
// OidcRelyingPartyRole.createClientAssertion(clientId, audience, signer, {expiresInSeconds?, jti?})
// signer: the federation key signer (02 §5)
// jti: UUID (our ReplayStore dedups on 03 §3); exp: 5 min, matches clock skew on the wire

const assertion = OidcRelyingPartyRole.createClientAssertion(
  `urn:overleaf-federation:client:${Settings.origin}`, // iss: A's client id
  `https://${peer.origin}/federation/s2s`,              // aud: B's S2S endpoint
  federationKeySigner,                                 // federation key (NOT the OIDC key)
)
```

Wire (all S2S):

```
POST https://<peer-origin>/federation/s2s
Content-Type: application/json
client_assertion: <the JWT, base64url compact>
client_assertion_type: urn:ietf:params:oauth:client-assertion-type:jwt

{
  "action": "authorize-invite" | "invited" | "revoke",
  "from":    "<caller origin, FQDN>",
  "to":      "<target origin, FQDN>",
  "ts":      <unix-ms — advisory, the JWT iat/exp is authoritative>,
  "payload": { ... }
}
```

Receiving (B):
1. Fetch the caller's federation JWKS **once** (cached in
   `federation:jwks:<origin>`, 1 h; refetched on `kid` mismatch —
   the JWKS URI is in the caller's *leaf* `jwks`, `02 §2`; there is no
   per-call JWKS negotiation).
2. Verify the assertion: `iss == urn:overleaf-federation:client:<from>`,
   `aud == B's S2S endpoint`, `exp`/`iat` within tolerance (60 s skew,
   `FederationOptions.clockSkewSeconds` default), signature against the
   cached federation key.
3. `jti` dedup via `ReplayStore` (§3).
4. **Any failure = `401` and NO state change** (the S2S handler is
   transactional: verify → dedup → apply, or refuse).

**No `nonce` field anymore** (replaced by `jti`), **no RFC 9421
`mht`/canonicalization** (JWTs are self-certifying), **no
application/signature headers** (the assertion is the signature).

## 3. Replay, dedup, clock — one store, one tolerance

- **`jti`** is the replay key: `ReplayStore` (`@oidfed/core`) records
  `federation:replay:<jti>` with TTL = `exp` (+ clock tolerance). The
  *same* `jti` delivered twice → `401 replay-jti`, no state change,
  audit entry.
- **Clock tolerance**: 60 s (`FederationOptions`), the same constant as
  OIDF verification. `ts` in the body is advisory (audit log readability);
  *verification* uses JWT `iat`/`exp` only.
- **No per-(peer, action) nonce** — the old `federation:dedup:<origin>:<nonce>`
  key in 04 §6 is retired.

## 4. The three actions (wire payloads)

### 4.1 `authorize-invite` (B is oracle for B's users)

Sent by A (RP) to B (home) when owner O on A saves a federated invite:

```json
{
  "action": "authorize-invite",
  "from": "overleaf-a.example",
  "to":   "overleaf.uni-bremen.de",
  "ts":   1765000000000,
  "payload": {
    "invitee": {
      "origin":    "overleaf.uni-bremen.de",
      "localName": "bla",
      "display":   "bla@uni-bremen.de"
    },
    "project": {
      "ref":              "<A-side project id, opaque to B>",
      "ownerLocalName":   "owner",
      "ownerDisplay":     "owner@uni-bremen.de",
      "privileges": ["edit"]
    }
  }
}
```

B's decision (user exists, not disabled, B admin allows):
```json
// 200 ok:
{ "ok": true,
  "payload": {
    "approved": true,
    "displayName": "...",          // profile fields, bounded by B admin
    "language": "de",
    "institution": "U Bremen",
    "avatarUrl": "https://…/avatar-64.png"
  } }
// 200 refused:
{ "ok": false,
  "code": "invitee-unknown" | "invitee-disabled" | "federation-off",
  "detail": "<admin-visible text>" }
```

B **returns no sensitive fields**: never `hashedPassword`, git/zotero/
compile config, email beyond what A's owner already typed. The deny-list
is `04 §4`. The "profile fields" here are the S2S-side mirror of the
OIDC claim allow-list (`01 §8.3`, 04 §8) — same admin policy, two
surfaces.

### 4.2 `invited` (read-only, 60 s cached on caller)

Same payload as §4.1 without `project.ref`; response is the
`displayName`-plus-`approved` subset only. Rate-limited (§5). This is the
"verify identity before saving the invite" check behind the invite UX
(`05 §8.1`).

### 4.3 `revoke` (admin-initiated trust revocation)

```json
{ "action": "revoke",
  "payload": { "origin": "<revoked origin or 'this-connection'>" } }
```

Receiver immediately:
- stops accepting S2S from that origin (`401 peer-unknown` after the
  assertion check),
- blocks grant minting for that peer on B (oidc-provider `findClient`
  returns undefined, `05 §8.8`),
- **does not** delete mirror rows,
- optionally invalidates outstanding codes (04 §5, admin toggle).
- existing *sessions* on the receiver are **not** killed (v1); see 04 §5.
Revocation is **admin-local**: A's "revoke B" affects only what A does on A's
machine.

## 5. Rate limiting — one budget table (replaces v1 §9 per-action table)

The budgets live in `04 §6`'s Redis keys; this file fixes the *semantics*:

| Action | Budget | Keyed by | Window | Notes |
|--------|--------|----------|--------|-------|
| `authorize-invite` | 30 / 120 s | `(caller, invitee.localName)` | rolling | owner typing an invite |
| `invited` | 30 / 120 s | `(caller, invitee.localName)` | rolling | 60 s *response* cache on caller |
| `revoke` | 5 / 1200 s | `(caller)` | rolling | admin action |

The v1 plan's separate budgets for `federate`/`revoke`/S2S
`federate-rotate` are retired: trust establishment is admin pinning (pairwise) / institutional registration (P3)
(not rate-limited here — that's the TA/anchor fetch) and revocation is
one admin action per direction.

**OIDC-side**: oidc-provider's per-visitor rate limiting for login /
consent is unchanged (NC v36 `FederationRateLimit` 5/1200 s is the
background budget; overleaf-cep has *no* background fetch, so the budget
applies only to interactive authorize hits — 10 per B-IP / 120 s).

Enforcement: Redis INCR + window start, `federation:ratelimit:*` keys
(04 §6), `429` with `Allow-Retry-After` on exceed, on the **receiving**
instance, mirroring NC v36 `lib/private/Security/RateLimiting/Limiter.php`.

## 6. Responses, errors, and audit

Response envelope (all S2S, HTTP 200; errors are in-band):

```json
// success:
{ "ok": true, "payload": { ... } }
// refusal:
{ "ok": false, "code": "<machine-code>", "detail": "<admin-visible text>" }
```

Machine codes (`code`): `bad-signature`, `unknown-kid`, `peer-unknown`,
`peer-not-approved`, `replay-jti`, `timestamp-skew`, `federation-off`,
`invitee-unknown`, `invitee-disabled`, `rate-limited`. (Compared to v1:
`replay-nonce` → `replay-jti`; `clock-skew` unchanged.)

Audit (04 §8, `federated_*` types on `ProjectAuditLogEntry`): every S2S
*receipt* writes one row with `{ assertion: {iss, aud, jti-hash},
action, result }`. The `jti` is **hashed** (audit row, not raw) — the log
is a cross-admin artifact and the raw jti is not secret, but keeping the
log small matters.

## 7. What is deliberately NOT in the S2S surface

- **No `federate` action** — trust is admin pinning (pairwise) / institutional registration (P3) (`02 §3–§4`).
  The admin approval screen on B is what the v1 "federate handshake"
  UX is replaced by.
- **No key rotation S2S** — key rotation is per-instance: publish,
  switch, retire (`02 §5`). Peers discover the new kid via the leaf's
  `jwks` on their next JWKS fetch (kid-mismatch refetch, 1 h cache).
- **No notify/refresh background** (NC OCM `notify`: share updates,
  well-known refresh). Overleaf-cep fetches discovery **on demand**:
  first trust establishment (admin pin: OIDF leaf fetch+verify), kid-mismatch refetch, admin "refresh trust" button.
- **No content** — no project bytes, no settings, no file URLs (the
  deny-list is absolute, 04 §4).

## 8. Mount and middleware (what 05 references)

- `POST /federation/s2s` on B (and on A, symmetrically) →
  `S2sRouter` (`nonCsrfRouter`, mounted per `05 §1.1`), **not** owned by
  oidc-provider.
- The S2S endpoint's audience string is a **fixed per-instance
  constant** `https://<origin>/federation/s2s` — no per-peer audience,
  because the peer is identified by `from` + client assertion `iss`
  (iss == A's client id, which encodes A's origin, §2).
- **No S2S on A's *home* path** unless A is also a peer of B (which, in
  a symmetric deployment, it always is after two admin pins).
- TLS public-CA only. No mTLS, no payload encryption (TLS is the boundary,
  `01 §4.2` unchanged).
