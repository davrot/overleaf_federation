# overleaf-cep Identity Federation — Data Model (v2)

Grounding: mongoose models live in
`services/web/app/src/models/` (`User.mjs`, `ProjectInvite.mjs`,
`Project.mjs`, verified 2026-09-17). The oidc-provider adapter is
rewritten against the verified v9.12.2 7-method contract in `05 §8.2`
(the v1 adapter description below is obsolete where it disagrees).
Trust/peer state is OIDF 1.0 (see `02-trust-model-oidf.md`): the
`FederationPeer` collection stores the **federation** key anchor
(pairwise pin, institutional chain anchor) and — institutional mode
only — the explicit **registration** subdocument, and it is the single
source for what B trusts.

## 1. `User` extension (local, on BOTH the home and partner instances)

The federated mirror is a **link**, not a species: the subdocument's
*presence* is the discriminator (same pattern as
`User.thirdPartyIdentifiers` for SSO, verified `models/User.mjs` L233).
No `kind` field anywhere.

```js
// services/web/app/src/models/User.mjs  (add to existing schema)
federation: {
  origin:      String,   // home server's FQDN, e.g. 'overleaf.uni-bremen.de'
  localName:   String,   // home login name, e.g. 'bla' (may contain '@')
  federatedAt: Date,     // when this mirror row was created/last re-bound
  // NO 'kind'. Presence of 'federation' = federated mirror.
  // hashedPassword is a CONSEQUENCE: mirror rows are created by the
  // federated grant handler, never by signup, so hashedPassword is
  // simply never set (undefined). SAML precedent: SAMLAuthenticationManager.mjs
  // L78 does $unset: { hashedPassword: "" } on SSO login — same posture.
  // email: '' — mirrors are NOT reachable by email lookup (06 §3).
}
```

- Mirror rows have `hashedPassword: undefined`, `email: ''`, `emails: []`.
  They are reachable **only** via the federated OIDC grant (01 §5) and are
  looked up exclusively by the two-field query
  `User.findOne({ 'federation.origin': X, 'federation.localName': Y })`.
- They are **full** local users for everything else: settings, projects,
  compile preferences, editor stack — the only difference is the
  authentication path (federated grant vs password/SSO).
- `role` is left default (`''`); `AdminController` (verified: gates on
  `user.isAdmin`) excludes them automatically. No federated "restricted
  species" code path exists (06 §2, "grant is an opener").
- **Why this kills the v1 local-vs-federated collision by construction**
  (06 §3): SSO lookups (`email`, `thirdPartyIdentifiers`,
  `samlIdentifiers`) cannot match mirror rows (empty email, no identifier
  subdocs); federated lookups cannot match SSO rows (they have no
  `federation` subdoc). Same collection, disjoint queries.
- **No unique index on `email`** exists (verified: none on `User.mjs`), so
  many `email: ''` mirror rows coexist fine; the `(federation.origin,
  federation.localName)` pair is unique *by lookup discipline*, not by
  index (partial unique index on `federation.origin` + `federation.localName`
  *with* `partialFilterExpression: { federation: { $exists: true } }`
  where Mongoose supports it — verify `User.mjs` for partial-index
  precedent; if unsupported, rely on the query discipline and log
  duplicates at creation).
- **Display convention** (only at human I/O boundaries — admin search,
  audit rendering, the invite form): `localName@origin`, e.g.
  `bla:overleaf.uni-bremen.de` is the *serialized* form the owner types;
  the colon is a separator, and storage/wire use two fields (01 §3.1).
  `:` remains forbidden in `localName` for that single reason (display
  ambiguity); it is **not** an anchor-format rule anymore.

### 1.1 The colon-forbidding change (display-level now, 01 §3.3)
The `:` ban now applies only to the **display serialization** `localName:origin`

Files to touch (all under `services/web/app/src/`):

- `Features/Authentication/SignUpController.mjs` — validation on
  `email` field before insert.
- `Features/Authentication/InviteController.mjs` (or equivalent in
  `Features/Collaborators/CollaboratorsInviteController.mjs`) — validation
  on invite target before `ProjectInvite` insert.
- `Services/Authentication/AuthenticationManager.mjs` — final
  `assertEmail`-style guard before `User.create` (defence-in-depth; the
  controller checks are UX, this is the invariant).
- Add a mongoose `pre` hook on `UserSchema` that throws
  `ValidationError` if `/\:/` matches `email` or any `emails[].email`
  (this is the *last* line of defence; the migrations below clean
  existing data).
- One-off **migration** (`models/migrations/` pattern, check
  `app/src/models/migrations/` for existing examples): audit existing
  `User.email` + `emails[].email` for `:`; log a warning for each (do
  *not* silently rewrite). The `:` case is near-zero in practice
  (RFC 5321 allows it but no common provider uses it); the migration
  is for *surprise detection*, and the answer for any hit is "ask the
  user to change their address; federation anchors cannot use a `:`"
  — but this is pre-existing data and not a federation requirement.

The migration enforced going forward; the migration stays read-only (audit, warn, no
silent rewrite) because the ban exists to keep invite-form parsing and
admin-search rendering unambiguous. The wire (claims) and storage
(two fields) are **not** affected by this ban.

### 1.2 What federated rows **cannot** do (enforced by existing code paths)

- Reset password: `PasswordResetController` already refuses if
  `hashedPassword` is empty; we add the mirror-row branch (test:
  `user.federation?.origin`)
- Email change: `EmailsController`/`UserController` — mirror rows
  have no email to change; the UI hides it, the API returns
  `403 {code: 'not-federated-local'}` on attempt.
- Delete: mirror rows are admin-deletable (removes the mirror; the
  next grant re-creates it). Admin-delete is the only way a mirror
  row is deleted otherwise.

## 2. New collection: `FederationPeer` (OIDF terms, v2)

`services/web/app/src/models/FederationPeer.mjs`. In v1 this stored a
peer origin + `jwksUri` + pinned JWK from the custom S2S `federate`.
In v2 it stores the **federation-key anchor** (the self-signed depth-1
leaf, pairwise, or the institutional chain anchor) that makes this peer
admissible on this machine (02 §3–§4), plus — institutional mode only
(02 §4) — the explicit **registration** subdocument. The row is what the
oidc-provider `clients[]` array is reconstructed from at boot (05 §8.8)
and what the S2S `authorize-invite`/`invited`/`revoke` handlers consult
for admin-approved state.

```js
const Schema = new Schema(
  {
    origin: { type: String, unique: true, match: /^[a-z0-9][a-z0-9.-]+$/i },
    displayName: String,               // admin-entered (pairwise) / from
                                          // registration metadata (institutional)
    entityId: { type: String },        // 'https://<origin>' — OIDF entity id (02 §2)
    mode: { type: String, enum: ['pairwise', 'institutional'], default: 'pairwise' },
    // Institutional mode only (02 §4): written from
    // ExplicitRegistrationResult on approval. pairwise = no registration
    // statement exists; pinning IS the establishment (02 §4 item 1), so
    // this block is absent for pairwise peers.
    registration: {
      clientId: String,                // our convention, see §7 (05 §8.8)
      expiresAt: Number,               // registration statement exp
      trustChainExpiresAt: Number,     // 02 §4 (explicitlyRegister result)
      childAnchorJwks: String,        // the anchor key (TA or pinned), JWKS
                                        // (audit/replay — the raw JWS is NOT
                                        // stored: the pin is the ground truth)
      childAnchorKid: String,
    },
    // The federation key we trust FOR this peer (public parts only; 02 §3:
    // pairwise = peer-own leaf key pinned by admin; institutional = the
    // anchor key from the institutional chain). Never the private side.
    anchorJwks: { type: String, index: false },   // JWKS doc (JSON-serialized)
    kid: String,                         // active keyId we verify against
    thumbprint: String,                  // sha256 of the JWK (TOFU admin display, 02 §3)
    // Trust direction (per-direction establishment, same shape as v1):
    direction: { type: String, enum: ['outbound', 'inbound', 'both'] },
    //   'outbound' = we pin B (B trusts us, A→B direction)
    //   'inbound'  = B pins us (we trust them, B→A direction)
    status: { type: String, enum: ['pending', 'approved', 'revoked'] },
    // 'pending' = pin/registration recorded, admin has not approved yet
    // (pairwise: admin fetch + click-verify, 04 §2.1; institutional:
    // 02 §4 `onRegistration` hook writes here before admin click)
    federatedAt: Date,
    approvedAt: Date,
    lastTrustRefreshAt: Date,            // leaf/JWKS re-fetch on kid-mismatch (04 §6)
    // Revocation extras (03 §4.3, 06 §8):
    killOutstandingCodes: { type: Boolean, default: false },
  },
  { collection: 'federationPeers' }
)
```

Indexes: `origin` (unique); `(status, direction)` for the admin dashboard.
Note: `anchorJwks` + `status: approved` are the fields
`createProvider.mjs` reads at boot to rebuild `clients[]` (05 §8.8);
`registration.clientId` (institutional only) supplies the client_id there.
Nothing else about OIDF trust is denormalized here (leaf fetches are
on-demand, 04 §6).

### 2.1 `status: 'pending'` (the admin approval gate)

The `pending` state is **admin-triggered**, and arrives one of two ways:
- **pairwise** (P0–P2, the default): B's admin clicks "Fetch leaf" in
  the peer form UI; B fetches `<peer>/.well-known/openid-federation`
  over TLS, the response is verified against B's *current* anchor set
  (depth-1: self-signed, §3 of 02), and the row lands as `pending`
  with `anchorJwks` extracted. There is no registration statement.
- **institutional** (P3, 02 §4 `onRegistration`): the explicit
  registration statement arrives inbound; the row lands as `pending`
  with the `registration` subdocument + the chain's anchor key.

In both paths B admin's peer list shows: `entityId`, `displayName`
(admin-entered for pairwise, from registration metadata for
institutional), `thumbprint`, kid, and the fetch source indicator
("fetched over TLS from <peertld>" vs "pasted" from admin).
Until approval, `authorize-invite`/`invited` from that origin are
answered `401 peer-not-approved` (no read-only carve-out: v1's
"read-only until approved" is tightened — a not-yet-approved peer must
not be probed). Grant minting is refused because `clients[]` has no
entry for it (reconstructed only from `approved`, 05 §8.8).
On approval: `status = 'approved'`, `approvedAt`, `direction` updated;
in institutional mode the "request reverse registration" button issues
the outbound explicit registration from B (02 §4), writing B's own
`FederationPeer.direction = 'outbound'` row locally.

## 3. `ProjectInvite` extension (`models/ProjectInvite.mjs`)

Existing schema (verified): `email`, `encryptedToken`, `tokenHmac`,
`sendingUserId`, `projectId`, `privileges` (Union of String|Boolean —
`PrivilegeLevels`), `createdAt`, `expires` (TTL 30 d), `reusable`,
`subscriptionId`. Add:

```js
federated: {
  type: Boolean, default: false,     // this invite targets a FEDERATED identity
  origin: String,                    // e.g. 'overleaf.uni-bremen.de'
  localName: String,                 // e.g. 'bla@example.com'  (may contain @)
  homeDisplayName: String,           // cached from authorize-invite response
  homeAvatarUrl: String,
  authorizedAt: Date,                // when B approved the invite
  authorized: { type: Boolean, default: false }
}
```

- The owner types the **anchor** `bla@example.com:overleaf.uni-bremen.de`
  into the existing invite field; the controller splits on the **last**
  colon. `federated: true` records origin + localName so the grant UX can
  pre-fill.
- `email` stays empty for federated invites (the anchor is *not* an
  email). The existing `email-unique` indexes must tolerate
  duplicated empty strings for federated rows, so we keep the
  `unique: false` default (verify: `ProjectInviteSchema` has no unique
  index on `email` — correct, it does not).
- No new TTL on `federated.authorizedAt` — B's approval is per-invite, not
  per-identity. If B later revokes the trust, `revoke` (protocol §7.5)
  invalidates pending federated invites for that origin (admin action).
- Invite privilege mapping is unchanged: `privileges` carries
  `PrivilegeLevels.value`; federation does not widen the grant beyond
  what the owner could grant locally. **A federated grant can never
  exceed the invite privilege** (enforced in `PermissionsService` when
  the grant is applied, 04 §4).

## 4. What does NOT cross-instance (deny-list, mirrored in
`01-identity-federation-protocol` §8)

| Field | Where it lives | Never leaves |
|-------|----------------|--------------|
| `User.hashedPassword` | home instance | always |
| `User.subscriptionId` / billing | home | always |
| git-sync config | instance-local `git-bridge` module | always |
| Zotero credentials | `zotero` module | always |
| compile settings | per-project `compile` settings | always |
| Project content bytes (`Doc`/`File`) | project owner instance | always |
| Session secrets | instance | always |
| `sessionSecrets` (app secret) | env | always |

**Why none of these cross**: identity federation moves *authentication*,
not *data*. The partner instance never needs the home user's secrets
to let them edit a project; the session cookie on the partner is local.

### 4.1 What DOES cross (the claim allow-list, per-B-admin local policy)

The id_token (B → A) carries, and *only* carries:
- `sub` (B-local user id; **never** the anchor — 01 §3.2, 06 §3),
- `origin` + `localName` (the identity tuple, always),
- `displayName` (always),
- optional, **per-B-admin** allow-list: `language`, `avatarUrl`,
  `institution` (opt-in).

This is B's *local* policy — not an OIDF claim-policy mechanism
(`@oidfed` has none; confirmed in source, 02 §8). It is set in B's
oidc-provider `claims` config (05 §8.5) and administered by B's admin,
per peer. The deny-list above is absolute and takes precedence over
any allow-list entry that could ever overlap (e.g. `avatarUrl` is a
URL B *publishes* for itself; it is never a local B secret).


## 5. oidc-provider storage (Redis, v9.12.2 contract)

`05 §8.7` is the authority. Summary for this file: the oidc-provider v9
adapter is a **factory**
`(modelName) => instance`, 7 methods — `find`, `findByUid`,
`findByUserCode`, `upsert(id, payload, expiresIn)`, `revokeByGrantId`,
`destroy`, `consume` (05 §8.2). The v1 description here
(`transaction()` / `findModel` / `WITHWATCH` / composite Session) is
**obsolete and deleted** — the bridge in 05 §8.3 uses raw
`interactionDetails`/`interactionFinished` on `(req, res)` and never
goes through the adapter for B's login state.

Redis keys (instance-local, ephemeral; oidc-provider model docs are
JSON + TTL per 05 §8.2 `upsert` contract):

```
federation:oidc:<model>:<id>   -> doc { id, value, exp }   TTL from oidc.ttl
federation:oidc:sub:<uid>     -> adapter model id (Session findByUid index)
federation:oidc:grant:<id>    -> Set<token ids> (revokeByGrantId cascade)
```

Two cookies coexist on the B-side browser: `overleaf.sid`
(overleaf-cep express-session) and the oidc-provider `_session`
cookie (the provider's Session model, Redis-backed via this adapter,
holds `accountId` + `grantIdFor(clientId, grantJti)`). They do
**not** share a name and are not merged; the *only* point where the two
meet is the interaction bridge (05 §8.3), which reads
`req.session.user` (overleaf) and writes oidc state via
`interactionFinished`. This is how "already logged in on B → no login
screen" works in v1 UX (06 §2).

`ttl:` values (05 §8.6): `AuthorizationCode: 120` (single-use secret,
01 §8.1), `Grant: 30d` (per-B admin "remember the choice" persistence —
the "remember the choice" checkbox writes the Grant, not a cookie),
`Interaction: 600` (10 min interaction window), `AccessToken: 3600`,
**no** `RefreshToken` (v1 has no refresh tokens, 01 §5 step 9).

## 6. Redis runtime keys (instance-local, all ephemeral; v2)

Namespace `federation:*` (kept disjoint from overleaf's `overleaf:*`
metrics and express's `sess:*`):

```
federation:jwks:<origin>           -> JWKS doc (JSON)          TTL: 1 h
federation:leaf:<origin>           -> leaf Entity Configuration TTL: 1 h
                                       (OIDF leaf fetch cache; kid-mismatch
                                        refetch per 02 §5 rotation; admin
                                        "refresh trust" button bypasses TTL)
federation:replay:<jti>            -> '1'  TTL: statement exp window (03 §3)
                                       (ReplayStore keys, keyed by jti alone —
                                        leaf ECs carry no aud claim, and we
                                        mint the jti as a UUID, so plain
                                        global uniqueness is sufficient)
federation:ratelimit:authorize:<origin>:<localNameHash>
                                   -> count + windowStart  TTL: 120 s
federation:ratelimit:invited:<origin>:<localNameHash>
                                   -> count + windowStart  TTL: 120 s
federation:ratelimit:revoke:<origin>
                                   -> count + windowStart  TTL: 1200 s
federation:ratelimit:registration:<origin>
                                   -> count + windowStart  TTL: 3600 s
federation:invite-cache:<peerOrigin>:<localNameHash>
                                   -> {approved, displayName, ...} TTL: 60 s
federation:peer-status:<origin>    -> {status, approvedAt, direction} TTL: 5 m
                                       (admin-dashboard fast path over Mongo)
```

The v1 `federation:dedup:<origin>:<nonce>` key is **deleted** (replaced by
`federation:replay:<jti>`); the v1 separate `federation:oidc:dedup:<code>`
key is also deleted (single-use is oidc-provider adapter `consume`, 05
§8.2). `localNameHash` stays as documented (audit-key only, secret-salted
HMAC, never the claim).

**None** of these keys carry a grant secret: code/JWT live under
oidc-provider-managed keys (`federation:oidc:*`), and their presence
*is* the "used" state — oidc-provider does not cache id_tokens beyond
the token doc (05 §8.2).

## 7. OIDC `clients[]` array (reconstructed at boot from `approved` peers)

`05 §8.8` is the authority and the implementation reference. Summary:
B's oidc-provider **does not** resolve clients by `urn:` from an
adapter; instead `clients[]` is **reconstructed on boot** from
`FederationPeer` rows where `direction IN ('inbound','both')` AND
`status: 'approved'`:

```js
// createProvider.mjs (05 §8.6)
clients: await FederationPeer
  .find({ status: 'approved', direction: { $in: ['inbound', 'both'] } })
  .then(peers => peers.map(p => ({
    // institutional -> p.registration.clientId (from the statement);
    // pairwise -> deterministic URN (no registration exists, 02 §4)
    client_id: p.registration?.clientId ??
      `urn:overleaf-federation:client:${p.origin}`,
                                               // (their origin, deterministic,
                                               // 05 §8.8)
    applicationType: 'web',
    redirect_uris: [`https://${p.origin}/federation/oidc/rp/callback`],
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',  // PUBLIC client — PKCE, no secret
    scope: 'openid',
  })))
```

Consequences:
- "Is peer X approved for grants on this machine?" reduces to "is there
  a `clients[]` entry for the client id `X` will present" — oidc-provider
  answers `400 invalid_client` itself if not. The old v1
  `findClient`/`urn:` adapter lookup (and §7's "pairwise client
  resolution" wording) is **deleted**: it was never in the OIDC spec
  sense anyway; the reconstruction is what the engine supports.
- **Public client, PKCE, no client secret** is a *per-entry* property
  (`token_endpoint_auth_method: 'none'`), and the *only* scope is
  `openid` (no `profile` — the profile fields are custom claims on the
  id_token, 05 §8.5; they are not a separate OIDC scope).
- Key rotation (`02 §5`) is **not** a clients[] change: the public keys
  are in the leaf (02 §2), and oidc-provider signs tokens with
  *its own* key (05 §8.6 `jwks` config), a second, separate key set.
- Client id convention is **string-only, not a wire promise**: both
  sides derive it from their own origin (05 §8.8); a change is a
  breaking change, registered at trust-establishment, not at runtime.

## 8. Audit entries (reuse, 04 §8 + 03 §6)

overleaf-cep's existing `ProjectAuditLogEntry` model
(`models/ProjectAuditLogEntry.mjs`) is reused **unchanged** as a
storage vehicle; only the `type` enum values extended here are the
`federated_*` ones. Full list (v2, replacing v1 §8's list — v1 listed
`openid_session_issued` etc., which are OIDC-layer, not audit,
events and are dropped):

Project-scoped (require `projectId`):
- `federated_invite_approved` / `federated_invite_denied` (B-side, at
  `authorize-invite` receipt — one row per action)
- `federation_session_issued` (A-side, per successful grant → mirror
  account resolution, `projectId` = the project being opened)
- `federation_peer_trust_revoked` (either side, on `revoke`; the
  admin action and the old anchor thumbprint, `meta`. Re-`federate` is
  a fresh pin and logged as `federation_peer_registered`.)

Project-optional (peer-level events, `projectId: null`):
- `federation_peer_registered` (per-direction; pairwise = the admin
  pin wrote the row; institutional = `onRegistration` wrote the
  pending row)
- `federation_peer_approved` / `federation_peer_revoked`
  (admin decision; the reverse-direction pin/registration is *not*
  logged here — it is logged as its own `federation_peer_registered`
  row on the other machine)
- `federation_trust_anchor_pinned` (pairwise admin action, `meta`
  holds the anchor `thumbprint` and entity_id — the TOFU audit trail,
  02 §3)
- `federation_key_rotated` (per key-set, `kid` + old/new state; the
  old kid is retained until grace expiry, 02 §5)

`meta` shape (free-form, all values allow-listed — 06 §8):
`{ origin, localName?, displayName?, kid?, anchorThumbprint?,
  registrationJtiHash?, direction }`. **Never**: JWS raw, key material,
password hashes, project bytes, any claim beyond `displayName`.

## 9. Index additions

- `projectInvites`: `(federated, origin, localName)` (dedup on
  re-`federate` for the same tuple).
- `users`: `{'federation.origin': 1, 'federation.localName': 1}`
  *with* `partialFilterExpression: { federation: { $exists: true } }`
  (see 04 §1 above for the partial-index support note — if Mongoose
  does not support partial indexes here, the two-field *query
  discipline* is the contract and this index is advisory for
  admin-dashboard listing; create it as a compound non-partial index
  and rely on the sparse-ish query pattern).
- `federationPeers`: `origin` unique, `(status, direction)` (above).
- `projectInviteAudits` (if `ProjectAuditLogEntry` is project-scoped):
  `(meta.origin, meta.localName)` with `partial` on `meta` — verify
  `ProjectAuditLogEntry`'s actual schema first (04 §9 as written
  pre-v2 flagged this as a "verify" item); if partial is unsupported,
  fall back to a `(meta.origin)` non-part compound index and treat
  federated filtering as query-level.
- **No new indexes on `User.email` / `emails`** (the `:` migration,
  04 §1.1, is read-only and reports only).
