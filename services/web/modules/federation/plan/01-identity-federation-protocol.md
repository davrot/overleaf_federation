# overleaf-cep Identity Federation — Protocol Specification

> Status: **design (v2, OIDF 1.0 trust)**. Identity federation, *not*
> content/stream federation. The trust layer is **OpenID Federation 1.0**
> (OIDC WG Final, 2026-02-17), implemented with the reference
> `@oidfed/*` packages; `02-trust-model-oidf.md` is the authority for
> everything trust-related and for the v2 key model. The runtime S2S is
> OIDF **client assertions** over HTTPS with `jti` replay protection;
> `03-s2s-wire-protocol.md` is the authority.
> Nextcloud v36 remains a *behavioural* reference only (pairwise bootstrap
> flow, rate-limit budgets, JWKS model). NC wire compatibility is **not**
> a goal.

## 1. Scope and what this is (and is not)

**We federate identities, not content.** A project always lives on one
machine, and editing happens on *that* machine, using its normal editor
stack. When an owner wants a user from another machine to edit a project,
the visiting user proves **who they are** (their home machine vouches for
them, over OIDC) and then edits locally on the machine that owns the
project. There is **no** streaming, no import, no ZIP relay, no sub-
protocol for the editor data stream.

Consequences:
- No document sync protocol. `real-time` and linked-url-proxy are untouched.
- No cross-instance project storage. Each instance's Mongoose holds its own
  `project`/`doc`/`user` rows.
- The only things that cross the wire:
  (a) OIDF **entity configurations** (the leaf: a signed public-metadata
  statement per instance),
  (b) **registration statements** (trust establishment, OIDF explicit
  client registration, signed) — **institutional mode only** (P3); pairwise
  (P0–P2, the default) has no cross-machine trust wire, the admin pins
  the peer's entity key locally (02 §4);
  (c) small **S2S actions** (invite authorisation / invite preview /
  revocation), each a signed *client assertion* over a JSON body,
  (d) a standard OIDC **authorization-code redirect** (the user's browser)
  carrying a short-lived, single-use grant into a local session.

No RFC 9421, no custom S2S `federate` handshake — these are v1 artifacts,
superseded. Trust establishment is now purely OIDF (§4).

## 2. Roles — symmetric

Every instance plays **both** roles at once; there is no dedicated
"provider" deployment. The two roles are per-*flow*, not per-*instance*:

| Role | Meaning | Stack |
|------|---------|-------|
| **Home (OP)** | This instance authenticates *its own* users and vouches for them to other instances. | `oidc-provider` v9 (IdP engine, `05 §8`) + `@oidfed/leaf` (entity statement) |
| **Partner (RP)** | This instance accepts a vouched user for a project that lives here and mints a local session for them. | `fetch` + the existing top-level `jose` for id_token verification — **no** OIDC client library |

Because the roles are symmetric and per-origin, instance `A` is *Home* for
the user whose home origin is `A`, and *Partner* for visiting home users
from other origins. The same binary and the same module
(`services/web/modules/federation/`) handle both; the only inputs are the
instance's own origin, its trust-anchor set, and the OIDF registrations
stored locally (04 §2).

## 3. Identity model

### 3.1 Federated identity anchor — the *tuple* `(origin, localName)`

An identity is a **tuple** `(origin, localName)`:

- `origin` — the home instance's FQDN (the host of `Settings.siteUrl`,
  e.g. `overleaf.uni-bremen.de`). Not a mail domain.
- `localName` — the home login name, i.e. the home user's email local-part
  convention as overleaf-cep stores it (may contain `@`, e.g.
  `bla@example.com`).

Display serialization (invite form, admin search, audit rendering) is
`localName:origin` — e.g. `bla@example.com:overleaf.uni-bremen.de` — with
the colon as a **separating, human-facing** mark and the split rule
"split on the last colon". The colon convention exists **only** at that
human I/O boundary:

- **Wire**: two *separate* OIDC id_token claims, `origin` and
  `localName` (issuer = the home instance, 05 §8.5). No concatenated
  anchor string travels.
- **Storage**: two separate fields, `User.federation.origin` and
  `User.federation.localName` (04 §1). No concatenated string is stored.
- **Claim `sub`** is the B-local user id (oidc-provider `public` subject
  type: `sub = User._id`, 05 §8.5); it is meaningful only to B and is
  **never** the anchor. The claim model inherits OIDF 1.0's invariant —
  identity claims are issuer-qualified, `sub` is a local identifier —
  which is exactly why we adopt OIDF for trust: the invariant is the
  standard, not an add-on.

### 3.2 Home account vs mirror account

- **Home account**: a normal local account on the home instance. The home
  instance is the **oracle** for the identity of its own users (login,
  SSO-SAML, LDAP, federated grant resolution) and decides, at login and at
  every grant, whether a given local user exists and whom they are.
  Nothing about the home account is transferred.
- **Mirror (federated) account** on the partner instance: a *normal*
  `User` row, *linked* — not flagged — by the presence of
  `User.federation = { origin, localName, federatedAt }` (04 §1). There is
  **no `kind` discriminator**: presence of the subdocument *is* the mark,
  the same pattern `User.thirdPartyIdentifiers` uses for enterprise-SSO
  links (verified `models/User.mjs` L233). `hashedPassword` is
  `undefined` on mirror rows and this is a **consequence** of "mirrors are
  never created through signup" (SAML/LDAP/SSO login paths actively clear
  passwords for their users, verified `SAMLAuthenticationManager.mjs` L78
  `$unset`) — it is not an identity mark. The mirror is a **full** local
  user: settings, projects, editor stack; only the authentication path
  differs (federated grant vs password/SSO). It is reachable **only**
  through grant resolution (`06 §3` proves local/SSO lookups cannot touch
  it).

### 3.3 The `:` rule — now display-only (re-scoped from v1)

overleaf-cep permits (nearly) anything in a login name, including `:`.
Under the v1 single-string anchor that made the anchor ambiguous; under
v2 the wire and storage are two-field, so **nothing on the wire is
affected** by `:` in `localName`. The ban is retained because the
*display* serialization `localName:origin` (invite form entry,
admin-search parse, audit rendering) splits on the last colon, and a
`:` in `localName` would be ambiguous for that parse. We therefore reject
`:` in new `localName` values (signup + email-change paths, `04 §1.1`;
read-only migration audit over existing rows; near-zero hits in practice,
RFC 5321 allows it but no common provider uses it). It is a **display-
layer constraint**, not a protocol constraint.

### 3.4 Project ownership & creation rules

- **Owner of a project** is a local user row on the machine where the
  project lives (`Project.owner`, ObjectId ref to `User`).
- **Project creation**:
  - Home user on their home machine: always allowed (status quo).
  - Mirror user on a partner machine: only when the *partner* admin has
    enabled `federation.allowFederatedProjectCreate` (default **off**).
    "Not over-cross": the partner admin decides what happens on *their*
    machine.
- **Editing a project as a mirror user**: permitted because the partner
  instance resolved a valid grant for that identity and minted a local
  session; the project's `Permissions` authorization is what actually
  authorises the edit, exactly as it does for a local user.

## 4. Trust model — OIDF 1.0 (pairwise depth-1 and institutional are
the same code path)

**Authority: `02-trust-model-oidf.md`.** Summary here for flow context:

Federation trusts are **peer-level and per-direction**: each direction is
an independent relationship (A registers at B, B registers at A), with its
own admin approval on the receiving machine. There is no cross-admin power
("the admin decides what happens on THEIR machine": not over-cross).

The trust mechanism is **OIDF 1.0 trust chains** over entity
configurations, not a custom handshake:

- Every instance serves a **leaf Entity Configuration** at
  `GET https://<origin>/.well-known/openid-federation` (signed JWT, ES256,
  `application/entity-statement+jwt`; `@oidfed/leaf` handler, `02 §2`),
  with entity types `openid_provider` + `openid_relying_party`.
- Trust establishment is the **
  per-direction admin pin** (pairwise, 02 §4 / 04 §2, the P0–P2 default;
  two admin acts, one per direction). Institutional (P3) adds OIDF
  **explicit client registration** (`@oidfed/oidc`, 02 §4): the
  registering side (RP role) signs its client metadata + trust chain and
  POSTs it to the other side's `federation_registration_endpoint`; the
  receiving side's admin approves or denies; the approval writes a
  `FederationPeer` row.
- **Pairwise depth-1** ("overleaf-cep ↔ overleaf-cep" in the wild, and the
  v1 "federate" UX): each side's admin pins the *other* side's entity key
  as a **trust anchor** for that peer (per-direction, admin action,
  TOFU-aided by `compareTrustAnchorKeys`, `02 §3`). OIDF's trust-chain
  resolver treats a leaf whose `entityId` is itself an anchor as a
  depth-1 chain — the peer is its own anchor. Same code path as
  institutional (the leaf's claim shape is unchanged, `authority_hints`
  is simply absent):
- **Institutional scale-out** (DFN-AAI / eduGAIN, `02 §6`): the instance's
  leaf gains `authority_hints` and the anchor set gains the
  institutional TA (e.g. DFN-CERT's anchor); `discoverEntity` and
  `OidcRelyingPartyRole.explicitlyRegister` run end-to-end. DFN-AAI is a
  *deployment configuration*, not a code path.

**Two key sets per instance** (the v1 "one key, two consumers" is a bug,
`06 §7`): a **federation key** (signs leaf + client assertions +
registration statements; `@oidfed/core` `FederationKeyLifecycleProvider`,
published→active→retiring→retired, historical keys served — `02 §5`) and
an **OIDC signing key** (signs id_tokens; oidc-provider v9 keystore,
`05 §8.6`). Separate rotation, separate leaks, different blast radii.

Key rotation is *not* an S2S action: it is local (publish/switch/retire
via the lifecycle provider, `02 §5`) and peers discover the new
`kid` through the leaf's `jwks` on their next JWKS fetch (1 h cache,
kid-mismatch refetch, 04 §6). There is no "re-federate" S2S call.

## 5. Grant flow — the OIDC "open"

When owner `O` (on `A`, in partner role) clicks **"Open on B"** for
project `P` with a federated invitee (`localName = bla@example.com`,
`origin = overleaf.uni-bremen.de`):

1. **Local authorisation check (on A).** A resolves the invite (the owner
   typed `bla@example.com:overleaf.uni-bremen.de`; the display parser
   splits on the last colon, §3.3) and checks: peer `B` is approved
   (04 §2 `status: approved`); the tuple is well-formed (`localName`
   present, no `:` in `localName`, §3.3); the invite privileges are within
   what A will grant (invite privilege ceiling, 04 §3).
2. **S2S invite preview (optional UX; cached 60 s).** A MAY issue the
   `invited` client-assertion to B (03 §4.2) to show the owner a profile
   preview (displayName + avatar) before saving. The invite is savable
   without it (admin "defer verification" toggle).
3. **Redirect to B (home/OP), public client + PKCE.** A issues a standard
   OIDC authorization-code redirect to B's authorization endpoint
   (oidc-provider v9, served at `https://<B>/federation/oidc/auth`,
   `05 §8.1`):
   - `client_id = urn:overleaf-federation:client:<A-origin>` — a
     *deterministic, non-secret* identifier derived from A's origin alone
     (05 §8.8); B's oidc-provider resolves it against its static `clients[]` (boot-reconstructed from approved peers,
     B's approved-peer set, so "is A approved on B?" is answered by the
     OIDC engine itself — no separate S2S trust check is needed at grant
     time,
   - **public client, `token_endpoint_auth_method: none`**, PKCE
     `code_verifier` + `S256` challenge (verifier in A's express-session
     + short Redis backup, 05 §3.1), no client secret anywhere,
   - `scope=openid`, `response_type=code`,
     `redirect_uri=https://<A-origin>/federation/oidc/rp/callback`,
     `state=` an HMAC-signed JSON nonce (intent id, project id, nonce —
     bound to A's session row to prevent cross-visitor state reuse),
   - `nonce` (OIDC OID) for the id_token.
4. **B session bridge (two-step, same-screen UX).** (a) *Login* step:
   B's interaction bridge (05 §8.3, mounted **before** provider callback)
   asks B's **own overleaf session** first — if the visitor is logged in
   on B, the bridge auto-answers `interactionFinished` with
   `login: { accountId: <User._id> }` (no login screen); otherwise the
   visitor logs in through B's normal `/login` and comes back. (b)
   *Consent* step: silent via B's stored Grant for
   `(accountId, client_id)` when it covers `openid` + the required claims
   (`loadExistingGrant`, 05 §8.4); first-ever visit shows **one** consent
   screen per B user per peer-client (not per invite), with the
   "remember the choice" pre-check (default on) persisting the Grant.
5. **Grant.** B mints the authorization **code** (oidc-provider
   `ttl.AuthorizationCode`, single-use by adapter `consume()`, 05
   §8.2, 120 s) and an id_token (ES256, `iss` = B's issuer
   `https://<B>/federation/oidc`, `sub` = B-local `User._id` under
   `subjectTypes: ['public']`, plus the identity claims `origin`,
   `localName`, `displayName`, and optional profile fields per B admin's
   claim allow-list, §8.3). **The portable identity is the claim pair
   `(origin, localName)` — never `sub`.**
6. **Redirect back to A.** B 302s to A's callback with `?code=…&state=…`.
   The URL is redacted (`code` is a secret, §8.1/06 §6).
7. **Code exchange (on A, no client library).** A fetches B's token
   endpoint (`POST` + `grant_type=authorization_code`, the
   `client_id`, the `code`, the `code_verifier`) and verifies the returned
   id_token with the *existing* `jose` dep against B's published JWKS
   (cached `federation:jwks:<origin>`, 1 h, kid-mismatch refetch):
   signature, `iss` (exactly B's issuer), `aud` (exactly A's client id),
   `exp`, `nonce`. Then **re-binds** the claim pair
   `(origin, localName)` to the invite's tuple. **Any mismatch = abort,
   no session, audit row `identity-mismatch`.**
8. **Local session on A.** A resolves the tuple to its mirror row
   (`User.findOne({ 'federation.origin': B, 'federation.localName': X })`,
   auto-created on first sight, 04 §1), checks project `Permissions` (or
   auto-grants from the invite's `privileges`), and establishes a
   **normal A express-session** (`overleaf.sid`, same 5-day TTL as local
   users). The grant is **an opener, not a session**: after step 8 the
   visitor is indistinguishable from a local user for the lifetime of that
   session.
9. **There is no refresh token in v1** (`scope: openid` only). Re-login
   via B's normal auth-code flow is **silent** (no re-consent): B's Grant
   for `(accountId, client_id)` matches, `loadExistingGrant` returns it,
   and the visitor experiences "open on A" as one click after the first.

**The visitor then edits on A** with A's normal editor stack — no
streaming, no relay, no cross-instance document traffic.

## 6. Discovery (OIDF well-known + standard OIDC configuration)

Every instance serves two well-known documents (both read-only,
cacheable, no auth):

1. **`GET https://<origin>/.well-known/openid-federation`** — the leaf
   Entity Configuration (signed JWT, §4; `@oidfed/leaf` handler). This is
   *the* discovery point for trust establishment and for the peer's
   federation `jwks` (02 §2). Peers fetch it: first "federate with X", on
   `kid` mismatch, and on admin "refresh trust". **Never** per grant.
2. **`GET https://<origin>/federation/oidc/.well-known/openid-configuration`**
   — oidc-provider's standard OIDC discovery document (05 §8.1, served
   automatically by the provider mount). Carries the issuer,
   `authorization_endpoint`, `token_endpoint`, `jwks_uri` (the **OIDC
   signing** JWKS, distinct from the federation leaf's keys, §4).
3. **`GET https://<origin>/federation/oidc/jwks`** — the standard OIDC
   JWKS for the OIDC signing key (oidc-provider mount default).
4. **`GET https://<origin>/federation/federation-keys`** (02 §5) — the
   historical *federation* key set, for in-flight verification of old
   statements during key rotation.

The v1 custom `GET /.well-known/overleaf-federation` (JSON,
origin/name/jwksUri/apiVersion/capabilities) is **deleted**; everything it
conveyed is now in the leaf EC (name → `metadata` extension key, allowed
since the EC is an open map; but we keep the leaf *standard-only* in v1 and
carry operational metadata in the admin display instead) and in the
standard OIDC configuration. The v1 `GET /federation/jwks` (federation key
JWKS) is **deleted** for the same reason: the federation key set is served
by `@oidfed/leaf` at the well-known URI and by `federation-keys`.

## 7. S2S wire — client assertions (overview; authority `03`)

Runtime machine-to-machine traffic is three actions — `authorize-invite`,
`invited`, `revoke` (03 §4) — each:

- `POST https://<peer-origin>/federation/s2s`, JSON body
  `{ action, from, to, ts, payload }`,
- signed **client assertion** header (`OidcRelyingPartyRole.createClientAssertion`,
  ES256, `jti`, `exp=5 min`; `03 §2`), verified against the peer's
  *federation* JWKS (leaf cache) + OIDF verification + `ReplayStore`
  `jti` dedup (`02 §7`),
- **any verification failure = `401` + no state change** (03 §2 step 4).

There is **no** S2S `federate` action, **no** RFC 9421 canonicalization,
**no** custom `mht`/signature header, and **no** background poll/fetch of
any kind (the "never fetched per grant" rule of v1 §6 is retained:
discovery fetches happen only on trust-establishment and kid-mismatch).
Admin-initiated trust revocation is the S2S `revoke` action (03 §4.3);
key rotation is local (02 §5) and propagates via the leaf's `jwks`.

## 8. Security properties and redactions (authority `06-security.md`)

`06` is the authority for the threat model, the
**link-disjointness** proof (local / SSO / federated-mirror identity
systems are disjoint by lookup construction — 06 §3), the deny-list
(06 §4), the redaction points (06 §6), and the key-leak blast-radius
table (06 §7). What §8 of v1 said is all *true* and is re-listed in 06
without change in substance:

- **Grant is a secret** (06 §2): code + id_token, single-use, 120 s,
  `Cache-Control: no-store`, redacted in every log/URL artifact,
  `?code=` redacted from access logs.
- **S2S is signed and minimal** (03 §1): the client assertion is the
  *only* signature mechanism at runtime; payloads carry trust +
  invite metadata and nothing else; `jti` dedup replaces the v1
  `nonce` + `ts` dedup (03 §3).
- **Allow-list / deny-list** (06 §4): the id_token claim set
  (`origin`, `localName`, `displayName`, optional profile — 04 §8) is
  the *only* identity data that crosses; the deny-list (passwords,
  billing, git/zotero/compile config, project bytes, keys) is
  absolute and **not** overridable by any trust anchor, TA, or
  institutional federation (06 §5: claim policy is per-B-admin local
  policy; `@oidfed` has no claim-policy mechanism, confirmed in source —
  we must not depend on one that does not exist).
- **Redaction** (06 §6): `?code=`, `id_token`, client-assertion values
  (S2S audit stores `{iss, aud, jti-hash}`), and the federation key PEM
  path.

The v1 §8.3 table (field-by-field, direction-by-direction) is preserved
in 06 §4 and is the gate for the security review sign-off (07).

## 9. Rate limiting (03 §5 is the authority)

| Surface | Budget | Window | Where |
|---------|--------|--------|-------|
| S2S `authorize-invite` | 30 per (`caller`, `invitee.localName`) | 120 s | receiving instance |
| S2S `invited` | 30 per (`caller`, `invitee.localName`) | 120 s | receiving (60 s response cache on caller) |
| S2S `revoke` | 5 per `caller` | 1200 s | admin action |
| OIDF registration (trust establishment) | 5 per `caller` | 3600 s | receiving (03: replaces the v1 `federate` budget; registration is still an admin-driven, low-volume act) |
| oidc-provider authorize (per visitor) | 10 per B-IP | 120 s | B (IdP) — login/consent burst guard |

All budgets on the **receiving** instance, Redis-backed (04 §6),
`429` + `Allow-Retry-After` on exceed. NC v36 `FederationRateLimit`
(5/1200 s, provider-to-provider background) is the *model* reference;
overleaf-cep has no background sync, so those budgets apply only to
interactive surfaces.

## 10. Error codes

- OIDF: standard OIDF error responses (`FederationErrorCode` values:
  `invalid_request`, `invalid_metadata`, `signature_invalid`,
  `trust_anchor_unknown`, and so on, 02 §8) from leaf / registration
  handling.
- S2S (in-band `{ ok: false, code }`, 03 §6): `bad-signature`,
  `unknown-kid`, `peer-unknown`, `peer-not-approved`, `replay-jti`,
  `clock-skew`, `federation-off`, `invitee-unknown`, `invitee-disabled`,
  `rate-limited`.
- OIDC: standard OIDC (oidc-provider v9, 401/400 per OIDC spec). A-side
  add on grant resolution: `identity-mismatch`, `peer-unknown`,
  `grant-expired`.

Human `detail` is for admins, never a user-facing string on a
cross-boundary response.

## 11. Versioning

`apiVersion` is **out** of the wire (it lived in the deleted v1
well-known). Compatibility is governed by: (a) the OIDF version this
instance speaks (v1 of the plan = OIDF 1.0, 1-to-1), (b) the
`oidc-provider` version (pinned; 05 §8 is version-specific),
(c) the *client id convention* `urn:overleaf-federation:client:<origin>`
(the only overleaf-specific wire constant, and a *string*, not an
intentional compatibility promise — both sides re-derive it, and a
change is a breaking change flagged at registration time, not a runtime
one).
