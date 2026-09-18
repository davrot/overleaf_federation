# Trust model — OIDF 1.0 (entity configurations, trust chains, key lifecycle)

> Grounding: **published npm v1.0.0** of `@oidfed/core`, `@oidfed/oidc`,
> `@oidfed/leaf` (verified 2026-09-17 against the npm tarballs *and* the
> git checkout at `~/federation/oidfed` — the export surfaces are
> identical; the free function names cited in v0 of this plan
> (`createLeafHandler`, `explicitRegistration`, `createExplicitRegistrationHandler`)
> do **not** exist in the npm exports — see §8 appendix). OIDF 1.0
> (OpenID Federation, Final 2026-02-17).
> This file is the authority for everything trust-related. If `01` or
> `05` disagree with this file, **this file wins**.

## 1. What "trust" means in this plan

Overleaf-cep federation trusts have exactly one job: **to decide, on a
machine, whether a signed statement from another origin is admissible**.
Two statements need that decision:

1. **Trust establishment** — "may this origin register as a client here /
   may we register there, and is its current key material the genuine one?"
2. **Runtime S2S** (03) — "is this signed action from an origin we already
   trust?"

Both run through the same OIDF 1.0 mechanism: an **Entity Configuration**
(leaf) is verified against **Trust Anchors** by walking a **trust chain**.
There is no custom handshake, no custom canonicalization, no RFC 9421.

The v1 plan's custom `federate` S2S + RFC 9421 bootstrap is **deprecated**
and replaced entirely.

## 2. Entity configuration (leaf) — `@oidfed/leaf`

Each overleaf-cep instance is, in OIDF terms, a **leaf federation entity**
with entity_id `https://<origin>` (its FQDN origin, HTTPS only). Two
entity types are declared, both: **`openid_provider`** and
**`openid_relying_party`** (the symmetric-role decision from `01 §2`).

Serving is a thin layer over `@oidfed/core.signEntityConfiguration`, not a
stock exported handler. The npm `Leaf` class exists but is for
**institutional** operation only — its constructor *throws* on an empty or
absent `authorityHints` (verified: `authorityHints MUST NOT be empty for
leaf entities`, npm v1.0.0). Pairwise is served by our own route:

```js
// oidf/leaf.mjs — pairwise (no institutional hierarchy)
import { signEntityConfiguration, createFederationSigningKey } from '@oidfed/core'

// Build the EC once (cached until leaf expiry / rotation):
const ec = await signEntityConfiguration({
  signer: federationKey.signer,       // our federation key (§5), JwkSigner
  entityId: `https://${Settings.origin}`,
  jwks: { keys: [federationKey.publicJwk] },
  metadata: {
    openid_provider: { /* provider metadata, same keys oidc-provider serves */ },
    openid_relying_party: { /* ... */ },
  },
  // authorityHints: UNDEFINED for pairwise — claim is ABSENT (legal).
  // An empty array is REJECTED by buildEntityConfigurationPayload (check 14);
  // absence is the pairwise marker. Verified with npm v1.0.0.
})
// mount: GET /.well-known/openid-federation on the module router (NOT on the
// oidc-provider mount):
//   res.type('application/entity-statement+jwt').send(ecJwt)
// Body is the raw EC JWT. Content-Type MUST be exactly
// application/entity-statement+jwt (per @oidfed/core performFetch).
```

- `GET https://<origin>/.well-known/openid-federation` serves
  `application/entity-statement+jwt` (raw single JWT) signed with the
  instance's **federation key** (not the oidc-provider key — see §5, they
  are different keys with different lifecycles).
- Served by any overleaf-cep build; no per-peer knowledge required.
- The instance **does not** run a TA or IA in v1 (see §6); it consumes
  anchors and serves its own leaf.

## 3. Trust anchors and trust chains — `@oidfed/core`

Core shape (npm v1.0.0 `d.ts`):

```ts
TrustAnchorSet = Map<EntityId, { jwks: Jwks }>
// createTrustAnchorSet([{ entityId: string, jwks: JWKSet }, ...]) — takes an
// ARRAY of objects, returns the Map. (Not a Map/tuple input.)
```

A trust anchor is **the entity_id of another entity + the key material we
trust to sign for that entity**. `@oidfed/core`'s trust-chain machinery
(verified from `trust-chain/{discovery,resolve,validate}.ts`):

1. `discoverEntity(entityId, trustAnchors, options)` fetches the entity's
   leaf + any superior statements and returns a `DiscoveryResult`
   containing candidate trust chains.
2. `resolveTrustChains` / `shortestChain` pick the chain that reaches one
   of *our* configured anchors.
3. `validateTrustChain` verifies: signature of every statement, chain
   continuity (each statement's `iss` = superior's `sub`), that the chain
   top's key is a configured anchor key, statement TTLs/clock, and
   (optionally) metadata policy.

**Pairwise (depth-1) is a first-class case**, verified in
`trust-chain/resolve.ts`: a leaf EC with **no `authority_hints`** whose
`entityId` is *already a key in `trustAnchors`* yields chain =
`[leafEC]`, `trustAnchorId = entityId`. The peer is its own trust anchor.
This is exactly the "admin pins the peer's entity key" model:

- B's admin clicks "trust `<origin>`", pastes (or fetches) the peer's
  leaf, and B's `onTrustAnchor` hook stores
  `{ "https://<peer-origin>": { jwks } }` in B's anchor store.
- From that moment, B verifies everything the peer signs with **OIDF
  verification only** — no custom S2S trust action exists anymore.
- Admin UX aid (not verification itself): `@oidfed/core`'s
  `compareTrustAnchorKeys` (exported function, npm v1.0.0) for TOFU-style
  human checks (show thumbprint, compare against the value fetched over
  TLS, let the admin confirm). The *decision* is the admin's; the
  *verification* is OIDF's.

**No depth-1 bootstrap needs a TA or IA.** Both "pairwise overleaf-cep
federation" and "eduroam-scale institutional" are therefore one code
path:

```
depth-1:  trustAnchors = { https://peer-a.example: {jwks} }      (pairwise)
depth-N:  trustAnchors = { https://dfn-...: {jwks}, ... }        (institutional;
                         the leaf's authority_hints walk up through
                         institutional TA/IA statements — same resolve path)
```

Scale-out is *data*, not code: a DFN-AAI / eduGAIN membership adds
institutional anchors (and the leaf's `authority_hints` chain) to the
same `trustAnchors` map and the same `discoverEntity` call.

## 4. Trust establishment — admin pin (pairwise) and explicit registration (institutional)

The OIDF 1.0 bootstrap is **explicit client registration**. In npm v1.0.0
it is exposed as the **`OidcRelyingPartyRole`** / **`OidcProviderRole`**
classes (the free functions `explicitRegistration` /
`createExplicitRegistrationHandler` cited in v0 of this plan exist only in
the git source and are *internal* to the npm build — see §8 appendix).

**Pairwise (P0–P2) trust establishment = the per-direction admin pin**
(04 §2). B's admin enters A's origin, B fetches A's leaf
over TLS (admin-triggered), verifies the self-signed depth-1 chain, and
pins `{ [A]: { keys: [...A's EC jwks] } }`. That pin *is* the
establishment step per direction (two admin acts, one per direction).
No registration statement exists in this mode.

**Explicit registration (institutional, P3)** — A registers itself as a
client at B under a shared TA. Construct the role, `initialize` it, then
call `explicitlyRegister`:

```js
import { OidcRelyingPartyRole } from '@oidfed/oidc'
import { createTrustAnchorSet } from '@oidfed/core'

const rp = new OidcRelyingPartyRole({
  protocolKeyProvider,   // our FederationKeyLifecycleProvider (wraps the
                         // federation key; §5). Also used for createClientAssertion
                         // signer selection (getRequestObjectSigner).
  metadata: { redirect_uris: [ /* A's RP callback */ ] },
})
rp.initialize({
  entityId: `https://${Settings.origin}`,   // A's own entity id (iss/sub)
  keyProvider,                              // same federation key provider
  trustAnchors,                             // institutional (TA) anchor set — same
                                             // anchors the instance exposes (04 §2)
  options: { /* FederationOptions, e.g. httpClient for tests */ },
})
// The role discovers B, verifies B against the anchor set, and POSTs the
// registration statement to B's `federation_registration_endpoint`.
// Institutional mode: A's leaf has authority_hints = [<TA>]; both sides
// resolve through the common TA anchor. With pure pairwise anchor sets
// it fails: "No shared Trust Anchor between RP and OP" (see below).
const res = await rp.explicitlyRegister(`https://${peerOrigin}`)
// Promise<Result<ExplicitRegistrationResult>>:
// { ok, value: { registrationStatement: ParsedEntityStatement,
//                clientId, clientSecret?, registeredMetadata,
//                expiresAt, trustChainExpiresAt } }
```

Note (verified npm v1.0.0): the registration EC's `authority_hints`
is **min(1)** (`ExplicitRegistrationRequestPayloadSchema`) — empty hints
fail the wire schema, which is why explicit registration only works
under an institutional anchor set the *peer* can also see. (The leaf EC
itself carries no hints for pairwise, §2.)

**OP side** (B receives the registration) — institutional only (see below),
via `OidcProviderRole` (npm v1.0.0):

```js
const opRole = new OidcProviderRole({
  trustAnchors,         // initialize() throws if empty (verified)
  replayStore,          // { useJti(claim) } Redis-backed (04 §6, §7)
  onRegistration: async (sub, clientMetadata, clientSecret) => {
    /* write FederationPeer row (04 §2) + oidc-provider client. */
  },
})
opRole.initialize({ entityId: `https://${Settings.origin}`, keyProvider, trustAnchors })
// mount: POST <registrationPath> → role.processExplicitRegistration(request)
// response Content-Type is application/explicit-registration-response+jwt
```

**The npm registration classes also enforce the OIDF shared-anchor rule**
(§5.4). `OidcRelyingPartyRole.explicitlyRegister` resolves *both* sides'
chains from **the RP-side anchor set** and requires a chain for both that
ends at a *common* anchor (`selectSharedRegistrationTrustChains`;
verified empirically: with pure pairwise anchor sets — mutual pinning,
self-anchor on each side, any combination — the call fails with
`No shared Trust Anchor between RP and OP`). OIDF 1.0 §5.4 is explicit:
"The RP and OP MUST share a trust anchor." Pure pairwise pinning (A pins
B, B pins A) creates no shared anchor, so:

1. **Pairwise (P0–P2) trust establishment = the per-direction pin**
   (above; 04 §2). No registration statement exists in this mode; the
   v1 plan's `registration_statement_jwt` artifact is **dropped**.
2. **First-use verification** (OIDF §5.1, automatic registration concept):
   at the first auth request from a peer's client, the OP re-discovers the
   peer's leaf and verifies it against the pinned chain — implemented as
   the oidc-provider `verifyClientAssertion` hook (03 §3).
3. **Institutional (P3) wire constraints** (verified npm v1.0.0; the
   flow itself works end-to-end under a shared TA, e.g. the DFN-CERT
   anchor):
     - registration EC is `iss=sub=<RP entity id>`, `aud=<OP entity id>`,
       `authority_hints` **min(1)** (explicit registration is depth ≥ 1 by
       construction — the shared anchor), `metadata.openid_relying_party`
       required.
     - the OP's registration *response* has Content-Type
       `application/explicit-registration-response+jwt` (exact match
       required by the RP) and typ `explicit-registration-response+jwt`;
       result: `ExplicitRegistrationResult { registrationStatement,
       clientId, clientSecret?, expiresAt, registeredMetadata,
       trustChainExpiresAt }`.
     - every non-leaf entity that a chain walks through must expose
       `federation_entity.federation_fetch_endpoint` (subordinate statement
       fetch, OIDF §6.3) — so **serving it is a runtime `@oidfed/authority`
       dependency in institutional mode** (P3), plus the institution
       issuing our subordinate statement.
4. In operational (production) deployments both may be active: TA for
   the institutional tree, peer pins for bilateral overleaf-cep ties.

**Consequences vs v1 plan:**
- No `federate` S2S action. No RFC 9421 anywhere.
- No `fingerprint`/`jwksUri` S2S envelope; the peer's keys arrive
  *inside* the signed Entity Configuration, verified by OIDF.
- The admin approval/pinning screen shows (pairwise): the fetched leaf
  `entityId`, `jwks` thumbprint (TOFU human comparison, 02 §3), and a
  confirm pin button. Institutional mode adds the registration
  statement `client_id` and statement `exp` (04 §2).
- Registration statements carry their own `exp`; expiring registrations
  re-run registration (04 §2, `trustChainExpiresAt` from
  `OidcRelyingPartyRole.explicitlyRegister`).
- In operational (production) deployments both may be active: TA for
  the institutional tree, peer pins for bilateral overleaf-cep ties.

## 5. Key model — TWO key sets per instance (this is the correction to v1)

The v1 plan had "one ES256 key, two consumers (S2S + OIDC)". OIDF 1.0
needs the separation:

| Key | Purpose | Package | Served |
|-----|---------|---------|--------|
| **Federation key** | Signs Entity Configurations (leaf), client assertions, registration statements | `@oidfed/core` `FederationKeyLifecycleProvider` | in leaf `jwks` + (via authority, never here) |
| **OIDC signing key** | Signs id_tokens / tokens for the grant flow | `oidc-provider` v9 keystore (`jwks` config, `05 §8.6`) | at `/federation/oidc/jwks` (oidc-provider default) |

`@oidfed/core`'s `FederationKeyLifecycleProvider`
(verified from `federation-keys.ts`): `getFederationKeySet()`,
`getHistoricalFederationKeys()`, `publishKey()`, `switchActiveKey(kid,
opts)`, `revokeKey(kid, reason)`. The key state machine is
**published → active → retiring → revoked**, and `getHistoricalFederationKeys`
serves retired-but-valid keys from
`GET /federation/federation-keys` (so in-flight verifications of old
statements keep working during rotation).

overleaf-cep must implement this provider **once**, against Mongoose
(durable: the leaf signs with it forever, keys outlive everything else) —
not Redis. Persistence shape: `{ kid, key (PKCS8), public (JWK),
state, publishedAt, retiredAt? }`. In v1 the admin has three buttons
(publish / switch active / revoke) + an auto "old key still retired"
sweep; automation is 07.

Rotation procedure (same for both key sets; the OIDC side is v9 standard
keystore behaviour with kid duality, `05 §8.6`):

1. `publishKey()` → new key **published** (public halves served, both
   verified).
2. `switchActiveKey(newKid)` → new **active**, old **retiring** (signature
   stops, verification continues for `clockTolerance` + statement TTLs).
3. After the grace window (default: leaf TTL + active statements' `exp`,
   e.g. 14 days), old key **revoked** — removed from historical set after
   its last accepted statement expires.

**Clock tolerance**: `@oidfed` verification allows 60 s skew
(`FederationOptions.clockSkewSeconds`); oidc-provider allows 15 s. The
leaves use different keys, so both are live at once during rotation —
this is why "old key retiring" must not remove the JWK from the leaf
before *all* in-flight verifications of old statements are impossible.

## 6. Where the institutional path lands (DFN-AAI / eduGAIN)

Facts (researched 2025-10, verified in the eduGAIN OIDF pilot repo
`GEANT/edugain-oidf-pilot` and DFN forum):

| Element | URL / fact |
|---------|-----------|
| eduGAIN OIDF pilot TA | `https://ta.oidf-pilot.edugain.org` (LightHouse) |
| Pilot IAs | `https://ia1.oidf-pilot.edugain.org`, `https://ia2.oidf-pilot.edugain.org` |
| Pilot RP | `https://rp1.oidf-pilot.edugain.org` (OFFA-based, subordinate to IA1) |
| DFN-AAI | edufederation OIDC-FED pilot active since 2025-06-30 (12 months); DFN-CERT implemented the first trust anchor; DFN-AAI is *the* German access environment these instances will sit in |
| Leaf URI | `<entity-id>/.well-known/openid-federation` (IANA-registered) |

Integration sequence when a German site wants DFN-AAI federation
(07 adds a pilot-test phase before production):

1. The institution's TA enrols overleaf-cep's entity at
   `ia1.oidf-pilot.edugain.org` (or the production DFN-CERT TA).
2. overleaf-cep's leaf gains `authority_hints: [<institution TA>]`
   (a *data* change: the leaf is re-signed, no code change), and its
   anchors map gains the institutional chain above the leaf key.
3. `discoverEntity` + `OidcRelyingPartyRole.explicitlyRegister` are
   **unchanged**; the chain just gets longer.

What does **not** change at institutional scale: the grant flow
(`01 §5`), the per-admin claim consent on B (04 §8 — claim policy is
*not* an OIDF concept here; `@oidfed` has no claim-policy enforcement,
confirmed in source), the rate limits (03 §6), or the admin approval
granularity (per-direction, per-machine).

## 7. Replay and dedup — `ReplayStore`

`@oidfed/core` provides `ReplayStore` for statement-level replay
protection (jti + `iat`/`nbf` semantics). overleaf-cep uses it in two
places:

- **Trust establishment**: registration statements and any authority
  statement accepted during a `trustAnchors` fetch are jti-deduplicated
  (authority statements are *not* served by overleaf-cep in v1; trust
  establishment is leaf + explicit registration only).
- **Runtime S2S** (03 §3): every client assertion `jti` is deduplicated
  through the same store before the action is applied.

Storage: Redis, `federation:replay:<jti>` TTL = statement `exp` window
(the store is keyed by statement lifetime, not clock). `04 §6` lists the
keys.

## 8. Grounding appendix (verified against npm v1.0.0, 2026-09-17)

All API names were verified against **the npm v1.0.0 tarballs** of
`@oidfed/core`, `@oidfed/oidc`, `@oidfed/leaf` (installed under
`/tmp/oidfed-npm-check`), not against the git checkout at
`~/federation/oidfed`. The git source is a superset; the *index
exports* do not match on `leaf`/`authority` (there is no npm
`@oidfed/authority` in v1; it was split into `federation-keys.ts`
and `trust-chain/*`).

Key corrections vs v0 plan:

- `@oidfed/leaf` npm **exports only `Leaf`** — the v0 plan's
  `createLeafHandler` is a *source* function in
  `packages/leaf/src/handler.ts` but not in the npm index.
- `@oidfed/oidc` npm exports the **role classes**
  (`OidcRelyingPartyRole`, `OidcProviderRole`) and *not* the free
  functions `explicitRegistration` / `createExplicitRegistrationHandler`
  (also source-only).
- The v0 plan's "free-function" API surface for trust establishment is
  **not reproducible from npm 1.0.0**; the class-based API is.
- `verifyEntityStatement`, `createTrustAnchorSet`, `discoverEntity`
  (as exported by `@oidfed/core`) are verified.
- `federation-registration-response +jwt` (Content-Type) and
  `explicit-registration-response+jwt` (typ) are exact-match (the
  `isExactContentType` helper in the build rejects non-exact matches).
- The leaf's EC wire **shape**: `iss == sub == own entity id`,
  `authority_hints` absent for pairwise (depth-1).
- The registration request (RP → OP) has `authority_hints: min(1)` —
  for explicit registration the TA/anchor is *required* in the claim;
  this is what "depth ≥ 1 by construction" means and is why pairwise
  does *not* produce a registration EC.
- **Trust-anchor pinning** (04 §2) is the primary v1 mechanism;
  `explicitlyRegister` is the institutional path and is covered by
  the v0 wire tests.
- `verifyClientAssertion` (not `verifyClientAssertionSync` — v0 was
  wrong about the name) is the client-assertion verifier; it takes
  `(assertion, jwks, expectedAudience, opts)` (opts: `clock?`,
  `clockSkewSeconds?`, `replayStore?`? no, replay is handled *by the
  caller* via `ReplayStore.useJti`, not a parameter on
  `verifyClientAssertion`).

**`validateTrustChain` is async** returning
`{ valid, chain?, errors? }` — the v0 "sync chain" claim is corrected
(references elsewhere use the async shape).

**Institutional (P3) note**: the authority (TA+IA) role is **not**
deployed in overleaf-cep v1; see §6 for when it *would* be (self-hosted
test TA + pilot enrolment). In institutional mode overleaf-cep sits
*under* a TA; it does not *be* a TA.
