# overleaf-cep Federation — Roadmap, Testing, NC Reference (v2)

Identity federation (no content transfer). Trust layer = OIDF 1.0 via
`@oidfed/*` (OIDC WG Final, 2026-02-17). Phases are *buildable slices*,
each independently testable in the two-container Docker matrix (§Docker
matrix), no external peer required.

## Phase structure (each phase = a mergeable branch)

### P0 — Trust bootstrap (OIDF leaf + key-material + OIDC-provider mount)

Deliverables:
- `services/web/modules/federation/index.mjs` skeleton
  (WebModule contract, `appMiddleware`, `start`; §05 §1/§1.1).
- `oidf/keystore.mjs` — `FederationKeyProvider` interface implementation
  over Mongoose (`FederationKey` collection: `activeKid` + full private
  JWKs for rotation, 02 §5); bootstrap ES256 key pair on first boot
  (auto-generate if no active key, persist; no PEM file keystore in v1).
  NOTE: `FederationKeyLifecycleProvider` (the publish/switch/revoke
  state machine) is a v1-simplification target — the npm interface
  `FederationKeyLifecycleProvider` exists in `@oidfed/core` d.ts,
  verified; the Mongoose impl of the lifecycle half is deferred to P2
  admin key-rotation, P0 ships `getFederationKeySet()` only.
- `oidf/leaf.mjs` + mount: `@oidfed/leaf` handler at
  `GET /.well-known/openid-federation`, entity types
  `openid_provider` + `openid_relying_party` (02 §2).
- `oidf/verify.mjs` — client-assertion verification + `ReplayStore`
  (03 §2–§3); `federation:replay:<jti>` Redis key.
- oidc-provider v9 mount on B: `createProvider.mjs` (§05 §8.6) +
  `RedisOidcProviderAdapter` (7-method factory, §05 §8.2, 04 §5) +
  `clients.mjs` approved-peer reconstruction (§05 §8.8) + bridge GET + POST
  (§05 §8.3) — **no** OIDC *client* library (that's the A-side and only in
  P1; P0 is B-only until the grant round-trips).
- **Test gate:** Docker matrix (§Docker matrix): leaf fetch + verify
  (sign → verify, round-trip over loopback), JWKS kid mismatch →
  refetch, `ReplayStore` dedup, oidc-provider discovery
  `/federation/oidc/.well-known/openid-configuration` +
  `auth`/`token`/`jwks` all respond.

### P1 — Registration (pairwise depth-1) + grant round-trip

Deliverables:
- `oidf/anchors.mjs` — trust-anchor set: pairwise (per-peer
  `FederationPeer.anchorJwks`, 04 §2) + institutional file
  (`Settings.federationInstitutionalAnchorPath`, 02 §6). Pairwise
  establishment is the **admin pin** (02 §4, 04 §2); no registration.
- `oidf/registration.mjs` — institutional-only path (P3): mounts
  `OidcProviderRole`'s `processExplicitRegistration` (02 §4), writes
  `FederationPeer` `pending` row (04 §2.1); admin approval via existing
  AdminController (P2 wires it). P1 ships it as a stub gated behind
  `Settings.federationInstitutionalMode`.
- `ClientAssertionClient` (A-side, for S2S `authorize-invite`/`invited`/
  `revoke`, 03 §4): **not** a dep, a ≤50-line wrapper over
  `OidcRelyingPartyRole.createClientAssertion` (static) + `fetch` +
  `verifyClientAssertion` for inbound.
- `rp/CodeExchange.mjs` (§05 §3.2) + `CallbackRouter` (§05 §3.3).
- `invite/FederatedInviteRouter` minimal:
  `GET /api/federation/invite/preview` (invited-only, read) +
  `POST /api/federation/invite/authorize` (the invitee-side approval).
- **Test gate:** two-container matrix (container A + container B),
  both auto-generate ES256 keys on boot, **no** network beyond
  loopback:
  1. A admin pins B (pairwise: paste B's leaf + jwks into
     `Settings.federationPeers[]` admin UI, or curl B's leaf over
     loopback).
  2. `GET https://<B>/.well-known/openid-federation` against A's pinned
     set: signature check + issuer/entity-id match (depth-1 self-signed;
     the *code path* is identical to institutional).
  3. Pin writes `clients[]` to B's oidc-provider (client doc derived
     from the leaf's `openid_relying_party` metadata, not from a
     registration statement; B's `clients.mjs` picks it up on next boot
     — for the test, restart B).
  4. A: owner `O` creates federated invite for
     `alice@b.example.local` (B's user, seeded).
  5. Alice visits `O`'s "open on B" URL → PKCE flow → A's
     `/federation/oidc/rp/callback` → mirror row created → 302 to
     project URL → session cookie set.
  6. **Replay test:** replay `authorize-invite` with same `jti` → 403
     (not "already approved").
  7. **Revoke test:** admin revokes B → next `authorize-invite` → 401
     `revoke`.

### P2 — Admin UI + claim allow-list + rate-limit

- Admin "Federation" tab (peer list, approve/deny/rotate/revoke, 04
  §2 + §05 §8.8).
- `Settings` additions (§05 §7): `federation.enabled`,
  `federation.allowFederatedProjectCreate` (default off), etc.
- Claim allow-list per peer (04 §4, 05 §8.5):
  `displayName`, `language`, `avatarUrl` + **optional** per-peer allow
  extra: `institution` (opt-in). `origin` + `localName` always.
- Rate-limiting (03 §5): budgets on *receiving* instance (not
  sender-side, not NC), in Redis; `429` + `Allow-Retry` header.
- **Test gate:** admin approval flow → grants work; claim
  allow-list enforced by oidc-provider `claims` config (not a
  runtime filter); rate-limit on `authorize-invite`/`invited`
  per §03 §5.

### P3 — Institutional (DFN-AAI) path + multi-peer + performance

- Institutional anchor support (02 §6): admin pastes TA JWKS +
  `authority_hints` in the leaf; **no code path change** for pairwise →
  institutional (depth-1 and depth-N are the same
  `discoverEntity` call, 02 §3).
- Multi-peer: N approved peers, grants fan-out, per-peer claim
  allow-lists coexist.
- Performance: leaf + JWKS fetch caching (02 §5 rotation grace),
  grant exchange < 300 ms cold (one JWKS fetch + sign + verify).
- **Docker matrix:** §Docker matrix (below).

### P4 (optional / post-v1)

- **S2S `revoke`** (trust revocation, 03 §4.3) — not in v1 (admin UI
  revokes locally; the S2S `revoke` is an *optional* notification to
  peers; default off).
- **OIDC RefreshToken** (re-login after 30-day grant expiry) — not in
  v1: re-login re-mints (silent consent, §01 §5 step 9).
- **Content-share federation** (if overleaf-cep ever supports it) —
  a separate plan, out of scope.

## Docker matrix (test infrastructure)

Three containers, all **loopback only** (no external network):

| Container | Role | Seeded state |
|-----------|------|--------------|
| `A` | overleaf-cep (federated, partner) | 1 local user `O` (owner), 1 federated invite pending |
| `B` | overleaf-cep (federated, home/OP) | 1 local user `alice` (federated identity) |
| `B-alt` | overleaf-cep (federated, home/OP) | 1 local user `bob` (institutional test) |

Scenarios (all in P1–P3, no real network, loopback):
- **A↔B pairwise:** A registers at B (pairwise depth-1, admin pins
  B's key as TA), grant O → B/alice, mirror row on A, session.
- **A↔B-alt institutional** (P3): B-alt's leaf has
  `authority_hints`, A pins a TA file (e.g. DFN-CERT test anchor,
  **not** the live eduGAIN anchor — test env), grant O → B-alt/bob.
  **Same code path**, different config (02 §3, 02 §6).
- **Replay:** duplicate `authorize-invite` `jti` → `replay` error
  (both containers' `federation:replay:<jti>` key hit).
- **Revoke:** B admin revokes → next invite from A/B pair rejects.
- **Key rotation (02 §5):** B rotates federation key
  (published→active→retiring→retired); A refetches leaf on kid
  mismatch (1 h TTL, 04 §6), re-verify old statements with
  historical keys (leaf's `jwks` during retire window, 02 §5).
- **Claim allow-list (P2):** per-peer allow-list enforced via
  oidc-provider `claims` config (04 §4, 05 §8.5); `displayName`
  always, `institution` opt-in per peer.
- **Rate-limit (§03 §5):** budgets on receiving side, 429 +
  `Allow-Retry` on exceed.

**No third "authority" container:** pairwise depth-1 is
peer-owns-own-trust-anchor; institutional is a config (TA file), not a
live dependency. The matrix runs in CI on loopback; no mock OIDF
authority required. (If a live authority is wanted, that's a *separate*
integration test, not part of the CI matrix.)

## NC reference (what we actually use)

Nextcloud v36 (the reference codebase the operator pointed at) is a
**behavioural** model, not a wire model. What we take:
- **Pairwise bootstrap flow** (admin paste, TOFU fingerprint
  display, explicit "register" action) — the *UX* for admin-driven
  key pinning; not the wire (NC uses RFC 9421 + OCM for
  content-sharing federation; we use OIDF + client-assertions).
- **Rate-limit budgets** (5/1200 s for background sync) — the
  *model* for receiving-side budgets (we apply them to
  `authorize-invite`/`invited`/`revoke`, 03 §5).
- **JWKS model** (per-peer JWKS doc, kid mismatch → refetch,
  1 h cache) — the *shape*; ours is OIDF leaf's `jwks` field (02 §2) +
  oidc-provider's OIDC-signing JWKS (05 §8.6), not NC's OCM JWKS.
- **Not taken:** RFC 9421 canonicalization (superseded by OIDF
  client assertion, 03 §2), OCM (out of scope), `federate` S2S
  handshake (superseded by OIDF explicit registration, 02 §4).

NC's wire is **not** a goal (00 §10 "no NC interop", retained).

## Test infrastructure

- **Unit:** `FederationKeyLifecycleProvider` state machine
  (published→active→retiring→revoked, historical keys served,
  `jwks` during retire window); `ReplayStore` dedup (same `jti`
  → second call fails); client-assertion verify (sig, `aud`,
  `jti`, clock-skew); `OidcRelyingPartyRole.createClientAssertion`
  (static) → `verifyClientAssertion` round-trip.
- **Integration (two-container, Docker matrix above):** leaf fetch +
  verify, registration approval → clients[] → grant round-trip,
  revoke, rate-limit, claim allow-list.
- **End-to-end (Docker + a third "browser" role in a small
  no-UI client):** the OAuth redirect itself (A's browser, B's
  oidc-provider, back to A's callback) with the mirror row +
  session cookie, the **entire** grant flow in CI.
- **Performance:** grant exchange cold < 300 ms (one JWKS fetch);
  warm (1 h cache) < 50 ms.
- **What we do *not* test (out of scope):** live eduGAIN/DFN-AAI
  network (no third container), NC interop (not a goal),
  content federation (no content transfer in this plan).

## Deliverables summary (per phase)

| Phase | Files (new) | Deps | Test gate |
|-------|-------------|------|-----------|
| P0 | federation module skeleton, `leaf.mjs`, `keystore.mjs`, `verify.mjs`, `oidc/createProvider.mjs`, `oidc/RedisOidcProviderAdapter.mjs`, `oidc/clients.mjs`, `oidc/bridge.mjs` | `oidc-provider@v9`, `@oidfed/core`, `@oidfed/leaf` | leaf round-trip, kid mismatch, ReplayStore, oidc discovery |
| P1 | `anchors.mjs`, `registration.mjs`, `ClientAssertionClient` (≤50 lines), `rp/CodeExchange.mjs`, `rp/CallbackRouter.mjs`, `invite/*Router.mjs` | + `@oidfed/oidc` | two-container grant round-trip, replay, revoke |
| P2 | Admin UI, `Settings` additions, claim allow-list, rate-limit | — | approval flow, claim enforcement, 429 |
| P3 | Institutional (02 §6), multi-peer, performance | — | B-alt institutional scenario, multi-peer fan-out |

## Open items (explicit, not "v2")

None. The v1 "v2 OIDF bootstrap" open item is **closed** by P0–P1
(OIDF leaf + pairwise registration). The institutional path (P3)
is a *deploy config* (TA file + `authority_hints`), not a separate
bootstrap mechanism (02 §6); it is testable in CI via the
loopback institutional scenario. The S2S `revoke` (P4, optional)
is a v2 scope decision, not a v1 blocker.
