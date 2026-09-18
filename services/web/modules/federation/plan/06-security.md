# Security — threat model, identity disjointness, deny-list, redaction

This file consolidates the security properties scattered across
`01 §8`, `02`, `03`, `04` and pins them to verified code paths. Where this
file and any other file disagree, **this file wins** for the *security*
claim and the other file must be corrected.

## 1. Threat model

Actors:
- **Local admin** — controls one machine only ("the admin decides what
  happens on THEIR machine", not over-cross).
- **Visitor (attacker browser)** — full control of one machine's browser,
  no control of the wire.
- **Wire (MITM)** — TLS public-CA boundary only (no mTLS, no key pinning;
  `03 §8`). Any certificate a public CA would sign is admissible; what
  keeps an attacker out of the trust layer is therefore **the OIDF
  verification**, not the transport.
- **Malicious peer** — runs a fully compromised overleaf-cep build, owns
  a genuine entity and its own real federated users, and wants to get a
  *second, attacker-chosen* identity accepted on a victim machine.
- **Stale state** — keys, registrations, and revocations that lag the
  world after rotation / revocation / rename events.

Claims the design must hold under all five:
1. No session is minted for a non-existent home identity.
2. No session is minted for an identity the home machine does not
   presently vouch for (revoked, disabled, renamed).
3. No grant secret survives its single use (codes, id_tokens).
4. No cross-instance data beyond the allow-list (04 §4 deny-list).
5. No cross-admin power: an admin on X cannot change, read, or mint
   anything on Y beyond what Y's admin allowed.

## 2. How each layer holds

| Layer | Mechanism | Grounding |
|-------|-----------|-----------|
| Trust | OIDF 1.0 entity configuration + trust-chain verification; pairwise depth-1 TA pin; institutional chains via anchors | `02 §3–§4`, `02 §8` |
| Trust establishment | Pin (pairwise, locally per direction) / explicit registration (institutional, P3); `onRegistration` = overleaf-cep admin hook | `02 §4`, `05` |
| Runtime S2S | Client assertion (JWT, ES256, `jti`-deduped) over HTTPS | 03 |
| Identity | `id_token` claim pair `(origin, localName)`; `sub` is B-local only, **never** the anchor | `01 §5`, `05 §8.5` |
| Session | The grant is an *opener*: after one id_token verification the partner runs a **normal** overleaf session; nothing about the "federated" state is re-verified per request | `01 §5` |
| Key lifecycle | Federation key (leaf, assertions) vs OIDC signing key (id_token) — separate rotation, historical keys served | `02 §5` |
| Replay | `jti` dedup (`ReplayStore`), 60 s clock tolerance | `02 §7`, 03 §3 |

**The single most important property** (unchanged from v1 and worth
re-proving per release): the grant is a secret, single-use, 120 s,
no-store. `oidc-provider` enforces `ttl.AuthorizationCode`,
`Cache-Control: no-store`, and code single-use via its adapter
`consume(id)` (`05 §8.2`); no plan file may loosen this.

## 3. Identity: link-disjointness (proof, not convention)

The overleaf-cep `User` collection is shared by three identity systems:
**local** (password/email), **SSO** (OIDC enterprise-SSO + SAML + LDAP via
`thirdPartyIdentifiers`/`samlIdentifiers`), and **federated mirror**
(`User.federation` link, 04 §1). The claim "a federated mirror can never
be treated as a local or SSO user, and vice versa" is what keeps the
whole plan safe from account-attachment. It is **by construction**:

Lookups (verified against `services/web/app/src/` and
`services/web/modules/authentication/{oidc,saml,ldap}/`):

| System | Query (verified) | Can it hit a mirror row? | Can it hit a local/SSO row? |
|--------|------------------|--------------------------|-----------------------------|
| Local login | `User.findOne({ email })` | No: mirror `email: ''` and is never passed a non-empty email by signup (mirror creation does **not** go through `SignUpController`) | Yes |
| SSO OIDC | `ThirdPartyIdentityManager.findOne({'thirdPartyIdentifiers.providerId': x, 'thirdPartyIdentifiers.externalUserId': y})` (L233) | No: mirror rows have no `thirdPartyIdentifiers` | Yes |
| SSO SAML | same shape + `samlIdentifiers` | No: mirror rows have no `samlIdentifiers` | Yes |
| SSO LDAP | email-first `User.findOne({ email: ldapAttribute })` | No: mirror `email: ''` never matches an LDAP attribute (and LDAP mapping is admin-configured, never returns `''`) | Yes |
| **Federated** | `User.findOne({ 'federation.origin': X, 'federation.localName': Y })` (04 §1) | Yes | **No:** mirror-row creation is the *only* writer of `User.federation`, and no local/SSO path ever sets it |

- **No unique index** on `email` exists (verified: `User.mjs` has none),
  so multiple `email: ''` mirror rows cannot collide with each other
  either. The federation pair is the *only* thing that makes the mirror
  identity unique, and it is two-field (04 §1).
- `hashedPassword` is **undefined** on mirror rows — a *consequence* of
  "mirror has no local credential", not a mark. SAML already does this
  proactively (`SAMLAuthenticationManager.mjs` L78: `$unset: { hashedPassword: "" }`);
  the federated link follows the same precedent. The `:`-in-email
  forbiddance is now *only* about display ambiguity (01 §3.3), not about
  the anchor being a single string.
- **Rename on B**: `localName` is admin-editable on B (it is the B-side
  login name). It is **not** mirrored anywhere on A except the audit
  row and the invite display. A re-binds the pair `(origin, localName)`
  from the **id_token** at every grant; a rename on B makes the next
  grant resolve to a *new* mirror row (old row frozen), or to the same
  row if B admin re-points the login. Neither is silent: both cases
  write an audit row (`federation_identity_rebound`, 04 §8).
- **Account-attachment**: because no SSO lookup path can reach a mirror,
  an attacker cannot "log into" a mirror row with a password or an SSO
  IdP assertion. The mirror is reachable **only** through a B-origin
  id_token whose claim pair matches `federation.*`.

## 4. Deny-list — what NEVER crosses an instance boundary

Absolute (this is the "not over-cross" invariant; no trust anchor, no
TA, no institutional federation may override it):

| Never leaves | Where it lives |
|--------------|----------------|
| `User.hashedPassword`, `User.loginEpoch` | home |
| billing: `subscriptionId`, plan, invoices | home |
| git-sync config (remote, credentials) | home `git-bridge` module |
| Zotero credentials | home `zotero` module |
| compile settings (LaTeX, fonts, binaries) | home, per-project |
| Project content bytes (`Doc`, `File`, `ProjectFileMetadata`) | owner instance |
| session secrets, `sessionSecrets`, any signing *private* key | env / KMS (v2) |
| any other `User` field not in the claim allow-list (04 §8) | home |

The *only* things that cross a wire:
1. OIDF entity configurations (public metadata, signed) — `02 §2`.
2. Registration statements (public metadata + client metadata, signed) —
   `02 §4`.
3. S2S actions + their small payloads (invite metadata, read-only
   profile fields, revocation notices) — 03.
4. OIDC code + id_token (grant secrets, short-lived) — `01 §5`.

Claim allow-list (B→A, per-admin B policy, `04 §8`): `sub` (B-local,
never the anchor), `origin`, `localName`, `displayName`, and optionally
`language`, `institution`, `avatarUrl`. **No** email, **no**
profile-URL, **no** address, **no** phone. (overleaf-cep has no
phone/address fields anyway; the enumeration is a defense-in-depth
reminder.)

## 5. Claim policy is local, trust anchors are claim-blind

Confirmed in `@oidfed` source (2026-09-17): **there is no
`claim_policies` and no `RESERVED_CLAIMS` and no metadata-policy claim
enforcement.** The TA chain vouches *identity and key presence*, never
claims. The per-B claim allow-list (04 §4) is therefore not an OIDF
concept and no OIDF artifact may define, carry, or override it. If a
future OIDF draft adds claim policies, this file's §4 deny-list takes
precedence until re-reviewed.

## 6. Redaction — the exact points (unchanged from v1, re-listed)

Structured log + audit must never contain:
- `code=<OIDC code>` in any URL query / body (`01 §8.1`).
- `id_token` in any artifact (token endpoint response is written to log
  as `id_token: [REDACTED]`).
- Client **assertion** *values* — the S2S audit row holds `{iss, aud,
  jti-hash}` (hashed, 32 hex); the body's `payload` is logged only for
  *approved* actions, and only the fields in the allow-list.
- The federation *private* key PEM path contents — never logged
  (02 §5: PEM file + env override in v1).
- Invite tokens (`encryptedToken`) — unchanged overleaf-cep behaviour.

Enforcement points (from `05`): the structured-logger filter
(`modules/federation/util/Redact.mjs`), the oidc-provider token-
*endpoint* response (oidc-provider logs at `debug`, the module sets it
to `info`+), and the S2S router (assertion → `{iss, aud, jti-hash}`).
A test in 07 greps a 24 h load and asserts redaction (P3 acceptance).

## 7. Key model threat surface

| Key | If lost/leaked | Consequence | Mitigation |
|-----|----------------|-------------|-----------|
| Federation **federation** key (private) | Attacker signs leaf/assertions as this origin | Peers accept attacker statements as if this origin signed | Per-peer revocation (3), re-issue (02 §5 rotation); institutional TA can suspend this entity at the anchor |
| OIDC **openid** signing key (B-side) | Attacker mints id_tokens for B users | A accepts forged identities from B | `kid` mismatch → JWKS refetch on kid mismatch (1 h cache, `04 §6`); the leaf's `jwks` does NOT contain the id_token key, so a leaf-trusted attacker cannot sign id_tokens without also owning B's OIDC key (separate rotation, 02 §5) |
| Peer's **federation** key on this machine (stored anchor) | N/A (public key) | None — anchors are public JWKs; pinning is the admin decision (02 §3) | Admin UI shows the thumbprint and the source (fetched over TLS / pasted from a human); TOFU comparison aid from `anchor-keys.ts` (02 §3) |
| Session cookie on a partner (A) | Session hijack | Normal overleaf session risk (not federation-specific) | overleaf-cep's existing cookie/CSRF posture (no change) |
| The **leaf** JWKS (public) | N/A | None | — |

**The federation and OIDC keys must not share a rotation cycle.**
Sharing a key pair for both roles (v1's "one key, two consumers")
remains a *bug*, not a design: a leaked federation key (needed only
to sign public metadata) would then also verify id_tokens.

## 8. Revocation is local and immediate (per machine)

Per receiver:
- `FederationPeer.status = 'revoked'` → S2S from that origin = 401
  (assertion check fails on the peer-lookup, before verify),
- oidc-provider `findClient` for that peer's client id returns
  undefined → grant minting refused,
- mirror rows are **kept**, flagged (revocation does not delete
  home-origin data on the partner side; re-`federate` re-approves),
- outstanding codes are *not* invalidated by default (they are single-use
  and 120 s; the `revoke` action's optional "kill codes now" flag
  (04 §5) covers the hostile case, default off).
- Existing *sessions* on the receiver are **not** killed (v1):
  revocation affects *new* grants, not already-open sessions. (This is
  the deliberate "not over-cross" choice: A's admin does not get to
  log out B's users on A without B's own admin's knowledge.)

Revocation of a *trust anchor* (institutional case) is out of scope for
v1: the anchor's key is simply retired from `trustAnchors`, and any
chain that depends on it stops validating (OIDF behaviour, no
overleaf-cep action required).
