# overleaf-cep identity federation — overview

Status: **v2 plan** (OIDF 1.0 trust layer). Supersedes the v1 custom-TOFU plan.
The 4 former files were restructured into 8; a pre-restructure snapshot lives
in `superseded-ocm-share-transfer/` (old content-federation plan, archived) and
the git history holds the v1 plan in full (commit `27e3eb3`).

## What this is

Federation for overleaf-cep so that **a user of machine B can open and edit a
project that lives on machine A, on machine A, under B's own account**, after
B's identity is vouched to A.

- **Identity federation, not content federation.** Nothing besides
  authentication material (OIDC id_token with a fixed allow-list of profile
  claims) crosses a machine boundary. The user edits on **the machine where
  the project lives** — on A, using A's editor stack, A's linked-URL proxy,
  A's git settings, A's session. There is no content stream, no sync, no
  remote-proxy.
- **overleaf-cep ↔ overleaf-cep** interop. Nextcloud (v36) is a *reference*
  for the model, not a wire-compatibility goal.
- **Identity anchor is a tuple** `(origin, localName)` where `origin` is the
  **home server's FQDN** (not a mail domain) and `localName` is the home
  server's login name (email local-part convention). Display form
  `user@uni.de:uni-overleaf.de` is a human-readable serialization of the
  tuple **only**; the wire uses two separate claims, and storage uses two
  separate fields (see 04 §1).
- **Trust layer: OIDF 1.0** (OpenID Federation, Final 2026-02-17), built with
  the reference `@oidfed/*` packages. Pairwise bootstrap (depth-1 trust
  chain, one admin approval per direction) and institutional scale-out
  (DFN-AAI / eduGAIN trust anchors) are **the same code path** — see
  `02-trust-model-oidf.md`.
- **Runtime S2S** (invite approval, preview, revocation) is a small signed
  surface over HTTPS using OIDF **client assertions**
  (`OidcRelyingPartyRole.createClientAssertion` static, `@oidfed/oidc`
  v1.0.0), with replay protection from `@oidfed/core`'s `ReplayStore`
  (we implement the `JtiReplayClaim` interface over Redis; `03 §2`/§3).
- **OIDC IdP engine: `oidc-provider` v9.12.2** (unchanged from v1 plan;
  verified against source 2026-09-17, see `05 §8`). The overleaf-cep
  enterprise-SSO OIDC *client* module (`passport-openidconnect`) is **not**
  reused for grants.

## The 8 files

| File | Contents |
|------|----------|
| `00-overview.md` | This file: architecture, file map, decisions |
| `01-identity-federation-protocol.md` | Identity model, grant flow, wire conventions, S2S overview |
| `02-trust-model-oidf.md` | OIDF 1.0 trust: entity statements, pairwise depth-1, DFN-AAI path, key lifecycle, rotation |
| `03-s2s-wire-protocol.md` | Runtime S2S: client assertion, actions, rates, revocation |
| `04-data-model.md` | User/peer/models, storage, indexes, claim policies, audit |
| `05-cep-integration.md` | Module shape, oidc-provider wiring (verified v9.12.2), mounts, Settings |
| `06-security.md` | Threat model, link-disjointness proof, deny-list, redaction |
| `07-roadmap-and-testing.md` | Phases, Docker matrix, NC reference, test infrastructure |

## Architecture at a glance

```
  Machine A (RP side)                                  Machine B (home OP)
  ───────────────────────                               ─────────────────────
  User.federation {origin, localName} mirror row  ←──── oidc-provider grant
  ProjectInvite.federated (origin, localName,        id_token: (origin=home B,
    privileges)                                        localName=home login, ...)
  client assertion S2S (authorize-invite,             interaction bridge on
    invited, revoke) ──────────────────────────────→  top of overleaf B login
  trust anchors (pairwise TA or DFN-AAI)   ◄─────────► /.well-known/openid-federation
                                                       entity configuration (leaf)
```

Both machines run the **same overleaf-cep build**. Roles (RP, home OP) are
per-flow, not per-instance: for project P that lives on A, B is the home OP
and A the RP. Users of B can also own projects that, conversely, make A the
home OP for a mirrored account on B.

## Decisions locked in this revision

1. **Anchor = tuple `(origin, localName)`** (was a single colon string).
   Colon is a display separator; wire and storage are 2-field.
   `:` still forbidden in `localName` — now only because of the display
   ambiguity (04 §1).
2. **Mirror row is a link, not a species.** `User.federation` is a
   subdocument `{ origin, localName, federatedAt }`; its *presence* is the
   discriminator (same pattern as `thirdPartyIdentifiers` for SSO, same
   "password gets cleared once federated" precedent as SAML/LDAP/SSO —
   04 §1.1). Mirror rows are **full** local users (settings, projects,
   editor stack). No `kind` field.
3. **Local-vs-federated collision is dead by construction.** SSO lookups
   query `email`/`thirdPartyIdentifiers`/`samlIdentifiers` and can never hit
   a mirror row; federated lookups query `federation.origin` +
   `federation.localName` and can never hit a local/SSO row. The two
   identity systems coexist on the same Mongo collection with **no** unique
   index (04 §1.2).
4. **OIDF 1.0 trust replaces the custom RFC 9421 `federate` handshake.**
   Trust establishment is the **per-direction admin pin** (pairwise) or
   the OIDF explicit-registration flow (institutional, P3); the admin
   decision is the same one click ("trust this entity" / approve
   pending). Pairwise depth-1 (admin pins the peer's entity key as a
   Trust Anchor) and institutional (DFN-AAI) share the same leaf code
   path; explicit registration is institutional-only (npm `OidcRelyingPartyRole
   .explicitlyRegister` enforces a shared anchor, 02 §4).
5. **One admin approves trust; each side approves its own direction.**
   No cross-direction implication. "The admin decides what happens on THEIR
   machine."
6. **`@oidfed/*` is the trust dependency**; `oidc-provider` remains the
   OIDC engine. No new OIDC *client* library: grants use public client +
   PKCE, and A verifies id_tokens with the existing top-level `jose`.
7. **S2S actions survive, RFC 9421 does not.** Runtime S2S is client
   assertion (03 §2).
8. **Claim allow-list stays local** (per-admin policy; 06 §4 deny-list and 05 §8.5 claim flow); `@oidfed`
   does not enforce claim policy, and neither should the trust layer
   (admin decides).
9. **No refresh tokens** in v1: `scope=openid`, public client, PKCE;
   re-login re-mints, no re-consent (01 §5).
10. **No NC interop goal** (unchanged, 07 NC reference).

## What is explicitly NOT in scope

- Content/stream federation of projects or files (old 4-file plan —
  superseded, archived).
- Machine-readable trust policy, claim policies, or `claim_policies`
  anywhere: claim sharing is per-admin local policy (06 §5).
- KMS-backed key storage in v1 (PEM file + env; v2 open question, 07 Open items).
- Automatic configuration assistance (git/zotero/compile) — v2 (07 Open items).

## Reading order

New: 01 → 02 → 03 → 04 → 06. Then 05 (implementation) and 07 (delivery).
`05 §8` remains the authoritative grounding for oidc-provider v9.12.2;
`02 §8–§9` is the grounding for the `@oidfed/*` integration.
