# Federation WebModule

Pairwise **OIDF 1.0 (OpenID Federation, Final 2026-02-17)** identity federation for
a fork of Overleaf / CEPP (`web` service). A user on instance **A** can be invited
to a project that lives on instance **B**: A performs an OIDC **relying-party**
flow against B's **provider**, obtains a mirror account, and the two instances
exchange authenticated **S2S** calls under OIDF client-assertion transport.

> **Scope (v1): identity federation only.** No content/stream federation, no
> document sync, no cross-instance project storage. The unit of trust is the *user
> identity*; the unit of data is the *project invite* and the resulting mirror
> account.

This is a **WebModule** (not a separate microservice): it mounts on `web`'s router
during module load and shares the web process's DB, Redis, and settings.

---

## Trust model (depth-1 → institutional)

- **Pairwise bootstrap (v1 default):** each instance has one leaf OIDF key. When an
  admin pins a peer (`POST /admin/federation/peers`), the peer's *leaf* entity
  configuration is fetched over HTTPS, schema-validated, and its **active** self-key
  is stored as `anchorJwks`. Runtime S2S verification is **depth-1** — the peer's
  assertion is verified against that pinned key. No chain walking at runtime.
- **Institutional (P3, implemented):** if the leaf EC carries `authority_hints`,
  pin-time resolution walks the OIDF chain up to a **configured institutional
  Trust Anchor** via `@oidfed/core`'s `discoverEntity`. Admins pin TAs in advance
  (`POST /admin/federation/trust-anchors`). A hinted leaf with **no** configured TA
  is refused (`institutional-anchor-missing`).
- **Key rotation:** a peer's `anchorJwks` may hold multiple keys; at runtime the
  assertion header `kid` selects the key, so rotation works without re-pinning.

Runtime S2S / outbound timeouts are **hardcoded constants**, not config-driven
(JWKS 5s, S2S 10s, token 30s — see `oidf/`, `rp/`, `admin/`).

---

## Folder map

| Folder | Purpose |
|---|---|
| [`oidf/`](./oidf/) | Leaf OIDF configuration, S2S client-assertion verification, keystore/key rotation, trust-anchor helpers |
| [`oidc/`](./oidc/) | B-side OIDC **provider** (`oidc-provider` v9) + the `/federation/oidc` bridge, clients, Redis-backed provider adapter |
| [`s2s/`](./s2s/) | Inbound S2S endpoint (`POST /federation/s2s`) + action handlers (`invited`, `authorize-invite`, `revoke`) |
| [`rp/`](./rp/) | A-side OIDC **relying party**: redirect, HMAC-signed state, authorization-code exchange, callback |
| [`invite/`](./invite/) | Federated invite surface (owner-side controller/router) |
| [`admin/`](./admin/) | Admin surface: pin/approve/deny/revoke peers, TAs, keys, audit |
| [`app/models/`](./app/models/) | Mongoose models (FederationPeer, FederationKey, FederationTrustAnchor) |
| [`app/views/`](./app/views/) | Consent page (Pug) |
| [`util/`](./util/) | Anchor serialization, PII redaction, audit, Redis rate-limit store |
| [`test/unit/`](./test/unit/) | Vitest unit tests |

Related files outside this module:
- `config/settings.defaults.js` — the `federation` settings block
- `app/src/models/User.mjs` — `user.federated` subdoc (mirror accounts)
- `app/src/models/ProjectInvite.mjs` — `invite.federated` subdoc
- `app/src/infrastructure/Mongoose.mjs` — model registry hook (indexes off;
  migrations create indexes)

---

## Runtime routes

### Inbound — this instance is the OIDC **provider** (B)
- `POST /federation/s2s` — S2S endpoint (client-assertion verified, rate-limited)
- `/federation/oidc/*` — OIDC provider endpoints (authorization/token/JWKS), bridged
  from `oidc-provider` (see `oidc/bridge.mjs`)

### Outbound — this instance is the OIDC **relying party** (A)
- `GET /federation/oidc/rp/callback` — OIDC authorization-code callback (non-csrf)
- The A-side RP flow is initiated from the invite surface (`invite/`) and ends in
  `CallbackRouter`, which 302s to the project URL.

### S2S actions (peer-to-peer, 03)
- `invited`          — invited-side: surface an invite to the user on the peer
- `authorize-invite` — approve / provision mirror + grant
- `revoke`           — trust revoked (local immediate + best-effort S2S)

### Admin (site-admin-guarded, mounted on the CSR `webRouter`)
- `GET    /admin/federation/peers`                 — peer list
- `POST   /admin/federation/peers`                 — pin a peer (TOFU; pairwise or institutional)
- `POST   /admin/federation/peers/:origin/approve` — `pending → approved`
- `DELETE /admin/federation/peers/:origin`         — **deny** (delete the `pending` row)
- `POST   /admin/federation/peers/:origin/revoke`  — **revoke** (local + best-effort S2S)
- `GET    /admin/federation/keys`                   — key metadata (public halves only)
- `POST   /admin/federation/keys/rotate`            — rotate the federation signing key
- `GET    /admin/federation/audit`                  — `federation_*`/`federated_*` audit rows
- `GET    /admin/federation/trust-anchors`          — institutional TAs
- `POST   /admin/federation/trust-anchors`          — pin institutional TA (entity id + JWK set)
- `DELETE /admin/federation/trust-anchors/:entityId` — delete a TA

---

## Configuration (`settings.defaults.js`, `federation` block)

```js
federation: {
  enabled: false,                    // master on/off (403 when false)
  allowFederatedProjectCreate: false // B-side: allow creating a project via federation
  requireAdminApproval: true,        // invite approval is admin-mediated, not automatic
  keyRotationGraceDays: 14,          // old key valid this long after rotate
  institutionId: null,               // our institution id (pairwise = null/leaf origin)
  institutionAuthorityHints: [],     // advertises these hints on our leaf EC (P3)
}
```

---

## S2S envelope & error contract

- **401** assertion-level failures (bad signature, replay/JTI, `from`/`to` mismatch,
  peer-unknown / peer-not-approved checks)
- **429** rate-limit (Redis-backed, per `from`/`to`)
- **200 + `{ ok, payload?, code? }`** — business result AND success
  (see `oidf/S2sErrors.mjs` / envelope docs)

Audit writes (`util/Audit.mjs`) are **redacted**: no PII, no tokens, JWK thumbprints
only. `util/Redact.mjs` enforces the allow-list. Business error codes (`s2s/`
handlers + `oidf/verify.mjs`) use short dash-separated slugs.

---

## Running tests & lint

```bash
cd services/web
# Vitest (all federation unit tests)
../../node_modules/.bin/vitest run -c vitest.config.js 'federation'
# ESLint (module + touched app files)
../../node_modules/.bin/eslint --no-cache --max-warnings 0 'modules/federation/**/*.mjs'
```

---

## Design authority

Source of truth for this module is the plan set in [`plan/`](./plan/):
00-overview, 01 (identity-federation-protocol), 02 (trust-model-oidf), 03
(S2S wire), 04 (data model), 05 (CEP integration / OIDC provider), 06 (security),
07 (roadmap + testing). When in doubt, **the plan wins over code comments**.

`HANDOFF.md` is the session-by-session project state log.
`ADMIN-GUIDE.md` is how to install, boot, pin, and test a live pair.
