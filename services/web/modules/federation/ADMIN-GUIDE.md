# Federation Admin Guide

Install, boot, pin, and test guide for identity federation on this fork.
Target reader: the sysadmin of instance **A** (invitee-side / RP + owner) and
instance **B** (home/OP). Identity federation only — no content sync.

---

## 1. Enable (both instances)

Edit `config/settings.local.js` (never `.defaults`):

```js
module.exports = {
  federation: {
    enabled: true,                      // master on/off
    // allowFederatedProjectCreate: false // keep default (off) on BOTH initially
    // requireAdminApproval: true,         // keep default
  },
}
```

Restart `web`. Boot side-effects of enabling (`index.mjs` `start()`):
1. `ensureBootstrapped()` — creates the instance's federation key pair if
   none exists (auto key rotation is **not** on; this is a one-time bootstrap).
2. `retireExpiredKeys()` — sweeps grace-expired keys
   (`federation.keyRotationGraceDays`, default 14).
The app-level middleware mounts, on enable:
- `GET /.well-known/openid-federation` — this instance's **leaf EC** (signed).
- `GET /federation/federation-keys` — public key listing (for admin
  browser/tooling).

Indexes: migrations run from the **repo root** via
`yarn workspace @overleaf/migrations up` (or the tooling in `tools/migrations/`
`package.json`); the two `20260721*` files create
`FederationPeer.origin`, `FederationPeer.status`, `FederationTrustAnchor.entityId`.

## 2. Verify the leaf is healthy

```bash
curl -sS 'https://b.example/.well-known/openid-federation'
```

- `Content-Type: application/entity-statement+jwt` (the `application/entity-statement+jwt`
  media type is verified per OIDF 1.0, not plain `application/jwt`).
- Three-part header: the **iss** claim equals `https://b.example`, the payload
  contains `jwks` (at least one P-256 ES256 signing key), and in **pairwise**
  mode no `authority_hints` key is present.
- For a second-instance sanity check: the leaf served at `a.example` and at
  `b.example` should not share a `kid` (each instance bootstraps its own key).

## 3. Pin peers (pairwise, both directions)

Pairwise bootstrap is **two admin acts** — one per direction. Do both, or
S2S one-direction only will work.

On **both** instances:

```bash
# A pins B and vice versa:
curl -X POST https://a.example/admin/federation/peers \
  -H 'Authorization: Bearer <siteAdminCookie...>' -H 'Content-Type: application/json' \
  -d '{"origin":"b.example","direction":"both"}'
curl -X POST https://b.example/admin/federation/peers \
  -H 'Authorization: Bearer <siteAdminCookie...>' -H 'Content-Type: application/json' \
  -d '{"origin":"a.example","direction":"both"}'
```

(`Authorization: Bearer` is a stand-in for the existing session-auth
mechanism on this fork's admin routes — whatever `ensureUserIsSiteAdmin`
expects today in this fork.)

The response is `201 { status: "pending", mode: "pairwise", anchorThumbprint,
kid }`. The peer is now pending; nothing is verified until approve:

```bash
curl -X POST https://a.example/admin/federation/peers/b.example/approve \
  -H 'Authorization: Bearer ...'
```

Repeat approve on `b.example`. Approved list:

```bash
curl https://a.example/admin/federation/peers -H 'Authorization: Bearer ...'
```

Expect `status: approved` on both rows (each direction).

### Institutional (P3) mode, only if the peer's leaf advertises `authority_hints`

If `https://b.example/.well-known/openid-federation` payload has a
non-empty `authority_hints` array, pinning B on A requires:

1. Pin the trust anchor A trusts (e.g. the DFN-CERT anchor):
   ```bash
   curl -X POST https://a.example/admin/federation/trust-anchors \
     -H 'Authorization: Bearer ...' -H 'Content-Type: application/json' \
     -d '{"entityId":"https://ta.example","jwks":{...public halves only...}}'
   ```
   A JWK set with a private component (`d` present) is **rejected** by the
   endpoint (05 §3 "public halves only").
2. Pin B as usual:
   ```bash
   curl -X POST https://a.example/admin/federation/peers -d '{"origin":"b.example"}'
   ```
   A's pin path walks `discoverEntity(b.example, <our TA set>)`, depth ≤ 10,
 10s. Response codes: `institutional-anchor-missing` (no TA on file),
   `institutional-chain-failed` (fetch/network), `institutional-chain-untrusted`
   (chain didn't resolve to a configured TA).

If the TA row is not on file when A pins a hinted leaf, the pin is **400
`institutional-anchor-missing`** — there is no pairwise fallback.

## 4. Key rotation (local, no S2S)

On either instance:

```bash
curl -X POST https://a.example/admin/federation/keys/rotate \
  -H 'Authorization: Bearer ...'
```

- Creates a new active key, publishes it in `federation-keys` + the leaf,
  keeps the old one for `federation.keyRotationGraceDays` (14).
- Peers discover on their **next JWKS fetch** (1h Redis cache). If a peer's
  S2S returns `kid-mismatch`, the admin can force by invalidating the
  `federation:jwks:*` Redis key or waiting for the cache to expire.
- Retire old key after the grace window (automatic via `start()` sweep).

There is **no S2S "re-federate" action** (02 §5): rotation is local, and
peers verify against kid-mismatch → refetch. Do not treat rotation as an
admin-approval step either; it is a local admin action.

## 5. Invite a user (instance A is the project owner; instance B is the home)

This is the happy-path UX flow (01 §5, 05 §2), the *owner-side* initiation:

1. Admin **approves peer `b.example` for outbound** on A (step 3, `direction:
   "both"`).
2. A's project owner, in the project, enters `inviteeLocalName: b.localName`
   (the B-side user's login name, **not** an email; the display
   `localName:origin` is parsed by `util/Anchor.parseAnchor`).
3. A: `GET /api/federation/invite/preview?anchor=<localName>:b.example`
   (soft preview, cached 60s on A, `approved:false` on miss/degrade — the
   invite is savable without it, "defer verification" 05 §4.1).
4. A: `POST /api/federation/invite/authorize` with
   `{ projectId, anchor: "<localName>:b.example", privileges: "readAndWrite" }`.
   - A does its local collaborator check.
   - A issues the outbound S2S `authorize-invite` to B (home oracle).
   - B resolves the local account, returns `{ approved, displayName,
     institution }`. Business refusal is a 200 envelope with
     `code: invitee-unknown | invitee-disabled` — **not** a 401.
   - A upserts the project invite, mints the PKCE signed state, 302s the
     browser to B's OIDC authorization endpoint.
5. B: the user is authenticated on B (via any B-side auth: password, SAML,
   LDAP); consent bridge; B issues a code to A callback.
6. A: callback → code-exchange (30s timeout on token endpoint) → mirror
   provision (if first invite for that anchor) → grant on the project →
   local session mint on A for the mirror user → 302 to the project URL.

Audit rows written on both sides: `federated_invite_authorized` (owner on
A) and `federation_session_issued` (mirrored session on A).

### Mirror account properties (so the support desk knows)
- The mirror row is a **regular** `User` row (no `kind` field, 01 §3.2);
  only the **presence of `User.federation` subdoc** marks it: `origin`,
  `localName`, `federatedAt`.
- `hashedPassword` is **undefined** on mirror rows (they never sign up with a
  password), and `email` is `''` (never through the `serializeUser`
  path); the mirror's "identity" on A is the OIDC id_token from B, not a
  local credential.
- Mirror rows are **only reachable** via grant resolution — login and local
  SSO paths do not resolve them by email (06 §3).

## 6. S2S round-trip (curl, to prove trust end-to-end)

On a clean machine (no admin), exercise the S2S *inbound* side to confirm
the wire works:

```bash
# 0) grab A's active key (kid + thumbprint)
curl -s https://a.example/federation/federation-keys
# 1) build a signed client assertion for the A→B direction (the B-side
#    endpoint expects an assertion signed by the A federation key whose
#    kid is in B's pinned anchor for a.example).
#    The actual `client_assertion` is produced by the outbound module
#    itself — this step is illustrative; for a live test, use the
#    invite flow (step 5) instead, which exercises the real builder.
```

The invite flow (step 5) is the end-to-end S2S proof; do that first, and
only drop to raw curl for a reproducible wire-level bug hunt.

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Peer pin returns `institutional-anchor-missing` | Leaf EC has `authority_hints` but no TA on file | Pin the institutional TA first (`POST /admin/federation/trust-anchors`), then re-pin peer (05 §3 "public halves only" — no `d` in the JWK). |
| `institutional-chain-untrusted` on institutional pin | TA row on file but chain doesn't resolve to it | Fetch the peer leaf EC manually, compare `iss` in the chain's SS to the `entityId` of every TA row on file; the leaf's *root* hint must be a TA we trust. |
| `kid-mismatch` in S2S log | Peer rotated its federation key before this instance's JWKS cache expired | Bump `federation:keyRotationGraceDays`, or `DEL` the `federation:jwks:<origin>` / `federation:jwks:<origin>:<kid>` Redis keys; the next fetch picks up the new kid. |
| `rate-limited` 429 from peer | `from` (our origin) over peer's S2S budget for this `localNameHash` | Wait out `Allow-Retry-After` (see 03 §5 budgets); or reduce per-`localNameHash` frequency from the owner UI. |
| Invitee S2S says `invitee-unknown` but the user "exists" on B | The `localName` entered is an email, not the B login name | Fix the invite input to the B login **name** (the local part per B storage convention, 01 §3.1) — the wire claims `origin` and `localName` separately; the colon string is display-only. |
| Mirror login lands back on A's home (no project) after consent | `url` in the signed state was not root-relative | Check the invite's `url` is `/project/<id>` (a single leading slash, no scheme, **no** backslash). `CallbackRouter` normalizes anything else to `/`. |
| Admin pin `invalid-ec` | Leaf EC `iss` doesn't match the pinned `origin` (case, trailing dot, trailing slash) | Verify the pin's `origin` is the exact host of the peer's `Settings.siteUrl` (bare FQDN, no scheme, no trailing `/`); the OIDF well-known is at the peer's own origin, not a subpath. |
| "Federation is off" 200 envelope with `federation-off` | `federation.enabled: false` on the receiving side | This is the expected wire for a peer with federation disabled (03 §5) — **not** an error; flip the setting and confirm `start()` bootstrap ran. |

### Audit
- `GET /admin/federation/audit?limit=100` (limit is clamped to `1..200`,
  default `50`). Rows are `ProjectAuditLogEntry` with `operation` in the
  module's `AUDIT_TYPES` set. Filter client-side if you need to isolate one
  operation.
- Audit rows are redacted (04 §8): anchor `localName` never logged raw;
  `jwks` never logged; `kid` + `thumbprint` allowed.

### Revoke
- Admin revoke on A:
  `POST /admin/federation/peers/b.example/revoke` — locally flips the row to
  `revoked` on A, then does a **best-effort** S2S `revoke` to B (03 §4.3). On
  B that inbound `revoke` also flips *B's* `a.example` row to `revoked`,
  stopping inbound S2S from A and blocking grant minting (client list
  rebuild). It does **not** delete mirror rows and **not** kill existing
  sessions (04 §5 v1).

### Reset / wipe (destructive — dev only)
- Delete `federationpeer`, `federationtrustanchor`, `federationkey` rows
  directly in Mongo and re-bootstrap. The OIDC provider memo (per-instance
  singleton) is rebuilt on the next web request once `status` flips. Do not
  mix "wipe peer row" with "re-pin before rotate" — if the key is rotated
  first, the old anchor `kid`/thumbprint on the peer row is stale and
  runtime verification will `kid-mismatch`.

---

## 8. What this is NOT (scope, again)

- No content/stream federation.
- No cross-instance project storage.
- No RFC 9421 signed-S2S (client assertion is OIDF 1.0's native transport).
- No `PermissionsService` on this fork — grant mechanism is
  `CollaboratorsHandler.promises.addUserIdToProject`.

For the *why* behind each of those: see `plan/00-overview.md` and
`plan/01-identity-federation-protocol.md` §1.
```
