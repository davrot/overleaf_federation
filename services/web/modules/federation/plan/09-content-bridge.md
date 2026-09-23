# overleaf-cep Federation — Content Bridge (v2, git-bridge project export/import)

> v2 increment — **out of P0–P2 (identity) scope** (00-overview "no content
> stream, no sync"; 07 open items). This file is the design authority for
> the first *content* surface on top of the identity wire. Phases 2a/2b/2c
> are mergeable slices; none change the P0–P2 wire.

Identity (P0–P2) gives home A a **mirror** for users of partner B. Content
is deliberately absent: their projects still live on B. This increment
adds the first content path: **a user on home A exports a project they
own on B (short-lived read-only git PAT, S2S-mediated), and imports it
into A as a NEW project via bidirectional git push (existing surface).
Re-clone + re-push = the backup mechanism.**

## 1. Scope

IN (v2.1, read-only export + user-side import):
- S2S action `export-project` (home → partner), reusing the existing wire
  (envelope, client assertion, replay, rate limit, redaction, audit).
- B-side mint of a **short-lived, read-only, project-scoped** git-bridge
  PAT, mint-verified against **the user's consent grant to home A** (§2.1).
- Import into A = overleaf-cep's **existing bidirectional-git** surface
  (`gitBridge` feature, `Settings.gitBridgePublicBaseUrl`): the user
  pushes the exported history into a NEW home project. **No new
  server-side "import from git" exists in overleaf-cep and none is
  built** (that would be a docstore-mapping feature, v3).
- Revocation tie-in: peer `revoke` sweeps exports + outstanding codes
  (04 §5 `killOutstandingCodes` gets real teeth — pairs with
  TODO-e652c0d9).
- Bonus: the same adapter index (§2.1) makes home-side
  `findExistingGrant` functional (01 §3 step 9 "no re-consent", the
  v1.1 item `bridge.mjs` documents).

OUT (deferred — v2.2+/v3; not designed here):
- **Write-back / sync B↔A** (docstore mapping + conflicts — v3).
- `list-owned-projects` S2S (needs a claims discussion, v2.2).
- Token refresh (v2.1: short-lived; expiry = re-export, not refresh;
  documented as a v2.1 UX wart).
- Admin approval queue for exports (consent IS the binding — §2.1 —
  so no queue needed; see 04 §2.1 "not-yet-approved" analogy).

## 2. Wire: S2S `export-project`

New action on `/federation/s2s` (the 03 §4 action template —
`revoke`/`invited` shape exactly; **no** new trust primitive):

- Request (A→B), envelope + client assertion from **A's** S2S key:
  ```
  action: 'export-project'
  payload: {
    projectId: <B-local project id>,
    expiresAt: <unix sec, ≤ now + export.maxExportTtlSeconds>,
  }
  ```
- B verifies (S2sRouter ③④⑤ unchanged): peer pre-lookup approved →
  assertion (signature vs pinned anchor, `iss` = A client_id, `aud`,
  `exp`, jti replay) → rate limit. **New budget row: `export-project`
  10 / 120 s** (03 §6 table grows by one row at 2a implementation;
  plan 03 file itself is P0-authority and is NOT retro-edited).
- B authorization — **the content-specific binding (§2.1)**.
- B response (200 envelope; errors are 401 per the 401/429 envelope
  contract, 03 §0):
  ```
  { ok: true, payload: {
      gitUrl: `https://<B-host>/git/<projectId>`,   // overleaf git URL
      pat: <short-lived read-only PAT>,
      expiresAt,
    } }
  ```
  **Secret transport (documented risk, v2.1):** `pat` rides the
  *unsigned* response envelope (03: responses are plaintext-over-TLS
  in v1). Acceptable v2.1 ONLY because: TLS + short-lived (≤
  `maxExportTtlSeconds`) + read-only + revocable + project-scoped.
  v2.2 option if too hot: signed response envelope (new wire work).
  Recorded here, decision is here.
- Redaction (03 §3 deny-list unchanged): `pat` is a NEW sensitive
  field — `Redact` must redact it in audits (audit stores length +
  expiry only, never the value). `gitUrl` = origin FQDN + project id
  (public-URI shape; not redacted).
- 401s: `peer-not-approved`, `export-disabled` (B off),
  `export-no-consent` (§2.1), `project-not-owned` (NEW codes, 03 §4
  table grows at 2a). No 429 change (new budget row only).

### 2.1 The user-binding on B (user-level auth over a server-level wire)

The S2S assertion identifies **home A** (server identity, OIDF 1.0 —
no user claim; that's the entity-authorization v2.2 follow-up). So the
binding must come from a *B-side record*: **B's consent grants.**

v2.1 rule (one sentence): *the export succeeds iff the project owner has
a LIVE consent grant to home A's client.*

- B-side grant lookup: `(accountId = Project.owner, clientId =
  urn:overleaf-federation:client:<A-host>)`. A grant exists ONLY for a
  B-native user who **explicitly consented to login at A** (that's the
  whole meaning of the grant — 04 §5 `Grant, 30d` "remember the
  choice"). So "live grant ⇔ this user knows A is home and approved
  A". The client_id string encodes A's origin (`clients.mjs`
  convention), so the binding is PER-HOME: B user U cannot have a live
  grant to A2 just because they consented to A1.
- **Implementation (adapter, our code):** add `findByAccountAndClient`
  (+ the `federation:oidc:account:<accountId>:<clientId>` secondary key
  written on Grant-model upsert in `RedisOidcProviderAdapter` — upsert
  is the only persistence point, 05 §8.2; `revokeByGrantId` already
  sweeps the `federation:oidc:grant:<id>` set, so the sweep must also
  delete the account key — same cascade). No new migration (the
  secondary key is ephemeral Redis, 04 §5).
- `Project.owner` must be B-**native** (a row with NO `federation`
  subdoc — mirror rows are home-side only, 04 §1; B's own user has
  their own credentials). Otherwise `project-not-owned`.
- No consent grant to A → `export-no-consent` (401). This is the
  consent-as-authorization gate: **no admin approval queue is needed**
  for the export path (the user's consent IS the approval, 04 §2.1
  "admin approval gate" analogy).
- **Side effect (2a):** this same lookup is exactly what home-side
  `bridge.mjs#findExistingGrant` needs (today hardcoded `return null`
  + re-consent, 01 §3 step 9). 2a adds it on B (OP-side grant
  storage); home-side `findExistingGrant` gets the lookup in the same
  2a diff (home A has the same grant storage for ITS clients —
  symmetric). Documented: this makes "no re-consent" work on B (the
  OP side of the dance) first.

## 3. B-side grant model

`app/models/FederationExportGrant.mjs`:
```
{
  owner: String,            // B-local user id (index)
  projectId: String,        // B-local (index)
  homeOrigin: String,       // the A that requested (from verified assertion iss)
  scope: String,            // 'federation:git_bridge' (read-only marker, §4)
  patHashPrefix: String,    // first-8 chars for UI display
  expiresAt: Date,          // ≤ now + Settings.federation.export.maxExportTtl
  status: 'active'|'revoked'|'expired',
  createdAt: Date,
}
```
Mint: `db.oauthAccessTokens.create` (type `personal_access_token`,
scope `'federation:git_bridge'`, `expiresAt` = grant expiry). Git
PATs ride the existing `oauthAccessTokens` collection (git-bridge
module's own vocabulary, 04 §4 deny-list respected: token is
instance-local; the PAT itself never crosses S2S except the
user-initiated §2 response — one documented v2.1 transport, §2).
Sweep (peer `revoke`, 04 §5 `killOutstandingCodes`): revoke handler
(03 §4.3 effects list GROWS at 2a):
- sweep `FederationExportGrant` rows for that peer → `revoked` +
  `db.oauthAccessTokens.deleteMany(...)` for their PAT values;
- + existing effects (S2S 401 post-lookup, provider memo reset,
  idempotent, audit);
- + **outstanding AuthorizationCodes** for the client (adapter
  cascade + `federation:oidc:authorization_code:*` per-client sweep —
  closes the 120s residual recorded in FINDINGS "Shared-client-row";
  **this is the first real consumer of `killOutstandingCodes`**).
Audit (B-side, `ProjectAuditLogEntry`, same redaction):
`federation_export_granted`, `federation_export_denied` (401 reason),
`federation_export_swept`. No project-id leak in A-side audit
beyond what §2 response already carries (A stores projectId + expiry
only if it persists anything — v2.1: A does NOT persist; the wizard
is stateless (session-only), §4).

## 4. Home-side import = bidirectional-git push (NO new import feature)

overleaf-cep has **no** server-side "import project from git":
`gitBridge` is bidirectional sync (user ↔ git-bridge ↔ project
history, `Settings.features.gitBridge`,
`Settings.gitBridgePublicBaseUrl`). Import reuses it, user-side:

1. On home A (logged in as the mirror user): run the **export wizard**
   (2b) — controller (§4.1) does §2 S2S via A's own B-side… no: via
   A's outgoing `ClientAssertionClient` against B's `/federation/s2s`,
   returns `{ gitUrl, pat, expiresAt }` **to the request session only**
   (XSS guard: rendered into instructions, `res.locals`, session
   binding — **not** in a response body field).
2. User workstation: `GIT_ASKPASS` clone of `gitUrl` with `pat` →
   full history of the B project (the **backup** is this clone).
3. User, home A: create a NEW project → bidirectional-git push of the
   cloned history into the empty project (existing overleaf-cep
   surface). Home now holds the imported copy.
4. Re-import ("refresh backup") = steps 2–3 again (new local clone or
   pull, push into a new or force-pushed project — v2.1: user's
   judgment, document; no server sync).

Read-only enforcement (**git-bridge module, 2c, one guard**): export
PATs use scope `federation:git_bridge` (the git-bridge auth regex
`/\bgit_bridge\b/` still matches it — `:` is a non-word boundary, so
auth succeeds — verified against `GitBridgePATManager`'s scope
query). Guard: `receive-pack` (push) on a `federation:`-scoped token
→ 403; `upload-pack` (fetch) allowed. Push is refused at the wire;
fetch is the content path. Net git-bridge diff (2c): one
scope-prefix check in the receive-pack auth path. No git-bridge import
of the federation module (dependency rule preserved: git-bridge does
not know about federation — the marker is in the token's scope string).

### 4.1 A-side wizard (2b), A-STATELESS (no home export state)

`invite/FederatedExportController.mjs`-shaped (`invite` module
pattern): `POST /federation/export` { projectId, expiresAt } →
server-side S2S call (A's `ClientAssertionClient.buildS2sRequest`
`'export-project'`, 03 §4) → **session-only** locals `{ gitUrl, pat,
expiresAt, instructions }` → view rendered (pug, `federation` module's
own view, 05 §1 view registration). A persists **nothing** (re-run =
new S2S call). A-side rate limit: none new (B-side budget row covers
the wire; the wizard is per-user-form, B-side budget is per-origin —
acceptable v2.1: the origin-level budget IS the per-(A,B)-pair budget).
A-side audit: `federation_export_requested` (redacted: gitUrl +
expiry, NEVER pat), `federation_export_denied` (B's 401 reason).

## 5. Settings (both instances, one block)

`settings.defaults.js` `federation`:
```
export: {
  enabled: false,              // B-side: allow export-project S2S
  maxExportTtlSeconds: 86400,  // cap for payload.expiresAt
  sweepOnRevoke: true,         // 04 §5 — killOutstandingCodes' first consumer
}
```
(Names chosen to read as one unit: `federation.export.enabled` = the
B-side switch for this S2S action; `federation.export.maxExportTtlSeconds`;
`federation.export.sweepOnRevoke` gates §3 sweep (default on; off =
the v1 NO-OP behavior preserved for migration safety). Both A and B
set their own `export.enabled` **separately** — A can export from B
even if B has export disabled… no: `export.enabled` is a B-side gate
on receiving. A-side needs nothing (A's wizard is per-user auth'd +
B-side 401s are the gate). Documented.)

## 6. Phases

- **2a (B-side, mergeable alone) — SHIPPED** (SESSION content-bridge 2a) — `export-project` S2S +
  §2.1 adapter index (`findByAccountAndClient` + account-key write in
  `RedisOidcProviderAdapter.upsert` for Grant + `revokeByGrantId`
  cascade) + grant model + PAT mint + 3 new 401 codes + budget row +
  redaction + audit + B-side home `findExistingGrant` wired (bonus).
  Tests (GREEN): S2S action unit (`exportProject.test.mjs`, 14 cases:
  settings gate, malformed/no-project/owner-missing/mirror/suspended →
  not-owned, no-consent, happy sha256+snake_case, idempotent fresh-PAT,
  TTL clamp ×2, grant-gone soft-degrade, ledger-failure no-break) +
  adapter account-index unit (`adapterAccountIndex.test.mjs`, 7 cases
  with fake-redis: Grant index, token-model exclusion, live/unknown/
  expired lookup, cascade destroy, not-over-cross) + two-instance S2S
  scenario (`two-instance.sequential.test.mjs` cases 13–17: export-
  disabled, dance→export happy sha256 ledger, idempotent re-export,
  no-consent, 429 budget on the 11th).
  Migration `20260721150001_add_federation_export_indexes` added to
  `tools/migrations/lib/mongodb.mjs` static map (`federationExportGrants`)
  — verified live against smoke Mongo (indexes `owner_status_1`,
  `expires_at_1` present; migration row recorded).
- **2b (A-side wizard, merges on 2a) — SHIPPED** (SESSION 13, commit
  `1b7a9d4634`) — `invite/FederatedExportController` +
  `FederatedExportRouter` on the CSRF `router` under `requireLogin`
  (invite shape), `app/views/federation-export[-result].pug` (form +
  one-time PAT render, Q2), `federation_export_requested` audit +
  `META_FIELDS += { gitUrl, expiresAt }` (09 §3.2, PAT never audited),
  mounted ④b in `index.mjs` `router.apply`. A persists nothing
  (re-run = fresh S2S). Wire: `callPeer(origin, 'export-project',
  { projectId, expiresAt })` — 2a contract `{ git_url, pat, expires_at }`.
  Tests: 9 new (`FederatedExportController.test.mjs`, thunk pattern +
  redaction regression) / 172/172 federation green.
- **2c (git-bridge guard + sweep, merges on 2a) — SHIPPED** (SESSION 14) —
  read-only **403 guard at the git-bridge write choke point**
  (`GitBridgeAuthMiddleware.ensureTokenProjectAccess('write')`):
  the token is resolved WITH its scope via the new
  `GitBridgePATManager.getUserIdAndScope` (`{ userId, scope }`;
  `getUserId` now delegates to it). A `federation:`-prefixed scope
  (marker `federation:git_bridge`, minted by B) is refused on the
  write path (receive-pack snapshot postback) **before** the
  permission oracle, `logger.warn` + 403; read paths (fetch /
  upload-pack) stay allowed (the content path). No federation import
  (dependency rule: scope-string prefix only).
  Sweep + revoke wiring: `export/Sweep.mjs` `sweepExportGrants(origin)`
  — ledger rows → `status:'revoked'` + per-row
  `db.oauthAccessTokens.deleteOne({_id, scope: EXPORT_SCOPE})`
  (scope-guarded, best-effort) + `federation_export_swept` audit
  (meta `{ origin, scope }`, PAT value never a field). Gates on
  `Settings.federation.export.sweepOnRevoke` (default ON; off = v1
  NO-OP). Independent of the `killOutstandingCodes` flag (that gates
  `revokeClientCodes`, the oidc code sweep, 06 §179). Called from BOTH
  revoke transitions (s2s `revoke.mjs` + admin `handleRevoke`, both
  try/catch best-effort mirroring the code-sweep twin).
  Tests: `git-bridge/test/unit/GitBridgeAuthMiddleware.test.mjs` (6
  cases: write+federation:scope→403 oracle NOT consulted,
  read+federation:scope→allowed fetch, write+normal→oracle applied,
  write+normal+no-access→403 via oracle, write+unknown→401,
  read+unknown→401; thunk `__TOKENS`/`__READ_ALLOWED`/
  `__WRITE_ALLOWED` + call-log) + `s2s/revoke.test.mjs` (4 cases: sweep
  on transition (2 PATs scope-guarded, ledger revoked, redacted
  audit), sweep off (NO-OP), idempotent no-sweep (0 modified),
  best-effort PAT-delete failure still revokes) + `admin
  /FederationAdminController.test.mjs` (2 cases: sweep on transition
  flag-INDEPENDENT + idempotent double-revoke). 183/183 (177 fed + 6
  git-bridge) green. Lint clean on all touchable 2c files.
- **OPEN for 2d:** 2-real-origins (A≠B) live docker smoke — export
  wizard → S2S export-project → PAT fetch + **live push-gets-403**
  against the deployed git-bridge (the guard is in this repo's
  Node REST surface; 2d verifies both the Bearer and Basic-info
  surfaces end-to-end).
- **RESOLVED in 2a (was open question):** git PAT expiry —
  git-bridge **DOES enforce `expiresAt`** on PATs: `GitBridgePATManager.getUserId`
  filters `expiresAt: { $gt: now }` when looking up a raw PAT
  (`GitBridgePATManager.mjs:98`). So the 2a TTL clamp
  (request ∩ grant remaining ∩ `maxExportTtlSeconds`) is the live
  expiry enforcement point; the §3 sweep is belt-and-suspenders.
  The scope regex `gitBridge: /\bgit_bridge\b/` matches both
  `git_bridge` (user PATs) and `federation:git_bridge` (2a export
  PATs) because `:` is a non-word boundary — the 2c read-only guard
  will need to distinguish by the `federation:` prefix (already the
  plan's intent). No change needed.

## 7. What "backup" means here (honest)

v2.1 backup = **user-initiated periodic re-clone + re-push-into-a-new
home project**. No scheduler, no sync, no rename (the home copy is a
separate new project — "imported from B <origin> <sha>" naming is a
2c-polish cosmetic). The home project's history IS the backup (docstore
via bidirectional-git, existing surface). Automation (cron re-export)
is a 2c+ item, NOT in v2.1.
