# 10 — eduGAIN / DFN-AAI (SAML) + GEANT AAI (OIDC) interop

> Status: P1a (fe4 SSO framework port) DONE, P1b (N-provider dispatch) DONE, **P1c (per-provider attrFilter roles) DONE** (2026-09-23, commit 8a99c05e79). Next: Phase 0 (Shibboleth proxy) → Phase 2 (DFN live) → Phase 3 (GEANT live) → Phase 4 (hardening). Paused goal
> `3ea7bb53` (v2: `3dad1c9e`) — content-bridge 2a–2d queued behind this.
> Primary sources: DFN-AAI doku (doku.tid.dfn.de); GEANT AAI Confluence export
> (`/home/davrot/edugain`, extracted at `/tmp/edugain_txt/`); upstream
> `overleaf-cep@fe4ceb6` ("Initial files", branch `sso`).

---

## 0 — Verdict (short)

1. **Our OIDF peer-federation module (plans 00–09) stays untouched and is KEPT** as the
   mechanism for every non-eduGAIN/DFN user (other parts of the world, peer-Overleaf
   SSO + content-bridge). It federates *Overleaf instances* (OIDF, origin-keyed trust).
   eduGAIN/DFN-AAI federates *university IdPs* (SAML2). Different axes, complementary.
2. **"Is our OIDC approach okay with them?"**
   - **DFN-AAI:** no OIDC track. DFN-AAI is SAML2-only for participation (their
     "non-Shibboleth IdPs/SPs" page lists SAML2 software: SimpleSAMLphp, ADFS).
     Only path for OIDC is a third proxy that publishes an OIDC IdP (e.g. eduTEAMS).
   - **GEANT AAI Service (eduTEAMS):** yes, compatible. It's an **as-a-service OIDC IdP**
     (`proxy.aai.geant.org/.well-known/openid-configuration`; SAML front:
     `/metadata/frontend.xml`) that collapses eduGAIN aggregate + direct OIDC IdPs
     behind one SaaS entity. Overleaf's OIDC client — stock, or the extended
     `fe4ceb6` framework — consumes it with minimal code. Gaps: `email` claim not
     guaranteed (R1), use `sub` as identity anchor (already stock default `id`).
3. **Architecture (LOCKED 2026-09-22):**
   - **SAML leg →** Shibboleth-SP (or SSP) proxy in front of the eduGAIN/DFN-AAI
     aggregate (proxy owns WAYF/EDS + IdP fan-in). No existing proxy exists →
     Phase 0 stands one up (Shibboleth-SP recommended; DFN test IdP first).
   - **OIDC leg →** N OIDC provider entries: GEANT AAI Service, national OIDC IdPs,
     etc.
   - **Provider count: N-OIDC + N-SAML active**, keyed by `ssoConfigs.providers[].id`
     (§0.7), extending the upstream `fe4ceb6` framework.
   - **Config surface →** SSO admin DB config replaces static `OVERLEAF_*` env for
     these providers.
4. **Work that is NOT needed:** in-app fan-in of the raw eduGAIN aggregate (thousands
   of IdPs, in-app discovery — v1 "Option C") explicitly dropped: N covers multiple
   *servers* as single SAML entries each, and the Shibboleth proxy handles the
   eduGAIN-wide IdP fan-in upstream of the app.

## 0.5 — What `overleaf-cep@fe4ceb6` actually is (verified 2026-09-22)

Commit `fe4ceb6ba2` ("Initial files" on branch `sso`, merged into ext-ce as
`01bb02c121`):

- **DB-driven SSO config**: `ssoConfigs` collection (doc `_id='sso-settings'`),
  `providers[]` with `{type:'saml'|'oidc', enabled, entryPoint, issuer, idpCert,
  privateKey, clientID, clientSecret, scope, ...}`, plus `order`, `loginPage`
  (logo/title/localLoginEnabled). Loader: `modules/authentication/ssoConfigLoader.mjs`
  (env fallback when no DB doc).
- **Admin module** `modules/authentication/admin` (SSO-only port — see §6):
  - `/admin/sso` UI + JSON API (get/save/reorder providers, LDAP toggle,
    login-page branding). Providers masked on read (secrets).
  - Test endpoints: OIDC = `openid-configuration` fetch; SAML = entrypoint GET
    reachability (weak — G3).
  - Also ships `emailConfigs` + `EmailAdmin` — **excluded** from this port (decision).
- **Login page rework** (`app/views/user/login.pug`): dynamic SSO buttons from
  `res.locals.ssoProviders`, optional logo/title, hide-local-login option.
- **Module wiring**: `saml/index.mjs` + `oidc/index.mjs` await
  `isSAMLEnabled()`/`isOIDCEnabled()` before import (DB-config can enable modules
  without `EXTERNAL_AUTH` env). `settings.defaults.js` module list gains
  `'authentication/admin'`; `mongodb.mjs` gains `emailConfigs` (and
  pre-existing `ssoConfigs`).
- **Per-manager base**: DB config or env, same shape; **only one provider per
  protocol registered** at login (decision: extended to N, §0.7):
  `getSAMLProviderConfig()` / `getOIDCProviderConfig()` = first-enabled.
- `SAMLStrategy` (passport-saml) + `OIDCStrategy` (passport-openidconnect),
  strategy names `'saml'` / `'openidconnect'` — collision under N,
  addressed by named per-provider strategies.
- SAML manager has hardcoded `providerId='1'` (upstream comment: "in the case of
  multiple SAML IdPs, one would have to do something similar") — exactly what §0.7
  resolves.
- Also bundled (not ported): `emergency-enable-local-login.sh`, navbar admin-menu
  admin entry, LDAP manager DB-config support.

### Fork divergence (overleaf-cep vs our fork)

Diverged in BOTH (our fork has v1 federation changes + hand-off session 11;
upstream has the SSO tweaks) → **manual 3-way merge**:
- `app/views/user/login.pug`
- `app/src/infrastructure/mongodb.mjs` (runtime) + `tools/migrations/lib/mongodb.mjs`
  (migrations, static-map learning from v1)
- `config/settings.defaults.js` (module list)
- `app/src/models/User.mjs` (if upstream touched it — verify)
- `modules/authentication/{saml,oidc}/...` (managers + module gates)

Clean new files (no conflict): `ssoConfigs` loader, `authentication/admin/` module
(SSO portion of the upstream module).

## 0.7 — N-provider design (LOCKED 2026-09-22, "N-OIDC + N-SAML")

N = multiple *SAML servers* / *OIDC IdPs*, each a single SaaS-managed passport
entry (e.g. "DFN/Shibboleth-SP proxy", "GEANT AAI Service", "national OIDC IdP").
Extends `fe4ceb6` (base = first-enabled per protocol).

**Provider-as-key** — the admin-generated `id` in `ssoConfigs.providers[].id` becomes:
- passport strategy name: `oidc-<id>` / `saml-<id>` (replaces `'oidc'`, `'saml'`
  defaults)
- provider link key: OIDC already links by `providerID || 'oidc'` → use real `id`;
  SAML `User.samlIdentifiers` is already `providerId`-keyed → use real `id` (replaces
  hardcoded `'1'`)
- per-provider runtime: `Settings.oidc.providers[<id>]` / `Settings.saml.providers[<id>]`
  (replaces the current singleton `Settings.oidc`/`Settings.saml`)
  Env fallback mode = one default id each (keeps `EXTERNAL_AUTH` compatibility)

**Lazy strategy registration (passports, not module load):**
- Module **load** still boot-time (env or DB enables the module via
  `saml/index.mjs` await). Strategy **registration** is ON-USE:
  `ensureStrategy(providerId)` helper; router calls it before
  `passport.authenticate`.
- Admin "save" → `clearConfigCache()` + next `ensureStrategy` picks up (no
  restart). Delete → strategy eviction (`passport._strategies[name]` plain map;
  recon: clean delete or leave + warn).
- `passportSetup` hook becomes a no-op logging helper (module contract preserved).

**Routes (per-provider login, one dispatched callback each):**
- OIDC: `GET /oidc/login/:providerId` → sets per-login provider state in
  session; callback unchanged `GET /oidc/login/callback` (dispatched per
  session). This preserves the redirect-URI contract with GEANT
  ("wildcards not supported" → exact URLs).
- SAML: `/saml/login/:providerId`; callback unchanged
  `/saml/login/callback` (per-session dispatch).
- `req.session.saml_extce{nameID, sessionIndex}` (logout match) already per-login;
  no change for N.
- Login buttons: `/oidc/login/<id>` + `/saml/login/<id>` URLs derived from
  `getEnabledProviders()` (admin already orders; add `providerId` field to
  locals).

**Recon seams (narrowed, record outcomes in recon log before build):**
- `passport-saml` (v5 in `@node-saml/passport-saml`): Strategy `name` option?
  (affects whether per-provider instances need distinct closure-bound config)
- `passport-oauth2` state store: session-key collision between per-provider
  OIDC strategies (shared `oauth2:state:oidc`)? If yes → per-provider
  `stateStore` factory or session-key namespacing.
- Strategy eviction semantics on provider delete.

**Managers (N-aware):**
- `OIDCAuthenticationManager.findOrCreateUser(req, profile, providerId)` —
  providerId from closure/session (not `Settings.oidc.providerId`);
  per-provider `allowedOIDCEmailDomains` (DB field already per-provider).
- `SAMLAuthenticationManager.findOrCreateUser(profile, providerId, ...)` —
  replaces `providerId='1'`; `User.samlIdentifiers` stays `providerId`-keyed.
- Audit method strings: `'OIDC login'` → `'OIDC login - <providerId>'`
  (SAML mirror).
- Policy: `samlPolicy`/`oidcPolicy` validate on `externalAuth` string —
  no change for N.

**Loader (N-aware):** `getAllEnabledProviders()` alongside first-enabled
helpers (which remain for env-fallback single-provider mode).

**Admin (SSO-only):** SSO admin module + `ssoConfigs` key + login-page
rework. `emailConfigs` NOT ported (decision §6.5).

## 0.8 — Per-provider attribute filters (ROLE: local / guest / blocked) — user requirement 2026-09-22

Per provider, admin-configurable **attribute filters** decide, from the
attributes actually released by that provider, *who may log in* and *what
they may do*:
- **local**  — normal account (may create own projects)
- **guest**  — allowed to log in, but **cannot create own projects**
- **blocked**— refused at login entirely (no account creation, no session)
- (admin — already handled by the existing attAdmin mechanism, unchanged)

**Shape (per provider, admin-configurable, `ssoConfigs.providers[i].attrFilter`):**
```
attrFilter: [ { role: 'local'|'guest'|'blocked'|'admin',
                attribute,      // claim/attr name as released (OIDC claim name,
                                 // or SAML attribute name/OID as admin specifies),
                values: [...],  // match list; multi-valued claim/array-aware
                match: 'equals'|'includes'|'regex',   // default 'equals'
                caseSensitive?: bool }, ... ]
```
- Multiple rows per provider; **evaluation order: blocked → guest → admin →
  local** (first match wins; no match → default 'local'). Admin must sort
  accordingly (UI hint: drag-reorder, "first match wins" docstring).
- `attribute` is whatever the provider actually releases. For GEANT
  `entitlements`, this is the claim name `entitlements`; DFN SAML uses the
  attribute name/OID as the admin specifies (recon seam: how the manager
  sees SAML profiles — OID NameID vs short name).
- **`sub` / persistent identifier stays the identity anchor** as before;
  row is a separate field. Never a role itself.
- **OIDC userinfo vs ID-token:** filter runs against what the profile
  payload carries. For userinfo-only claims (`entitlements` is
  userinfo-only per GEANT attrs table), the manager fetches userinfo when
  required for JIT (recon seam: passport-openidconnect profile surface
  — where the token is available post-redirect). No double-fetch for
  ID-token-only claims.
- `values` list capped at admin UI (≤10 rows per default); per-attribute
  match is `equals` (single-valued claim vs single value) or `includes`
  (multi-valued claim contains value, e.g. `entitlements` membership)
  or `regex` (string match — **no ReDoS guard at first pass**, documented,
  keep values simple).

**Where role is stored (N-aware):**
- `user.ssoRoles[providerId] = { role: 'local'|'guest'|'blocked',
  filterId?: <row>, reason?: '<attr>=<val>', at: <ts> }` — optional
  subdocument on `User`; schema is `strictQuery:false` in our fork so
  reading a stale doc is safe. Existing OIDC/SAML users inherit 'local'
  when absent (no migration).
- **Re-evaluated on every login** (admin can change rows without wipe;
  next login picks up the change; DB value updated).
- **Blocked:** if a row is `blocked` *now* and the filter matches, refuse
  the login (redirect to `/register` for JIT, 401 for existing account) —
  no session, no account creation, audit row `sso-login-denied`.
- **Guest:** login allowed; **project creation refused** (below).
- **Local / no match:** normal.

**"Guest cannot create own project" seam — VERIFIED (recon 2026-09-22):**
overleaf-standalone has **no** `canCreateProject` capability, and
`newProject` (ProjectController.mjs) doesn't plan-check at the route level;
all "create own project" paths converge on one function:

  `ProjectCreationHandler.promises.createBlankProject(ownerId, projectName,
  attributes)`  (app/src/Features/Project/ProjectCreationHandler.mjs)

called from `ProjectController.newProject` (UI), `ProjectDuplicator`
(duplicate → new own project), `ProjectUploadManager` (upload → new
project), `TpdsController`/`TpdsUpdateHandler` (external-store sync) →
ONE check in `createBlankProject` (keyed on `user.ssoRoles[providerId]`
+ the session-bound SAML/OIDC providerId recorded at login) covers every
"create own project" path. Audit row `sso-guest-create-denied`.
PermissionsManager kept as fallback if the direct seam turns out
noisier. Env: **no** env knobs — admin-config only (per requirement).

**Admin UI (per SSO provider card):**
- Rows: role (select local/guest/blocked/admin), attribute (text), values
  (comma-separated or multi-value), match (equals/includes/regex),
  caseSensitive (default true). Add / remove / reorder (first-match-wins
  hint).
- Test button: fetch sample claim value, run filter in-memory, return
  match result for given test value (no live assertion needed).
- **Default** when no `attrFilter` rows: **all users are 'local'**.

**Tests (Phase 1 + Phase 2 live, per provider/role/providerId/filter
row/admin-config/login seam):**
- OIDC userinfo claim present + matches `equals` → `role='guest'` →
  `ProjectCreationHandler` (or Permissions) refuses create.
- Assertion attribute present + matches → `role='blocked'` → login
  refused, audit row, redirect (no account).
- No match → default 'local' → create allowed.
- Ordering: `blocked` row above `guest` → `blocked` wins.
- Re-login re-evaluation: admin changes row → next login picks up new
  role.
- Existing accounts: `ssoRoles` subdocument written; no stale
  `ssoRoles` breaks login.

**Risk additions (§5):**
- **G4:** "blocked" row applied retroactively to **existing** users —
  decision: **re-evaluated on next login only**; not enforced
  mid-session (existing `guest`→`blocked` keeps current session until
  logout+login; admin can force via session wipe — documented, not
  automated).
- **G5:** `attrFilter` regex row — no ReDoS guard at first pass; document
  that `values` should be simple regexes; `values` list ≤10 rows per
  default.
- **G6:** OIDC userinfo fetch for userinfo-only claims (e.g. GEANT
  `entitlements`) — extra HTTP call at JIT for `oidc-<id>` rows where the
  filter attribute is NOT in the ID-token; only when required; timeout
  (recon: passport-openidconnect userinfo fetch semantics and token
  availability post-redirect).

## 1 — Three boxes, what talks to whom

| Box | Protocol | Overleaf surface | Multi-IdP? |
|---|---|---|---|
| **eduGAIN / DFN-AAI** (SAML aggregate + DFN metadata set) | SAML2 SP-only | stock SAML module + Shibboleth proxy (N-managed entry) | Proxy fans in; Overleaf sees ONE SAML entity (proxy) |
| **GEANT AAI Service** (eduTEAMS) | OIDC (and SAML) | OIDC module (N-managed entry); `sub` persistent | eduTEAMS fans in eduGAIN+direct OIDC IdPs |
| **Overleaf OIDF** (ours, 00–09) | OIDF | `modules/federation` (peer-Overleaf) | Origin-keyed client assertions |

User-facing: "login with eduGAIN/DFN" = SAML proxy entry (university IdP via
WAYF inside the proxy); "login with GEANT" = OIDC against GEANT service
(entitlements available if needed); OIDF = peer-Overlane login.

## 2 — Option A (SAML via Shibboleth proxy) — app-side

Proxy (Shibboleth-SP, recommended; SimpleSAML php fallback; no existing proxy —
Phase 0 stands one up) configured with eduGAIN/DFN aggregate metadata; Overleaf
configures ONE SAML entry pointing at the proxy:

- `entryPoint` = proxy SSO; `issuer` = proxy `entityID`; `idpCert` = proxy X.509
  (paste, per `fe4ceb6` pattern).
- `attributeConsumingServiceIndex` per proxy ACSS;
  `authnRequestBinding=HTTP-POST` (R&S criterion); `wantAssertionsSigned=1`;
  `identifierFormat` persistent.
- Attributes (verified against GEANT/eduGAIN release): ePPN stable (`attUserId`);
  `givenName`/`sn` display; **no guaranteed `email`** → synthetic-email JIT (R1,
  the one functional app change, §4).
- SP metadata for mdv (SP registration): **our `/saml/meta`** (signed,
  auto-regenerated). DFN criterion: stable signed URL + daily refresh (we
  regenerate on fetch — compliant; *verify* DFN acceptance in Phase 0),
  DisplayName/InformationURL/contactPerson + English (`@node-saml` input
  may need explicit fields — R2).
- CoC/R&S category declaration: GÉANT CoCo v.1 is **deprecated 2026-01-01** per DFN
  doku — use **REFEDS CoC v.2**. Category travels with (a) proxy's metadata
  (as eduGAIN participant) and (b) our own SP metadata, so IdPs see **both**
  the proxy's and our SP's R&S declaration (R3: confirm exact placement with
  DFN/GEANT).

Proxy-side (out of app scope): mdv registration, CoC v.2 declaration, test-IdP
connection (DFN test federation), WAYF/EDS in its own UI.

## 2.5 — Option B (OIDC via GEANT AAI Service) — app-side

GEANT as a third-party OIDC IdP (eduTEAMS proxy+DS+MDS SaaS). N = OIDC entry
with `https://proxy.aai.geant.org` issuer:

- Register at `webapp.aai.geant.org/sp_request` (test env: Sandbox 3-month opt-in;
  `test@aai.geanorgorg` reserved accounts — **do not** grant valuable resources).
- Overleaf OIDC entry (in N framework): `scope='openid aarc profile email'`
  (`aarc` carries the persistent `sub`/voperson_id claim; `profile` name claims
  optional; `email` OPTIONAL → R1 synthetic fallback).
- `attUserId=id` (stock default — keep; `sub` is the identity anchor).
- Entitlements (`urn:geant:aai.geanorgorg:group:...`) via **userinfo**
  `entitlements` scope — not v1 (only needed for group-gated services).
- Production promotion = form completion (privacy URL, AUP, IR policy,
  jurisdiction, CoC/Sirtfi/R&S checkboxes).
- Sandbox enforcement is provider-side (their consent page) — no app code.
- Client-credentials (machine-to-machine groups): **not v1**.
- **SAML leg & SP registration (metadata XML) are now plan 11**
  (11-saml-sp-metadata-and-geant-registration.md) — this is the box that both
  DFN-AAI and GEANT AAI require at submission. The OIDC leg above needs no code;
  plan 11 fixes the SAML `/saml/meta` endpoint and adds GEANT SP registration.

## 3 — Phase plan (v3, decisions locked)

### Phase 0 — Procurement + vendor (no app code)
- [ ] **Provision Shibboleth-SP proxy** (no existing — fresh infra; SimpleSAML
  php fallback), connect to DFN test federation (test IdP); verify ePPN +
  persistent nameID, signed assertions only, HTTP-POST, metadata fetch.
- [ ] **DFN-AAI membership application** (org: technical contact, privacy,
  AUP, IR policy, jurisdiction) for the SAML proxy entity (CoC/R&S category
  travels with the proxy metadata; our own SP metadata gets R&S too, R3).
- [ ] **GEANT AAI test-env registration** (`webapp.aai.geant.org/sp_request`,
  Sandbox group).
- [ ] Confirm R3 (category placement: proxy vs our SP metadata) with DFN/GEANT
  support.
- [ ] Identifier policy: ePPN-only (default) vs ePPN + persistent nameID.

### Phase 1 — Port `fe4ceb6` SSO framework (SSO-only) + N-provider extension
App changes, discrete commits pushed:
- [ ] 3-way merge: `login.pug`, `User.mjs` (if touched), `AuthenticationController.mjs`,
  `mongodb.mjs` (runtime + migrations lib — static-map learning from v1),
  `settings.defaults.js` module list, `modules/authentication/admin/` (SSO
  portion of upstream module, no email admin).
- [ ] `ssoConfigs` key: runtime already after port; add to
  `tools/migrations/lib/mongodb.mjs` static map. Env fallback mode still works
  (loader does this — smoke test both modes).
- [ ] **N-provider extension (§0.7):**
  - `ensureStrategy(id)` in SAML + OIDC modules (lazy registration).
  - `/oidc/login/:providerId` + `/saml/login/:providerId` route dispatch (callback
    unchanged).
  - `getAllEnabledProviders()` in loader.
  - SAML manager drops hardcoded `providerId='1'`.
  - Audit method includes provider id.
- [ ] **Per-provider attribute filters (§0.8):**
  - `attrFilter` rows in `ssoConfigs.providers[i]` (shape per §0.8).
  - Filter eval on login (`equals` / `includes` / `regex`, `caseSensitive`),
    first-match-wins (blocked → guest → admin → local), no-match = local.
  - `user.ssoRoles[providerId]` subdoc (write on login, re-eval on re-login).
  - **Blocked** → refuse login (no session, no account, audit `sso-login-denied`).
  - **Guest** → create-project refused at `ProjectCreationHandler.createBlankProject`
    (verified choke point for new/duplicate/upload/Tpds paths — see
    §0.8); audit row `sso-guest-create-denied`.
  - Admin UI: per-provider rows (role/attribute/values/match/caseSensitive),
    reorder (first-match-wins), test button (in-memory eval for given value),
    masking (no secrets).
  - Env fallback mode defaults `local` (no `attrFilter` on env-mode providers
    for v1).
  - **Recon seams** (record outcomes in recon log before build):
    - passport-saml Strategy `name` option support (v5).
    - passport-oauth2 per-strategy state-store key collision.
    - `passport._strategies` eviction on provider delete.
  - Login buttons derived from `providers[]` (admin orders; add `providerId`
    field to locals).
- [ ] Federation OIDF module (ours) does NOT register a passport strategy
  (provider-side `oidc-provider`) — no collision with stock OIDC strategy
  (verify on port; document).
- [ ] Tests: admin SSO API (save → `ssoConfigs` shape, masked read, reorder,
  test endpoints), loader (DB vs env fallback; `getAllEnabledProviders`),
  login page (dynamic buttons, logo, local-login hide), N dispatch (provider id
  in session; `ensureStrategy` lazy registration; audit method includes id).
- [ ] SSO admin runbook: proxy cert rotation (paste new cert → SSO admin →
  test → no restart needed thanks to lazy registration), mdv submission URL
  (our `/saml/meta`).

### Phase 2 — eduGAIN SAML via proxy (app-side + live)
- [x] **R1 synthetic-email JIT** (SAML + OIDC managers, env-gated) — SHIPPED
  (SESSION 16): SAML + OIDC managers JIT `<userpart>@<domain>` when the
  email is absent and the anchor (eppn / `sub`) is present; SAML flag
  `samlIdentifiers[0].syntheticEmail: true`, OIDC flag merged into the
  thirdPartyIdentifier `externalData` `{ syntheticEmail: true }`; env knobs
  `OVERLEAF_SAML_SYNTHETIC_EMAIL_DOMAIN` / `OVERLEAF_OIDC_SYNTHETIC_EMAIL_DOMAIN`
  (default: `Settings.siteUrl` host); no-anchor + no-email → throw. Tests:
  `modules/authentication/test/unit/r1SyntheticEmail.test.mjs` (8 cases).
  - SAML: `profile[attEmail]` absent + eppn scope present → synth
    `<eppn-userpart>@<OVERLEAF_SAML_SYNTHETIC_EMAIL_DOMAIN>` (default: our
    `siteUrl` host), flag synthetic (e.g. `samlIdentifiers[0].syntheticEmail:
    true`), SAML users unaffected on password reset (already `change-password=false`).
  - OIDC mirror (`email` claim absent + `sub` present).
  - Env knobs: `OVERLEAF_SAML_SYNTHETIC_EMAIL_DOMAIN`,
    `OVERLEAF_OIDC_SYNTHETIC_EMAIL_DOMAIN`.
- [ ] Admin SSO test endpoint extended for SAML (fetch metadata URL, verify
  signature, extract cert — G3).
- [ ] SP metadata: verify `/saml/meta` carries DisplayName/InformationURL/
  contactPerson + English (R2); document as stable URL for mdv.
- [ ] Live: DFN test IdP → Shibboleth proxy → Overleaf login → JIT →
  audit row `SAML login - <providerId>`.
- [ ] SSO admin runbook (cert rotation flow, mdv submission).

### Phase 3 — GEANT AAI OIDC live
- [ ] Register test env; `sub` persistent identity check; `aarc` scope; email-claim
  behavior (optional vs provided) → decide synthetic-email default.
- [ ] Sandbox group flow (provider-side enforcement) — document admin
  runbook.
- [ ] Production promotion checklist (form, CoC/Sirtfi/R&S, jurisdiction).

### Phase 4 — Hardening
- [ ] Cert-expiry alerts (our SP cert, proxy cert) → ops runbook.
- [ ] `FINDINGS.md`/`HANDOFF.md`: "eduGAIN = proxy SAML + GEANT OIDC via SSO
  admin; OIDF peer track unaffected; N-provider extension in place."
- [ ] Audit: `externalAuth='saml'` / `='oidc'` vs federation OIDF users — no
  cross-linking (stock `_doLink` flow is explicit).

## 4 — Code delta (v3)

| Item | Scope | Est. |
|---|---|---|
| Port `fe4ceb6` SSO-only (3-way merge + admin module, no `emailConfigs`) | 8–12 files | ~1 dev-day incl. tests |
| **Per-provider attribute filters (§0.8):** `attrFilter` rows in `ssoConfigs`, `ssoRoles` sub-doc on `User`, admin UI + test button, login-time gate, guest create-refusal seam (recon: `ProjectCreationHandler` vs PermissionsManager) | ssoConfigLoader, SAML/OIDC managers, `User` subdoc, 1 seam file, admin UI | ~1–2 dev-days incl. tests |
| **N-provider extension (§0.7):** `ensureStrategy(id)`, per-provider routes,
  `getAllEnabledProviders()`, SAML manager `providerId`, recon seams | `saml/` + `oidc/`
  modules, managers, loader | ~2–3 dev-days incl. tests |
| R1 synthetic-email JIT (SAML + OIDC manager) | 2 files, ~30 LOC each + env | ~1 hr |
| SAML metadata test endpoint (G3) | admin controller, ~40 LOC | ~1–2 hr |
| R2 SP metadata display fields | `SAMLModuleManager` | ~1 hr |
| Login-page merge (ours vs upstream) | views | — |

**Deferred (Phase 0/2, not implementation-blocking):** persistent-nameID policy
(ePPN-only default); JIT domain-allowlist for eduGAIN users;
"how did this account arrive" audit readout (no UI).

## 5 — Risk register (v3)

| ID | Risk | Mitigation |
|---|---|---|
| — | *(G1 resolved: N-provider extension — §0.7 / Phase 1)* | n/a |
| R1 | No guaranteed `email` from eduGAIN/GEANT | Synthetic-email JIT (Phase 2/3), env-gated |
| R2 | `/saml/meta` may miss DisplayName/InformationURL | Check `@node-saml` `ServiceProviderMetadata` input fields |
| R3 | CoC/R&S category placement unclear (proxy vs our SP) | DFN/GEANT confirmation in Phase 0 |
| G2 | Proxy cert rotation = manual paste | Doc + metadata-check test endpoint (G3); mdv watchlist |
| G3 | `testSAMLProvider` too weak (GET reachability) | Extended: fetch metadata URL, verify signature, extract cert |
| R5 | `sub` (persistent) vs `preferred_username` (revocable) | Keep `attUserId=id`; username is display-only |
| R6 | DFN "metadata daily refresh" criterion vs on-demand generation | Doc: "regenerated on fetch; mdv fetches daily" (*verify* DFN acceptance) |
| R7 | Three auth tracks on one deployment (SAML proxy, GEANT OIDC, OIDF peer) | `externalAuth` distinguishes; link flow explicit; audit row per track |
| R8 | Sandbox/test accounts must not reach prod | GEANT-side sandbox; our allowlist excludes test patterns in prod |
| N1 | `fe4ceb6` merge onto fork (ours has v1 federation + hand-off 11) | 3-way merge plan (Phase 1); smoke env fallback + DB modes |
| N2 | `ssoConfigs` key must land in MIGRATION lib `db` map (v1 static-map learning) | Add `ssoConfigs` to `tools/migrations/lib/mongodb.mjs`; runtime already covered after port. **No `emailConfigs`** (SSO-only) |
| N3 | Passport strategy name collision stock vs ours | Ours uses `oidc-provider` (provider-side, no passport); stock OIDC uses passport `openidconnect` — no expected clash; **verify on port** |
| N4 | passport state-store collision under per-strategy | **CLOSED 2026-09-22:** passport-oauth2 state store key = `sessionKey || 'oauth2:' + hostname(authorizationURL)` (strategy.js:103) — derived from issuer URL, NOT strategy name. Per-provider strategies (different issuers) ⇒ distinct keys, no collision. passport-saml `extce` is per-login session. No action. |
| N5 | *(new)* passport-saml strategy named registration | **CLOSED 2026-09-22:** `super()` in @node-saml/passport-saml strategy.js:28 sets no `.name` (verified at runtime via live probe) ⇒ plain `passport.use('saml-<id>', new SAMLStrategy({options}))` works; per-instance `.name` override available. Eviction via `passport._strategies[id] = undefined` (no public API; `passport.unuse` only clears default-named strategies). |
| G4 | "blocked" row applied retroactively to **existing** users | Re-evaluated on next login only; not enforced mid-session (admin can force via session wipe — documented) |
| G5 | `attrFilter` regex row — no ReDoS guard | Document `values` should be simple; ≤10 rows per default |
| G6 | OIDC userinfo-only claims (e.g. GEANT `entitlements`) | Extra HTTP fetch at JIT only when required; recon: passport-openidconnect profile surface, token availability post-redirect; timeout |

## 6 — LOCKED decisions (2026-09-22)

1. **OIDF peer track KEPT** — for non-eduGAIN/DFN users; plans 00–09 unchanged.
2. **Provider scope: N-OIDC + N-SAML** (design §0.7).
3. **Live targets: DFN-AAI (SAML via proxy) and GEANT AAI (OIDC) — both.**
4. **No existing Shibboleth proxy** — Phase 0 stands one up (Shibboleth-SP;
   SimpleSAMLphp fallback; DFN test IdP first).
5. **Port scope: SSO only** — no `emailConfigs` / `EmailAdmin` port.
6. **Per-provider attribute filters** (§0.8): `attrFilter` rows
   (`role: local|guest|blocked|admin`, attribute, values, match,
   caseSensitive) in `ssoConfigs.providers[i].attrFilter`; role stored in
   `user.ssoRoles[providerId]`, re-evaluated on every login; ordering
   blocked → guest → admin → local, first match wins; no-match default =
   local. Guest = can log in, cannot create own projects (seam in
   `ProjectCreationHandler` or PermissionsManager — recon picks). No env
   knobs — admin-config only.

## 7 — Out of scope (explicit)

- In-app native multi-IdP SAML (metadata aggregation, in-app WAYF).
- OIDF module changes (plans 00–09) — untouched.
- Content-bridge (plan/09) — paused; 2a TODO-39131029 recon still closed,
  not yet resumed.
- Machine-to-machine group management (client-credentials).
- Attribute Authority (AA) project-scoped attrs.

## 8 — References

- DFN-AAI: `dfn-aai-about`, `de:join`, `de:metadata`, `de:attributes`,
  `de:entity_attributes`, `de:nonshib`, `de:certificates`, `de:functionaltest`
  (indexed).
- GEANT AAI: `/home/davrot/edugain` (Confluence HTML + extracted at
  `/tmp/edugain_txt/`).
- Upstream commit: `overleaf-cep@fe4ceb6` ("Initial files", branch `sso`).
- Fork stock modules: `modules/authentication/{saml,oidc,ldap,logout}`
  (verified 2026-09-22).
- Fork OIDF: `modules/federation/plan/00–09` (unaffected).
