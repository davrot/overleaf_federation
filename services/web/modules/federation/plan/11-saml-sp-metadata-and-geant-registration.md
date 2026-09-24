# 11 — SAML SP metadata for GEANT AAI / eduGAIN SP registration (+ GEANT OIDC leg)

> Date: 2026-09-24 (SESSION 16). Status: **draft, recon-only — no code written yet.**
> All facts below verified live this session unless marked (inferred).
>
> Companion to `10-educain-interop.md`:
> - §0 verdict unchanged: eduGAIN/GEANT = university-IdP axis (new SSO
>   providers), OIDF peer-federation (plans 00–09) **untouched**.
> - This plan = the "SP registration" box that both DFN-AAI and GEANT AAI need
>   (metadata URL), plus what the GEANT OIDC leg actually requires.

---

## 1 — Verified state (no assumptions)

### 1.1 Existing endpoints
| What | Where | Fact |
|---|---|---|
| SP metadata | `GET /saml/meta` | **Already exists** — `modules/authentication/saml/app/src/SAMLRouter.mjs:15` → `SAMLAuthenticationController.getSPMetadata`. Not in the federation module. |
| Callback | `POST /saml/login/callback` | `SAMLNonCsrfRouter.mjs` (CSRF-exempt, per-provider via P1b login dispatch). |
| IdP discovery | (GEANT) | `https://proxy.aai.geant.org/metadata/frontend.xml` (prod) / `proxy.acc.aai.geant.org` (acceptance) — fetched live: entityID `https://proxy.aai.geant.org/proxy`, metadata **signed**, SSO bindings Redirect+POST, **no SingleLogoutService published** (so R0 no-SLO is compatible with GEANT as IdP). |

### 1.2 What `/saml/meta` does **today** (source + exact library repro; no live instance call yet)
Repro executed this session (node-saml v5.1.0, our node_modules):
```js
const xml = saml.generateServiceProviderMetadata(
  { decryptionCert: undefined, publicCert: undefined },   // ← the controller's actual first arg
  (err, xm) => {}                                          // ← and its dead 2nd arg (callback, v4 style)
)
// typeof xml === 'string'  →  endpoint DOES answer (callback is dead code, not a hang)
// entityID === '<options.issuer>' ; 0 <KeyDescriptor>; 0 Organization/ContactPerson
```
- **BUG 1 (wrong entityID)**: strategy `options.issuer` = `provider.issuer` (the
  *IdP's* issuer, `buildStrategyOptions`) → metadata `entityID = <IdP issuer>`.
  A registry (DFN AA / GEANT eduTEAMS MDS) registers *our* SP; the SP identifier
  must be ours (e.g. `<siteUrl>/saml`), not the IdP's.
- **BUG 2 (not registrable)**: no `<Organization>`, no `<ContactPerson>` (repro) —
  eduGain/REFEDS MDV ingestion requires organization + contact + signed
  metadata (REFEDS MDS policy).
- **BUG 3 (unsigned)**: no SP signing keypath is wired (provider row holds only
  `idpCert`, the IdP cert we trust — not a key we hold; and per BUG 4 the cert-
  override args are not even delivered).
- **BUG 4 (arg shape)**: controller passes `publicCert` inside the first-arg
  object; v5 expects `(decryptionCert, publicCerts)` as separate args → the
  DB/env cert override is silently ignored.
- **BUG 5 (500 when SAML disabled)**: `ensureStrategy` may register nothing →
  handler dereferences `samlStratery._saml.options.issuer` → TypeError/500
  instead of a graceful “SAML not enabled” response.
- `Content-Type: application/xml; charset=utf-8` from the shared `xmlResponse`
  helper (`app/src/infrastructure/Response.mjs`); Shibboleth MDS convention is
  `application/saml-metadata+xml` (change on the meta endpoint only).
- `ssoConfigs` is a raw `db.ssoConfigs` findOne (`ssoConfigLoader.mjs`) — **no
  mongoose model constrains it** (`models/SSOConfig.mjs` exists but the loader
  does not use it) → an `spMetadata` subdoc can be added freely,
  **no migration**.

### 1.3 GEANT-side verification (live this session)
- OIDC discovery (OIDC leg, no new code — plan 10 §0.7 N-provider row):
  issuer `https://proxy.aai.geant.org`, endpoints `/OIDC/authorization`,
  `/OIDC/token`, `/OIDC/userinfo`; scopes `openid, profile, email, aarc,
  voperson_id, ...`; claims incl. `sub, email, preferred_username, name,
  given_name, voperson_id`. **No `jwks` in well-known** (verified: absent) →
  IdP key discovery goes through the OP's JWKS URL *if* supplied later;
  passport-openidconnect in v1 uses the `jwks-uri` claim **only if** we add it —
  needs a live handshake to confirm where GEANT publishes keys (open item I2).
- SAML front (SP-side registration target): the GEANT "connect a service" form
  (fetched doc "How to connect a new service to the Geant AAI Service"):
  - **SAML SP form fields**: Service Description; contacts (admin/sec/helpdesk/
    technical); Privacy Notice URL; AUP/ToU URL; Incident Response (optional);
    Jurisdiction; CoC ✓; Sirtfi ✓; R&S ✓; **then either "SP is part of eduGAIN"
    + SAML2 Entity ID, OR "SAML2 Metadata (URL)"** (the one we must serve).
  - **Attribute selection step**: required attributes + justification (eppn,
    email, name — per "Attributes available to Connected Services": mandatory
    `User Identifier`, `Username`, `Display Name`; optional given/family
    (fetched doc).
  - **OIDC RP form (alt leg)**: grants, public client, PKCE, redirect URLs —
    no metadata, no form-hosted metadata URL; client_id/secret issued at
    submission. (Alt path if we go OIDC-only vs GEANT.)
- GEANT test env first (Sandbox group opt-in), then promotion to production —
  both per fetched doc. No code-side env difference; only client/SP ids differ.

---

## 2 — Design (code, all under `authentication/saml` — not the federation module)

One endpoint, one edit path. No new module, no migration, no env vars.

### 2.1 `GET /saml/meta` — v3 metadata (fixes §1.2 gaps)
Build XML with **node-saml v5 `generateServiceProviderMetadata` directly**
(stop going through the strategy — strategy options are IdP-direction; the SP
identity is orthogonal to the IdP):

````
params = {
  issuer:                spEntityId,            // <our> SP identifier (below)
  callbackUrl:           `${siteUrl}/saml/login/callback`,
  logoutCallbackUrl:     `${siteUrl}/saml/logout/callback`,
  metadataOrganization:  spMetadata.organization,   // { name, displayName, url } (admin)
  metadataContactPerson: [ spMetadata.contacts... ],// [{ contactType, email }]
  signMetadata:          !!spMetadata?.privateKey,  // sign IFF a PEM is present
  privateKey:            spMetadata?.privateKey,    // PEM, masked on read
}
```
- **Signing rule** (resolves §4 R2 default): `signMetadata = !!privateKey` —
  the endpoint **always signs when a SP key is configured**, never signs
  without one. No separate `signMetadata` flag in `spMetadata` (one key, one
  behaviour).

- **SP entity ID** (`spEntityId`): a stable *per-deployment* URL. Precedence:
  1. `ssoConfigs.spMetadata.spEntityId` (admin-set; **not** a secret — shown in GET)
  2. fallback: `${siteOrigin}` + `/saml` (documented default)
  Decision: **per-deployment URL, not per-provider** — the registry registers the
  *service*, and the same SP fronts N providers (plan 10 §0.7).
- **SLO**: `logoutCallbackUrl: ${siteUrl}/saml/logout/callback` IS advertised —
  the SAML module already runs `POST /saml/logout/callback` (fe4ceb6 port);
  v5 emits `<SingleLogoutService>` when this param is set (verified) → keep it.
  GEANT's *IdP* metadata publishes no SLO (verified on `frontend.xml`) — that
  only affects IdP-initiated logout, which we don't need.
- **Key**: signing is a v1 toggle — `spMetadata.privateKey` (PEM) drives
  `signMetadata: !!privateKey` (always signed when a key is present;
  REFEDS/eduGAIN MDV publication requires signed metadata — confirm the exact
  enforcement at submission; flag R2).
- Return `Content-Type: application/saml-metadata+xml; charset=utf-8`
  (new local header; do not alter `xmlResponse` for other consumers — SAML
  responses use the same helper; add a `res.setHeader` before `res.send`).
- The strategy (IdP direction) is **untouched**: `buildStrategyOptions`/
  `ensureStrategy` unchanged. This endpoint is **SP metadata** only.

### 2.2 `ssoConfigs.spMetadata` (raw doc, no migration)
```jsonc
spMetadata: {                 // new subdoc on the same 'sso-settings' doc
  spEntityId:     string,     // optional; default = siteUrl origin + '/saml'
  organization:   { name, displayName, url },   // required for registries
  contacts:       [ { contactType: 'technical', email }, ... ],
  privateKey?:    string,     // PEM — **masked** in all admin GET responses
                              //   presence ⇒ signMetadata (no separate flag)
}
```
Admin: one PUT `spMetadata` route in the SSO admin module
(`SSOAdminController` — add `saveSAMLSPMetadata` + `testMetadata` (re-emit
XML for eyeballing before submission)). GET read: masked (reuse the existing
provider-masking path in the admin router).

### 2.3 What changes, what doesn't
| Change | File | Notes |
|---|---|---|
| SP metadata generation (v3 params) | `authentication/saml/app/src/SAMLAuthenticationController.mjs` | rewrite `getSPMetadata`: call the v5 **direct** `@node-saml/node-saml` `generateServiceProviderMetadata(params)` (synchronous, returns string) — own SP entityID, `metadataOrganization` + `metadataContactPerson`, `signMetadata: true` + `privateKey` (PEM) when present, `Content-Type: application/saml-metadata+xml`; graceful “SAML not enabled” response; keep route path `/saml/meta` |
| Content-Type | same | `application/saml-metadata+xml` |
| SP metadata config + admin route | `authentication/admin/...` (SSOAdminController + Router + pug row) | PUT `spMetadata`, masked GET |
| No change | `buildStrategyOptions`, login dispatch, federation module (00–09), migrations, env defaults | IdP direction and OIDF stay byte-identical |
| New (tests) | `authentication/test/` metadata unit test (own entityID; org+contacts present; signed when key; unsigned fallback) + admin route test | |

No new SSOConfig schema fields (loader is raw `db.ssoConfigs`). No env keys.

---

## 3 — External (operator, no code)
1. GEANT SAML SP registration form (test env first, Sandbox opt-in, then
   production) — fill the §1.3 fields (org, contacts, URLs, jurisdiction,
   checkboxes), metadata URL = our `/saml/meta`.
2. DFN-AAI test IdP / MDV registration (dfn.de) if the SAML leg goes DFN
   first — same metadata, different registry.
3. (Alt) GEANT OIDC RP registration if we prefer the OIDC leg — form issues
   client_id/secret; then one `type:'oidc'` provider row via SSO admin
   (plan 10 §0.7, already built). No metadata.

## 4 — Open items (to close before submission)
- **I2**: where GEANT publishes OIDC IdP keys (well-known had no `jwks`) —
  live handshake needed; if absent we may need a JWKS URL from GEANT support.
- **R2 (operator, open)**: metadata signature requirement — eduGAIN MDV/REFEDS
  MDS publication requires **signed** metadata (inferred from REFEDS MDS policy,
  NOT verified against GEANT MDS behaviour) → implement `signMetadata: true`
  + `spMetadata.privateKey` PEM pair support; decide before submission.
- **I1**: attribute policy — which attrs we require (eppn mandatory) and the
  per-provider `attrFilter` (plan 10 §0.8) role mappings (local vs guest) —
  decisions needed at submission (not code).

## 5 — Cross-refs
- plan 10 §0 (verdict), §0.7 (N-provider), §0.8 (attrFilter), §2/§2.5 (SAML /
  OIDC legs), Phase 0/2 (provisioning, DFN-live), R1 (synthetic-email JIT).
- v1 identity-federation goals `3ea7bb53` / `3dad1c9e` (content) — **not**
  affected by this plan (different axis; OIDF module untouched).
