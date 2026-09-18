# overleaf-cep Integration — `services/web/modules/federation/` (v2)

A single WebModule (the overleaf-cep module contract
`services/web/types/web-module.ts`: `{ dependencies, router, nonCsrfRouter,
hooks, middleware, sessionMiddleware, appMiddleware, start }`) at
`services/web/modules/federation/index.mjs`. Grounding references:
`modules/git-bridge/` (the "external-protocol module" shape we follow)
and `modules/authentication/saml/index.mjs` +
`modules/authentication/saml/app/src/SAMLNonCsrfRouter.mjs` (the
`nonCsrfRouter` pattern for cross-origin POSTs that `Csrf.blockCrossOriginRequests()`
(`app/src/infrastructure/Server.mjs:157`) would otherwise block).

The existing enterprise-SSO OIDC **client** module
(`modules/authentication/oidc/index.mjs`, built on `passport` +
`passport-openidconnect` with a *server-side* client secret) is **not**
reused for federation grants: federation grants use a *public* OIDC
client with PKCE, and A's verification uses plain `fetch` + the existing
top-level `jose` (05 §3). No OIDC *client* library is added.
Trust-layer deps (new, OIDF 1.0 — `02-trust-model-oidf.md` is the
authority): `@oidfed/core`, `@oidfed/oidc`, `@oidfed/leaf`.

## 1. Module layout

```
services/web/modules/federation/
  index.mjs                        # WebModule default export
  start.mjs                        # appMiddleware: mount leaf, provider, s2s, admin, jwks
  oidc/
    createProvider.mjs             # oidc-provider v9 instance (B = OP role, §8)
    RedisOidcProviderAdapter.mjs   # 7-method factory (04 §5, §8.2)
    bridge.mjs                     # interaction bridge (login + consent, §8.3)
    signingKeys.mjs                # oidc-provider keystore (OIDC signing key, §4 of 02)
  oidf/
    leaf.mjs                       # @oidfed/leaf handler mount (02 §2)
    registration.mjs               # explicit-registration handler + onRegistration (02 §4)
    keystore.mjs                   # FederationKeyLifecycleProvider impl (02 §5)
    anchors.mjs                    # trust-anchor set: pairwise rows (04 §2) + institutional file
    verify.mjs                     # client-assertion verify + ReplayStore (03 §2–3)
  s2s/
    S2sRouter.mjs                  # nonCsrfRouter: POST /federation/s2s (03 §8)
    actions/
      authorizeInvite.mjs          # B-is-oracle approval (03 §4.1)
      invited.mjs                  # read-only preview (03 §4.2)
      revoke.mjs                   # trust revocation (03 §4.3)
  rp/
    CodeExchange.mjs               # fetch + jose id_token verification (§3.2)
    CallbackRouter.mjs             # GET /federation/oidc/rp/callback (CSRF-exempt path)
  admin/
    FederationAdminController.mjs  # peer list, approve/deny/revoke, key rotate, anchor pin
    AdminRouter.mjs                # mounted on the existing AdminController area
  invite/
    FederatedInviteController.mjs  # tuple parse (display split on last colon, 04 §1)
    FederatedInviteRouter.mjs      # GET /federation/invite/preview, POST …/authorize
  invitee/
    FederatedSessionManager.mjs    # grant → local express-session (the "opener", 01 §5)
  util/
    Anchor.mjs                     # display (de)serialization: tuple <-> 'local:origin'
    RateLimitStore.mjs             # 04 §6 Redis budgets
    Audit.mjs                      # ProjectAuditLogEntry wrappers (04 §8)
    Redact.mjs                     # log redaction (06 §6)
  views/
    consent.html.ejs               # B-side: "Allow <peer> to see <claims>?"
```

### 1.1 `index.mjs`

```js
const mod = {
  name: 'federation',
  dependencies: [/* none */],
  hooks: {
    // passport untouched: federated rows get a normal express-session,
    // so there is no new passport strategy (v1 stub deleted).
  },
  nonCsrfRouter: {
    // ALL fed routes live here: it is mounted on webRouter AFTER
    // webRouter.use(session(...)) (Server.mjs:186), so req.session is
    // available on every route, including the OIDC interaction bridge.
    mount: (router) => {
      /* MOUNT ORDER MATTERS (§8.1):
           1. leaf route          GET /.well-known/openid-federation
           2. S2sRouter           POST /federation/s2s
           3. interaction bridge  GET  /federation/oidc/interact/:uid
                                 POST /federation/oidc/interact/:uid/consent
           4. provider.callback()  mounted at /federation/oidc (terminal)
      */
    },
  },
  // (WebModule contract: `start` takes NO arguments — app.mjs:126
  //  `await module.start?.()`; the Express app is not passed.)
  start: async () => {
    /* key-material bootstrap (02 §5 federation keystore + OIDC-signing
       keystore), one-time before listen. Note: the Provider instance and
       its clients[] are built inside the nonCsrfRouter mount (§8.6),
       because they must be constructed after Settings + Mongoose are ready
       and the mount runs post-DB-connect. */
  },
}
```

The SAML module is the *only* working in-repo pattern for "mount a
router that is NOT subject to the session middleware chain"; copy it.
The type surface is unchanged (§6: `types/web-module.ts` untouched).

## 2. B = OP role: `oidc-provider` v9.12.2 instance

Authority: **§8 of this file** (verified against the `v9.12.2` source,
`federation/node-oidc-provider`; if §2 disagrees with §8, §8 wins).
Summary of the creation shape (full config in §8.6):

```
const provider = new Provider(`${Settings.siteUrl}/federation/oidc`, setup)
// setup: { adapter /* §8.2 factory */, clients /* 04 §7 boot reconstruction */,
//   claims / findAccount /* §8.5 */, interactions.url /* bridge §8.3 */,
//   loadExistingGrant /* §8.4 */, subjectTypes: ['public'],
//   ttl { AuthorizationCode: 120, Grant: 30d, Interaction: 600 },
//   features.devInteractions.enabled: false, cors (origin-allow),
//   jwks: { keys: <OIDC signing key keystore> /* §8.6 */ } }
app.use('/federation/oidc', provider.callback())   // terminal
```

### 2.1 Login + consent = the interaction bridge (§8.3)

v9 has **no** `interact:` config and **no** `provider.interact()`.
Interaction is driven by `interactions.url` + `interactionDetails` /
`interactionFinished` on raw `(req, res)` — the bridge mounts at
`GET /federation/oidc/interact/:uid` and
`POST /federation/oidc/interact/:uid/consent`, *before* `callback()`,
reads `req.session.user` (B's overleaf session) and auto-answers the
login step when present; consent is rendered with a single sentence
plus a default-on "remember the choice" checkbox that persists the
Grant (`provider.Grant`, `addOIDCScope`/`addOIDCClaims`, §8.3/§8.4).

### 2.2 Client resolution = boot-time `clients[]` reconstruction (§8.8)

There is **no** `findClient` hook in v9 and no `urn:` adapter lookup.
`clients[]` is rebuilt at boot from approved `FederationPeer` rows
(04 §7); each entry is a public client
(`token_endpoint_auth_method: 'none'`, PKCE) whose `client_id` is the
deterministic `urn:overleaf-federation:client:<peers-origin>`.
"Is peer X approved on this machine?" is therefore answered by the
OIDC engine itself (`400 invalid_client` otherwise); the grant is the
*identity* approval (B's user, at consent), and the S2S
`authorize-invite` (03 §4.1) is the *invite* approval (A's owner) —
two independent gates that compose (01 §5 steps 1–4).

## 3. A = RP role: no client library — `fetch` + `jose`

A's RP role needs exactly three things: a PKCE verifier store, a token
exchange, and id_token verification. **No OIDC client library is
added** (the v1 plan's `openidconnect-client` dependency is dropped):
all three are ≤30 lines with the existing top-level `jose`.

### 3.1 PKCE + state store (A-side)

- On "Open on B": generate `verifier` (32 B `crypto.randomBytes`,
  base64url) and `challenge = S256(verifier)`; persist `state` +
  `verifier` + intent `{projectId, privileges, nonce, origin, localName,
  url}` in A's express-session **and** a short Redis backup
  (`federation:invite-cache:...` pattern, 04 §6, TTL 120 s — survives
  cookie expiry across tabs).
- `state` payload: HMAC-signed JSON over `Settings.sessionSecrets[1]`
  (04 §6) — a forged `state` cannot mint a mirror account.
- Redirect (01 §5 step 3) includes `state`, `code_challenge` +
  `code_challenge_method=S256`; `client_id` is A's deterministic URN
  (04 §7), no secret.

### 3.2 `CodeExchange.mjs` (fetch + jose v4)

```js
import { jwtVerify } from 'jose'   // repo-top-level jose, v4.15.5 (existing dep, NOT a new one)

async function exchange(peerOrigin, { code, codeVerifier, state, intent }) {
  const jwks = await fetchJwksWithCache(peerOrigin)       // 04 §6: f:oidc-jwks:<origin>, 1 h
  const tokenResp = await fetch(`https://${peerOrigin}/federation/oidc/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: `urn:overleaf-federation:client:${Settings.siteUrl}`,
      code,
      code_verifier: codeVerifier,
    }),
  }).then(r => r.json())
  if (!tokenResp.id_token) throw new Error('exchange-failed') // audit, 04 §8
  const key = await resolveJwk(jwks, tokenResp.id_token)      // by kid, ES256
  const { payload: claims } = await jwtVerify(tokenResp.id_token, key, {   // JWK object works
      audience: `urn:overleaf-federation:client:${Settings.siteUrl}`,
      issuer: `https://${peerOrigin}/federation/oidc`,
  })
  if (claims.origin !== peerOrigin)                    // identity-mismatch (06 §3)
    throw new Error('identity-mismatch')
  if (claims.nonce !== intent.nonce)                    // state replay (01 §5 step 3)
    throw new Error('state-mismatch')
  if (claims.localName !== intent.localName)            // invite not honoured
    throw new Error('identity-mismatch')
  return claims
}
```

The id_token is verified against oidc-provider's **provider** JWKS
(the v9 mount's `/.well-known/jwks`, 01 §6 item 3), *not* the leaf —
because oidc-provider signs tokens with its own OIDC-signing keystore
(§8.6), distinct from the federation key (02 §4).

### 3.3 `CallbackRouter.mjs`

`GET /federation/oidc/rp/callback?code=…&state=…` — a GET redirect into
A's express router (mounted via `applyNonCsrfRouter`; CSRF is a *POST*
guard, a GET landing is not cross-origin-form, so no carve-out is
needed). The router: (1) reads + **deletes** the single-use verifier
(session row first, Redis backup fallback), (2) verifies `state` HMAC +
`nonce`, (3) calls §3.2, (4) resolves the mirror row
(`User.findOne({ 'federation.origin': X, 'federation.localName': Y })`,
auto-create per 04 §1), (5) applies `intent.privileges` via
`PermissionsService` (04 §3 ceiling), (6) sets the normal
express-session (`overleaf.sid`) with `session.user` — and 302s to
`intent.url` (project URL). **The grant is an opener, not a session**
(01 §5 step 8, 06 §2).

### 3.4 Key + secret invariants (A-side)

- **No client secret** anywhere (public client, PKCE).
- No grant secret in URLs beyond the 302 hop (code) and the 120 s
  code TTL (01 §8.1); `state` is the HMAC-signed *intent*, never a
  secret that outlives the open.
- Re-login after a lapsed session is silent (01 §5 step 9): the B-side
  Grant for `(accountId, client_id)` matches via `loadExistingGrant`
  (§8.4) and no consent screen is shown.


## 4. Frontend (v1)

Three UI pieces + one admin surface, all standard overleaf-cep React (no new
framework, no new build steps):

1. **Invite field** (owner enters the federated identity):
   The existing collaborator-invite form gains a "Federation user" toggle with
   a placeholder `name:origin`. On blur, the client:
   - splits on the **last** colon,
   - resolves `peer.origin` against the approved peer list (a small
     read-only admin-area API: `GET /api/federation/peers?approved=true`),
   - on valid: shows a `invited`-style preview (displayName + avatar) via
     `POST /api/federation/invite/preview`
     (server→peer S2S `invited`, 60 s cache),
   - on invalid: inline error ("unknown peer or identity").
   Saves as a `ProjectInvite` row with `federated: true` (02 §3).

2. **"Open on <peer>" button** (owner triggers the grant):
   Rendered on any project where
   (a) the viewer has collaborator permission,
   (b) a federated invite exists for the selected peer,
   (c) peer is `approved`.
   On click, the server:
   - builds the OIDC authorization redirect
     scope: `openid`, `state`, `code_challenge` (01 §5, custom id_token
     claims — no `profile` scope),
   - stores the PKCE `verifier` in the session + Redis backup (05 §3.1),
   - 302s to `https://<B>/federation/oidc/auth?…`.
   The button itself does **no** content fetch; it is a pure
   identity redirect.

3. **"Signed in as <home identity>" banner** (partner-visitor UX):
   Shown when `User.federation.origin` is present on the session's user
   row (mirrors carry no `kind`; subdoc presence is the mark, 04 §1). Purely cosmetic —
   the session is otherwise indistinguishable from a local one
   (which is the security property: no special "federated" code
   path in the editor). Disappears on the next normal login.

4. **Admin "Federation" tab**: peer list, approve/deny/revoke (trust
   approval: pin for pairwise, registration for institutional, 04 §2),
   key rotation (federation key + OIDC signing key, separate, 02 §5/§8.6),
   key rotation (federation key + OIDC signing key, separate, 02 §5/§8.6),
   audit log. Standard `AdminController` layout.

## 5. Audit log (04 §8 is the authority)

Reuses overleaf-cep's existing `ProjectAuditLogEntry` model
(`models/ProjectAuditLogEntry.mjs`); adds `federated_*` types (04 §8
list, v2). No content audit (there is no content transfer; see 01 §1).

## 6. Type surface (what we actually change in overleaf-cep)

| File | Change | Nature |
|------|--------|--------|
| `services/web/modules/federation/**` | *new* module (this file, §1) | new |
| `services/web/app/src/models/User.mjs` | + `federation: { origin, localName, federatedAt }` (04 §1; presence = mirror) | additive |
| `services/web/app/src/models/ProjectInvite.mjs` | + `federated, origin, localName, localNameHash, privileges, authorized, authorizedAt` (04 §3) | additive |
| `services/web/app/src/models/FederationPeer.mjs` | *new* model (02 §2) | new |
| `services/web/app/src/models/ProjectAuditLogEntry.mjs` | + 4 type values (02 §8) | additive |
| `services/web/app/src/Features/Authentication/SignUpController.mjs` | reject `:` in email (01 §3.3) | additive |
| `services/web/app/src/Features/Authentication/AuthenticationManager.mjs` | refuse federated-role actions (reset, email change, SSO enroll) | additive |
| `services/web/app/src/Services/Authentication/AuthenticationManager.mjs` | (if separate) — same check | additive |
| `services/web/app/src/infrastructure/Server.mjs` | **no change** required (federation mounts via `appMiddleware`) | — |
| `services/web/types/web-module.ts` | **no change** (module uses only existing `nonCsrfRouter` + `appMiddleware` + `start` interfaces) | — |
| `services/web/config/settings.defaults.js` | + `federation: { enabled, allowFederatedProjectCreate, requireAdminApproval, keyRotationGraceDays, keystores: { federationPath, oidcKeyId }, institutionalAnchorFile: <admin-mnt path> }` (Settings below) | additive |
| `services/web/package.json` | + `oidc-provider@v9.12.2` (new dep for B = OP/IdP role) + the three OIDF packages `@oidfed/core`, `@oidfed/oidc`, `@oidfed/leaf` (trust layer, 02 §1). **No OIDC *client* library** for A = RP role: that role uses `fetch` + the *existing* top-level `jose` dep (§3). `passport-openidconnect` (existing, enterprise SSO) is a different engine and is **not** reused for federation grants. | two new dep families, each single-purpose |
The following are **untouched** (this is the payoff of the identity model —
federation is a single new HTTP surface (S2S + OIDC) rather than a content pipeline):

- `services/real-time/**` — real-time editor service (the visitor
  edits with the *local* editor stack on their current machine).
- `services/linked-url-proxy/**` — linked-URL proxy (no cross-origin
  URL proxy in federated projects; all URLs are local).
- `modules/git-bridge/**` — git-sync settings never leave the machine
  (01 §8.3 deny-list, 02 §4).
- `modules/zotero/**` — Zotero credentials (deny-list).
- Compile-settings module — (deny-list).
- `services/web/app/src/infrastructure/Server.mjs` — untouched; the
  federation module attaches via `appMiddleware` (standard WebModule
  mechanism, `types/web-module.ts`).

## 7. `Settings` additions (`config/settings.defaults.js`)

```js
federation: {
  enabled: false,                     // master toggle per instance
  allowFederatedProjectCreate: false, // partner-side: allow mirrors to create
                                       //   projects (01 §3.4). Default OFF.
  requireAdminApproval: true,         // B-side: approve received pins
                                       //   (pairwise) / registration
                                       //   statements (institutional, P3).
                                       //   Default ON (v1).
  keyRotationGraceDays: 14,           // federation key retire window (02 §5):
                                       //   must exceed max live statement lifetime
  federationKeystorePath: null,       // PEM for the federation ES256 key
                                       //   (auto-gen + persist on first boot,
                                       //   02 §5 keystore)
  oidcSigningKeyId: null,             // kid for the OIDC-signing key set
                                       //   (05 §8.6; separate set, 02 §4)
  // Institutional anchors: a (read-only) PEM file or pasted anchor JWKS
  // mounted out-of-band, e.g. DFN-CERT (02 §6). The pairwise depth-1 anchors
  // are per-peer and live in FederationPeer.anchorJwks — not here.
  institutionalAnchorPath: null,
  // NOT configured here (deliberately, "not over-cross"): no cross-instance
  // sync of local settings; no per-peer claim policy (claim sharing is a
  // per-B-admin local policy: claim allow-list per peer, 05 §8.5);
  // keys are always local.
}
```

All three fields are instance-local; no federation setting is shared.
The *admin* UI (§6) edits these per machine.

## 8. oidc-provider **v9.12.2** grounding contract (read-first reference)

This section is the authority for §2, §3, and ``04-data-model.md` §5–§7. Every
API name, constructor shape, and config key below was verified against the
actual **v9.12.2** source (`panva/node-oidc-provider` at tag `v9.12.2`, local
clone at `federation/node-oidc-provider`), not the v8-era README. If §2–§3
below disagree with this section, **this section wins** — rewrite that section.

Dependency (the **only** new npm package for the IdP role):

```bash
yarn add oidc-provider      # package v9.12.2
# its own node_modules resolve bundled deps: koa ^3.2.1, jose ^6.2.12, keygrip,
# object-assign, etc. — we do NOT import koa or jose from them; we use the
# overleaf-cep top-level jose (existing) for all RP-side verification (§3).
```

### 8.1 Constructor and mount — `new Provider(issuer, setup)`

`lib/index.js` exports:

```js
import Provider, { errors, interactionPolicy, Provider as Nom } from 'oidc-provider'
import { ExternalSigningKey } from 'oidc-provider' // lib/helpers/keystore.js re-export
// errors: { SessionNotFound, ... } — the error classes thrown by interactionDetails().
```

`lib/provider.js` constructor is `(issuer, setup)` — **two arguments**, no
`app` argument (v9's Provider **is** the Koa app; the `.app` getter is
deprecated and returns `this`):

```js
const provider = new Provider(`${Settings.siteUrl}/federation/oidc`, setup)
```

Mount (per `example/express.js`, the pattern we copy):

```js
app.use('/federation/oidc', provider.callback())
```

`provider.callback()` is inherited from the bundled Koa 3.2.1
(`koa/lib/application.js:182`): it is a **terminal** `(req, res) => ...`
handler — it runs the provider's internal Koa middleware chain and
responds itself. Express's `app.use(path, fn)` strips the prefix from
`req.url` before passing it in, and v9 derives its mount path from the
issuer URL (`lib/provider.js:153`, `#mountPath` from
`new URL(issuer).pathname`) — so with `issuer = <siteUrl>/federation/oidc`
the internal router matches the stripped relative paths (`/auth`, `/token`,
`/jwks`, ...). The cookie-path scoping in
`lib/actions/authorization/interactions.js:145-149` derives the mount path
from `ctx.req.originalUrl.indexOf(ctx.req.url)`, so `Path:` scoping of the
provider cookies works automatically. `interactionDetails(req, res)`
(`lib/provider.js:255`) and `interactionFinished(req, res, ...)`
(`:242`) also accept **raw** `(req, res)` pairs (they call
`this.createContext(req, res)` internally) — that is what lets the bridge
in 02 §5.2 run from inside the Express world without a Koa context.

Because `callback()` is terminal, the mount order in `start.mjs` is
**provider mount first**; anything on the same prefix must be mounted
**before** it (the interaction bridge, §8.3) so Express dispatches the
bridge routes first and lets the provider own the rest of `/federation/oidc/*`.
Provider-internal routes (all relative to the mount):

```
GET  /federation/oidc/.well-known/openid-configuration
GET  /federation/oidc/auth              (authorization)
GET  /federation/oidc/auth/:uid          (resume after interaction)
POST /federation/oidc/token
GET  /federation/oidc/jwks
GET  /federation/oidc/me                 (userinfo)
POST /federation/oidc/session/end
POST /federation/oidc/token/revocation
```

No collision with the existing enterprise-SSO OIDC module
(`modules/authentication/oidc/`, routes under `/oidc/*`, see `OIDCRouter.mjs`)—
the namespaces are prefix-disjoint.

### 8.2 Adapter contract (v9) — factory + 7 methods, **no transactions**

`lib/helpers/initialize_adapter.js` accepts either a **constructor** or a
**factory function** `(modelName) => adapterInstance`; the factory receives
the model name: `'Client' | 'Grant' | 'Session' | 'Interaction' |` any
token model name (see `lib/models/base_model.js:19-31` and
`lib/models/client.js:405`, which both instantiate per-model via
`instance(provider).Adapter` cache). There is **no** `transaction()`,
`findModel`, or `keyForValue` in the v9 surface — the 7 methods are
(`lib/adapters/memory_adapter.js` is the reference shape):

```js
class RedisOidcAdapter {
  // modelName ∈ ['Client','Grant','Session','Interaction',
  //              'AccessToken','AuthorizationCode','IdToken', ...]
  constructor(modelName) { this.modelName = modelName }

  async find(id)                    // JSON doc or undefined
  async findByUid(uid)              // Session-only (the `uid` = sub-index); undefined ok
  async findByUserCode(userCode)    // CIBA-only; return undefined (we don't use CIBA)
  async upsert(id, payload, expiresIn)   // expiresIn in SECONDS; SET key JSON EX expiresIn
  async revokeByGrantId(grantId)    // delete all tokens holding grantId (02 §7.5 cascade)
  async destroy(id)                 // DELETE key
  async consume(id)                 // single-use: GET id, delete and return { ...payload, consumed: true }
}
export default function (modelName) { return new RedisOidcAdapter(modelName) }
```

`upsert(id, payload, expiresIn)` is the **only** persistence point —
`base_model.js:90`; `revokeByGrantId` is the revocation cascade used by
token revocation and S2S `revoke`; `consume(id)` is how the
authorization-code single-use is enforced (01 §8.1 "Grant is a secret").
The secondary index `sessionUid:<uid>` (see
`lib/adapters/memory_adapter.js:67,117,137`) is the one extra key we must
maintain in Redis for `findByUid`:

```
federation:oidc:sub:<uid>            -> adapter model id     (Session only)
federation:oidc:grant:<grantId>      -> Set<token ids>       (revokeByGrantId index)
federation:oidc:<model>:<id>         -> doc { id, value, exp }
```

02 §5 must be rewritten against this 7-method contract; the v8-era
"`adapter.transaction` no-op / `findModel` / `WITHWATCH`" paragraph is
obsolete.

### 8.3 The interaction bridge (login + consent on the overleaf session)

v9 has **no** `provider.interact()` method and **no** `interact:` config.
Interaction is driven through `interactions.url` (a function returning the
redirect URL, `lib/helpers/defaults.js:3351`) plus the two public methods
below. `lib/actions/authorization/interactions.js:100-155` shows the exact
sequence the bridge endpoints must mirror: the provider sets cookie
`_interaction` (name from `cookies.names.interaction`) + `_interaction_resume`
and 303s to `interactionUrl(ctx, interaction)` — **we override** `interactions.url`
to point at our own Express routes:

```js
// createProvider.mjs
interactions: {
  url: async (ctx, interaction) => `/${interaction.uid}`,   // relative —
  // oidc-provider prepends issuer-origin on redirect; the bridge
  // route GET /federation/oidc/interact/:uid is mounted BEFORE callback().
}
```

Bridge (02 §5.2, the B-side session that reads `req.session` from the
overleaf express-session — **the overleaf session is the B-side login
source**; oidc-provider has no login UI of its own in this design):

```js
// bridge.mjs — mounted BEFORE provider.callback() (start.mjs order)

router.get('/federation/oidc/interact/:uid', async (req, res) => {
  const interaction = await provider.interactionDetails(req, res) // raw req/res OK
  // interaction.prompt.name === 'login' | 'consent'  (base() policy)
  // interaction.details:  { name, reasons, details }  (per-policy)
  // interaction.params:   { client_id, redirect_uri, scope, ... }
  // interaction.session:  { accountId, ... }          (may be absent)
  // interaction.returnTo: '/federation/oidc/auth/<interaction uid>'
  if (req.session?.user) {           // overleaf B-login already present → no screen
    // login result: accountId must be the B User._id for that session user
    return provider.interactionFinished(req, res, { login: { accountId: req.session.user._id } })
  }
  // else: redirect to B's normal /login?backto=<resume-url>
  //       (AuthenticationManager.login path; on return the bridge re-fires
  //        and this time req.session.user exists → same finished() call)
})

router.post('/federation/oidc/interact/:uid/consent', express.urlencoded({ extended: false }), async (req, res) => {
  const interaction = await provider.interactionDetails(req, res)
  const { details } = interaction.prompt    // { missingOIDCScope, missingOIDCClaims }
  const grant = interaction.grantId
    ? await provider.Grant.find(interaction.grantId)
    : new provider.Grant({
        accountId: interaction.session.accountId,
        clientId: interaction.params.client_id,
      })
  if (details.missingOIDCScope)   grant.addOIDCScope(details.missingOIDCScope.join(' '))
  if (details.missingOIDCClaims)  grant.addOIDCClaims(details.missingOIDCClaims)
  await grant.save()
  return provider.interactionFinished(req, res, {
    consent: interaction.grantId ? {} : { grantId: grant.jti },
  }, { mergeWithLastSubmission: true })
})
```

`interactionDetails`/`interactionFinished` signatures, **exact**:

```
interactionDetails(req, res)
  -> Interaction model: { uid, returnTo, prompt: {name, reasons, details},
                           params, session: {accountId,...}|undefined, grantId }
  throws errors.SessionNotFound on expired uid
interactionFinished(req, res, result, { mergeWithLastSubmission })
  result ∈ { login: {accountId}, consent: {grantId}, error: {error, error_description} }
  → 303 to interaction.returnTo (the resume route)
```

(`lib/provider.js:255,242` and `interactionResult` at `:224` — merge-vs-replace
on `lastSubmission` is `mergeWithLastSubmission && !('error' in result)`.)

This replaces the v8 `interact: (ctx, tx) => ...` line in §2.1 wholesale.

### 8.4 `loadExistingGrant` (silent re-consent) + `Session` overlay

`lib/actions/authorization/session.js` (full, 30 lines):
`loadAccount` calls `configuration.findAccount(ctx, accountId)`;
`loadGrant` then calls `configuration.loadExistingGrant(ctx)`, and if it
returns a `Grant` whose `accountId`/`clientId` match, it calls
`ctx.oidc.session.grantIdFor(clientId, grant.jti)` — so **the provider's
Session model is what persists the oidc-session's accountId + grant-id
pair**, and `lib/shared/session.js` (sessionHandler) re-sets the
`_session` cookie with `exp` refreshed per touch. Therefore:

- `loadExistingGrant(ctx)` → `provider.Grant.findOne({ accountId,
  clientId })` **before** asking consent → if a saved grant exists and
  covers `openid` + the requested claims, policy check
  `op_scopes_missing`/`op_claims_missing` pass without UI (04 §5).
- v9 Session is a **Redis-backed model** via the adapter
(`federation:oidc:session:<id>` per 04 §5); it is **not** a composite over the
  overleaf express-session. The overleaf session and the oidc-provider
  session are **two separate cookies** (`overleaf.sid` and `_session`) —
  both sent on the same browser. The bridge (§8.3) is the *only* place
  the two meet: bridge reads `req.session`, calls `interactionFinished`.
  The provider `_session` cookie is then created by sessionHandler with
  `accountId` + `grantId` for repeat-visit grant skipping.
- **`features.devInteractions.enabled: false`** — mandatory. Default `true`
  (defaults.js:1119) would register dev login views that collide with
  the same paths and ship unauthenticated screens.
- Cookie names (`defaults.js:914-921`):
  `{ session: '_session', interaction: '_interaction', resume: '_interaction_resume' }`
  — all `httpOnly`, `sameSite: 'lax'`, `secure` per `cookies.long`/`short`
  (set `secure: true` in prod). No collision with `overleaf.sid`.
- `loadExistingGrant` return: `provider.Grant.findOne({ accountId,
  clientId })`. The `Session` model then records `grantIdFor(clientId,
  grant.jti)` (session.js:158) — repeat visits short-circuit through
  `grantIdFor` without calling `loadExistingGrant` at all.

### 8.5 Claim flow — `findAccount` + `claims:` config

v9 claim model (NOT the v8 `claim(...)` callback shape): the provider
call is `configuration.findAccount(ctx, accountId)` returning
`{ accountId, claims: { ...claim values }, claims?: (ctx, scope, claims) => obj }`
per `defaults.js:3355` + `lib/helpers/configuration_result.js:account()`,
and **static** `claims` config lists which claim names are supported and
which scope they live under (`defaults.js:717-727`). The id-token JWT
merges the account's claim object with `sub` injected last
(`lib/helpers/account_claims.js:1-5`) — custom claim values (origin,
localName, displayName, institution, language, avatarUrl per 01 §5) come
straight from `findAccount`'s returned claim map. Grant filtering
(`lib/models/grant.js:171-225`, `getOIDCClaims*`) is where `op_claims_missing`
decides whether to re-prompt: the claim names must already be on the
grant, which is why the consent bridge adds `details.missingOIDCClaims`
via `grant.addOIDCClaims(...)` (§8.3) — **not** a runtime claim filter.
`interactionPolicy` export (`lib/helpers/interaction_policy/index.js`) gives
`base()`, `Prompt`, `Check` — we do not override the default `base()`
(login + consent), but we do use `base()`'s `consent()` prompt
for the consent step (default behaviour already).

```
claims: {
  openid: ['sub', 'origin', 'localName', 'displayName', 'institution', 'language', 'avatarUrl'],
}
findAccount: async (ctx, accountId) => {
  const user = await User.findOne({ _id: accountId })
  if (!user) return undefined
  return {
    accountId: user._id,
    claims: {  // these values are placed VERBATIM into the id_token
      origin: new URL(Settings.siteUrl).hostname,  // B's origin FQDN (01 §5)
      localName: user.email,                 // (colon-forbidden, 04 §1.1) — the anchor (01 §3.3)
      displayName: user.displayName || user.email,
      institution: user.institution || '',
      language: Settings.uiLocale || 'en',
      avatarUrl: user.avatarUrl || '',
    },
  }
}
```

(`sub` is **not** in this map for public subjectType
(the account claim map returns the values above; `sub` is
 it is auto-injected
by `account_claims.js` as `sub = accountId` for the local `User._id`; we
want `sub = User._id` verbatim because A re-binds via
`(claim origin, claim localName)` pair, **not** `sub` — 02 §7.1 pairwise-
sub concerns are therefore **not** v9-blocking: we use `subjectTypes: ['public']` (the v1
  pairwise-sub mechanism is not used at all: A binds on the claim pair,
  06 §3).)


### 8.6 The complete v9.12.2 creation (verified key list is the authority)

The v9.12.2 *top-level* configuration keys (verified against
`lib/helpers/defaults.js`, `makeDefaults()`) — this is the *only* list of
valid keys the creation may use:

```
acrValues, adapter, claims, clients, clientDefaults, clockTolerance,
conformIdTokenClaims, allowOmittingSingleRegisteredRedirectUri,
acceptQueryParamAccessTokens, cookies, discovery, extraParams, features,
formats, jwks, responseTypes, pkce, routes, scopes, subjectTypes,
clientAuthMethods, ttl, extraClientMetadata, interactions,
enabledJWA, fetch, fetchResponseBodyLimits, enableHttpPostMethods,
loadExistingGrant (fn), ... (full JSDoc list in lib/helpers/defaults.js)
```

The top-level `metadata`, `token`, `jwt`, `grantUris`, `dynamicClient`,
`client` (singular), `issuer` (constructor arg), and `loadExistingGrant`-
as-model shapes are **not** valid v9.12.2 keys — the *earlier* plan's
draft creation (the v1 draft creation, since deleted) contained several of them and
is no longer referenced. The creation, grounded to this list:

```js
// oidc/createProvider.mjs — B = OP role
import Provider from 'oidc-provider'
import User from '../../../../app/src/models/User.mjs'
import Settings from '../../../../app/src/infrastructure/Settings.mjs'
import { loadOidcSigningKeys, oidcProviderJwks } from '../oidf/signingKeys.mjs'
import redisClient /* existing overleaf-cep Redis client */
import { oidcAdapterFactory } from './RedisOidcProviderAdapter.mjs'
import approvedClients from './clients.mjs'        // 04 §7 boot reconstruction
import { bridgeInteractions } from './bridge.mjs'  // §8.3

export async function createOidcProvider(app) {
  const jwks = await oidcProviderJwks()   // OIDC signing keys (02 §4, 05 §7)
                                          // separate from the federation key
  const setup = {
    issuer: undefined,                   // issuer = mount path default =
                                          //   `${siteUrl}/federation/oidc`
    adapter: oidcAdapterFactory,         // 04 §5, 05 §8.2
    clients: await approvedClients(),    // 04 §7 §8.8:
                                         //   per-approved-peer entries,
                                         //   PUBLIC (grant_types/response_types/
                                         //   scope: 'openid', PKCE)
    subjectTypes: ['public'],            // sub = accountId (User._id)
    scopes: ['openid'],
    claims: { /* §8.5: openid → ['sub','origin','localName','displayName']
               per per-peer admin allow-list (04 §4) */ },
    ttl: {
      AuthorizationCode: 120,            // 01 §5 step 5 (single-use, 120 s)
      Grant: 30 * 24 * 3600,             // "remember the choice" (01 §5)
      Interaction: 600,                  // 10 min interaction window
    },
    // (no RefreshToken: no refresh tokens in v1)
    interactions: {                       // §8.3 bridge — mounted *before*
      url: (ctx) => `/federation/oidc/interact/${ctx.uid}`,
    },
    loadExistingGrant: async (ctx) => {  // §8.4 silent re-consent
      const client = ctx.oidc.client
      if (!client) return undefined
      const account = await ctx.oidc.account  // via findAccount (§8.5)
      if (!account) return undefined
      const grant = new ctx.oidc.provider.Grant({
        accountId: account.accountId,
        clientId: client.id,
      })
      grant._id = ctx.oidc.session.grantIdFor(client.client_id)
      return ctx.oidc.provider.Grant.get(grant, false, 0) // load or undefined
    },
    findAccount: async (ctx, sub) => {   // §8.5
      if (!sub) return undefined
      const account = await User.getByIdAndRoleCheck(sub, ['user','staff'])
      return account ? { accountId: account.id,
                         claims: (scope) => ({ /* §8.5 */ }) } : undefined
    },
    jwks: (async () => {
      // static function returning the public JWKs (02 §4/05 §7);
      // oidc-provider's `jwks` config accepts a fn or JWK array
      return oidcProviderJwks()
    })(),
    features: { resources: { enabled: false }, devInteractions: { enabled: false } },
  }
  const provider = new Provider(
    `${Settings.siteUrl}/federation/oidc`,
    setup
  )
  // Mount on the EXPress router that has req.session (webRouter via
  // nonCsrfRouter — see §1.1 correction), bridge FIRST (§8.3), then the
  // provider. `provider.callback()` is a node `(req, res, next)` handler
  // (v9 Provider extends the bundled Koa; .callback() is the node
  // listener, Koa app.js:182). Express strips the mount prefix; v9
  // derives its routes from the issuer URL's pathname.
  router.get('/federation/oidc/interact/:uid', bridgeLogin)
  router.post('/federation/oidc/interact/:uid/consent', bridgeConsent)
  router.use('/federation/oidc', provider.callback())
  return provider
}
```

**The RP-side (A = RP role)** does *not* use `openidconnect-client` or
any OIDC client library (03 of this file, §3.2 above). The v9.12.2
provider signs tokens with the OIDC signing key set (a *second*,
independent from the federation key, 02 §4); A verifies against
*that* JWKS (oidc-provider's mount `/federation/oidc/.well-known/jwks`,
01 §6 item 3), *not* the leaf (06 §6.1).

### 8.7 Cross-file summary (what this grounding changed in the other files)

This §8 was written against the *actual* v9.12.2 source, not the v8-era
README. Concretely, against the *earlier* plan it forced:

- **04 §5** — the adapter is the 7-method factory (§8.2); `transaction()`,
  `findModel`, `WITHWATCH` and the "composite Session" description are
  gone; Redis keys are `oidc:<model>:<id>` / `oidc:sub:<uid>` /
  `oidc:grant:<id>` (§8.2).
- **04 §7** — client id is `urn:overleaf-federation:client:<origin>`;
  no `grant_prefix` (not in the metadata model), no dynamic `findClient`
  lookup — clients are reconstructed on boot from `FederationPeer`
  (04 §7, §8.8); the *pairwise-sub* mechanism is **not used**
  (`subjectTypes: ['public']`, A binds on `(origin, localName)`, 06 §3).
- **04 §9** — indexes are unchanged (Mongoose-side; not affected by
  oidc-provider version).
- **03 of this file §1** — drop `Client.mjs` and `pairwiseClient.mjs`;
  keep `signingKeys.mjs` (02 §5 keystore, *federation* key)
  and `oidc/keysigning.mjs` (05 §7 OIDC signing keystore); *no*
  `openidconnect-client` dep.
- **03 of this file §2** (`new Provider(...)` shape) — rewritten to §8.6.
  v8-only keys (`claim(...)` callback form, `opts.app` argument,
  `issuerMode`, `federatedSubjectMode`, `metadata:`, `token:` as key,
  `jwt:` as key, `grantUris`, `dynamicClient`, `client` singular) are
  all gone.
- **03 of this file §2.1** (`interact:` config) — v9 has no `interact:`;
  the interaction bridge is §8.3 (GET + POST on `req`/`res`) and
  `interactions: { url }` (§8.6).
- **03 of this file §2.2** (`findClient`/pairwise) — gone; §8.8 replaces
  it.
- **03 of this file §3** (`Client.mjs`, `openidconnect-client`) — deleted;
  `CodeExchange.mjs` is §3.2 (fetch + jose); `CallbackRouter.mjs` is §3.3
  (a plain GET Express route, not on the provider mount).
- **03 of this file §3.5 Settings** (formerly §6) — add
  `federationOidcKeyPath` *and* `federationKeystorePath` (05 §7): two
  separate key paths, 02 §4 (key sets).
- **03 of this file §10** (type surface, now §6) — deps:
  `oidc-provider` (IdP) + `@oidfed/leaf`, `@oidfed/oidc`, `@oidfed/core`
  (trust layer, 02 §1); *no* `openidconnect-client` (the v1
  "two panva deps" row is replaced by "one panva dep + three OIDF
  packages").
- **03 of this file §11** (Settings, now §7) — add
  `federationOidcKeyPath`, `federationKeystorePath`,
  `federationGrantDurationDays`.
- **07 (roadmap)** — P0: "RFC 9421 sign/verify" row is replaced by
  "OIDF leaf mount + key-material keystore bootstrap + one roundtrip
  `createClientAssertion`/verify pair". P1: "oidc-provider mount +
  Redis adapter" stays.
- **00-overview** — file map: `02-data-model`, `03-cep-integration`,
  `04-roadmap` are gone; the 8-file layout is at 00 §1.

**04 §5.2 (composite Session) is gone**; v9's Session is a Redis-backed
model with `accountId` + `grantIdFor` fields; `req.session` (overleaf,
express) is the *only* B-login source and is bridged by the interaction
bridge (§8.3), not by the adapter. `provider.Session.get(ctx)` is a v9
model getter (not `oidc.session` — the v9 adapter receives plain
`req`/`res`); the bridge uses *raw* `(req, res)` and *never* calls the
adapter's Session.

### 8.8 Client registration → boot-time `clients[]` reconstruction (v9)

v9 does **not** expose a `findClient` hook and there is no dynamic
client registration. Client resolution in v9 is `ctx.oidc.client`
from the static `clients[]` array (constructor setup). The
*federated* client list is therefore **reconstructed on boot** from
`FederationPeer` rows with `status: 'approved'` and direction
`inbound|both` (04 §7 is the authority; 04 §2 is what the row holds):

```js
// oidc/clients.mjs — called from createProvider.mjs (§8.6)
export default async function approvedClients() {
  const peers = await FederationPeer
    .find({ status: 'approved', direction: { $in: ['inbound','both'] } })
  return peers.map(p => ({
    client_id: `urn:overleaf-federation:client:${p.origin}`,
    applicationType: 'web',
    redirect_uris: [`https://${p.origin}/federation/oidc/rp/callback`],
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',   // PUBLIC — PKCE, no secret
    scope: 'openid',
  }))
}
```

Three consequences:
1. "Is peer X approved for grants on this machine?" is answered by the
   OIDC engine itself (`400 invalid_client`), not by a separate S2S
   trust check at grant time (01 §5).
2. The client id is a *deterministic string*, derived locally by both
   sides from their own origin — **derived, not transmitted** (no S2S
   payload carries a client id; the v1 "federate" wire is gone).
3. Admin approval flow (04 §2.1): pending pins/registrations are
   *not* in `clients[]` until approved; in institutional mode the
   "request reverse registration" button issues B → A explicit
   registration (02 §4), writing B's own outbound row.
