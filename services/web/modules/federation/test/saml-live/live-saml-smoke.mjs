/**
 * S22: live SAML SSO smoke (plan 10, Phase 2 live SAML dance).
 *
 * Drives the REAL app SSO surface — not a stand-in:
 *   1. real express app (Server.mjs order for the SSO path:
 *      json/urlencoded → express-session → csurf → passport; the SAML ACS
 *      (nonCsrfRouter) is mounted BEFORE the csrf middleware, exactly as
 *      Server.mjs applies applyNonCsrfRouter before `webRouter.use(csrf.middleware)`),
 *   2. the module's OWN samlModule (index.mjs: SAMLModuleManager + SAMLRouter +
 *      SAMLNonCsrfRouter + initSettings/initPolicy + the Phase-4 cert-expiry
 *      sweep run here via `sweepSsoCertExpiry()` — module.start()'s body),
 *   3. the passport SAML strategy built by SAMLModuleManager.buildStrategyOptions
 *      from the real DB ssoConfigs rows (idpCert = the IdP's OWN cert path,
 *      fetched from the live IdP metadata at run time — it is ephemeral),
 *   4. the real AuthenticationController.finishLogin chain (audit +
 *      serializeUser/session + AsyncFormHelper.redirect),
 *   5. a real LIVE SimpleSAMLphp IdP (kristophjunge/test-saml-idp, compose.yaml).
 *
 * The harness is the test-side actor: it GETs `GET /saml/login/<providerId>`
 * (a cookie-carrying dance — express-session must round-trip so
 * req.session.samlProviderId reaches the ACS), follows the app's 302 to the
 * IdP (redirect binding: raw-deflate + b64 + URL-encode, AuthnRequest carries
 * the required ProtocolBinding attr), POSTs the test creds, captures the IdP's
 * auto-POST form (SAMLResponse) and replays it to the app ACS with
 * Accept: application/json.
 *
 * Wire ground truth (Live verified, S22, see HANDOFF §22.1):
 *   — IdP returns an auto-POST form, NOT a 302 (destination = our registered
 * ACS, https://smoke.example/saml/login/callback)
 *   — the IdP signs BOTH <samlp:Response> and <saml:Assertion>
 *   — released attrs: uid => '1', eduPersonAffiliation => 'group1',
 *     email => 'user1@example.com' (NO eduPersonScopedEmail — R1 leg 2)
 *   — transient NameID, SPNameQualifier = our registered issuer
 *   — <saml:Audience>https://smoke.example/saml</saml:Audience> (IdP echoes
 *     the registered SP entity id → node-saml v5 audience check passes with
 *     provider.issuer = audience).
 *
 * Scenarios (plan 10 §3 R1 + P1c + plan 11 §2.1 /saml/meta + Phase 4 S18):
 *   s01  real-email SAML login — IdP releases `email` (R1 leg 1):
 *        account + ssoRoles.main + samlIdentifiers + audit row
 *   s02  synthetic-email SAML login — emailField points at an attribute the
 *        IdP does NOT release → JIT `1@<siteHost>` + syntheticEmail flag
 *        (uid='1' is the only persistent identifier the IdP releases)
 *   s03  attrFilter `blocked` role — 401 + sso-login-denied audit, NO account,
 *        NO ssoRoles.blocked marker (P1c: denial precedes findOrCreateUser)
 *   s04  SP metadata endpoint — GET /saml/meta 200 + XML + ACS
 *   s05  cert-expiry sweep — rows for sp-metadata:publicCert (SEEDed
 *        inline PEM, S17 shape) + saml-provider:main:<issuer> (IdP cert file)
 *
 * Run (from this directory, with the stack from compose.yaml):
 *   node live-saml-smoke.mjs
 * Env overrides: SMOKE_MONGO_PORT (27107), SMOKE_REDIS_PORT (6380),
 * SMOKE_IDP_PORT (8080), SMOKE_IDP_ORIGIN (http://127.0.0.1:8080),
 * SMOKE_IDP_USER/SMOKE_IDP_PASS (user1/user1pass), SMOKE_SITE_URL
 * (https://smoke.example — the registered SP entity; must match
 * idp/saml20-sp-remote.php).
 *
 * Exit code 0 = all green. The script owns its mongo namespace (drops the
 * `test-overleaf` db) and its temp files. The drop is GUARDED: it only proceeds
 * against a loopback `test-overleaf` db under NODE_ENV=test — the repo's own
 * dropTestDatabase guard (libraries/mongo-utils/test-utils.js) is name+env
 * only and is NOT wired into this raw connection path, so the harness
 * replicates its intent plus a hostname check before the drop.
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import express from 'express'
import expressSession from 'express-session'
import cookieParser from 'cookie-parser'
import csurf from 'csurf'
import passport from 'passport'
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'saml-live-'))
process.on('exit', () => {
  fs.rmSync(tmpDir, { recursive: true, force: true })
})

// ── env (BEFORE any settings-dependent import — @overleaf/settings reads
//    process env at module evaluation) ─────────────────────────────────────────
// The app's dropTestDatabase guard (libraries/mongo-utils/test-utils.js)
// refuses to drop anything except NODE_ENV=test + db name 'test-overleaf'.
process.env.NODE_ENV ??= 'test'
const MONGO_PORT = process.env.SMOKE_MONGO_PORT || '27107'
const MONGO_DB = 'test-overleaf'
const REDIS_PORT = process.env.SMOKE_REDIS_PORT || '6380'
const IDP_ORIGIN = process.env.SMOKE_IDP_ORIGIN || `http://127.0.0.1:${process.env.SMOKE_IDP_PORT || 8080}`
const IDP_USER = process.env.SMOKE_IDP_USER || 'user1'
const IDP_PASS = process.env.SMOKE_IDP_PASS || 'user1pass'
const SITE_URL = process.env.SMOKE_SITE_URL || 'https://smoke.example'

process.env.MONGO_CONNECTION_STRING ??= `mongodb://127.0.0.1:${MONGO_PORT}/${MONGO_DB}`
process.env.REDIS_HOST ??= '127.0.0.1'
process.env.REDIS_PORT ??= REDIS_PORT
process.env.PUBLIC_URL ??= SITE_URL
process.env.SESSION_SECRET ??= 'saml-live-smoke-2025-00000000000000000000'
// Leave OVERLEAF_SAML_SYNTHETIC_EMAIL_DOMAIN unset → synthetic-email domain
// defaults to the siteUrl host (the R1 leg-2 default under test).

// ── the real runtime ──────────────────────────────────────────────────────────
const Settings = (await import('@overleaf/settings')).default
// SSO path is env-independent here: EXTERNAL_AUTH unset → DB mode (ssoConfigs).
delete process.env.EXTERNAL_AUTH
Settings.moduleImportSequence = [] // don't import the app's 15 modules
Settings.siteUrl = SITE_URL
Settings.externalAuthentication = {
  saml: { enabled: true },
  oidc: { enabled: false },
  ldap: { enabled: false },
}
Settings.adminOnlyLogin = false
// Session middleware (in-memory express-session — the redis-backed
// CustomSessionStore is NOT part of the SSO chain under test; UserSessionsManager
// is stubbed below, same seam live-smoke.mjs stubs).
Settings.cookieName = 'fedsmoke'
Settings.cookieSessionLength = 1000 * 60 * 60
Settings.sameSiteCookie = 'lax'
Settings.secureCookie = false
Settings.behindProxy = false
// cookieRollingSession off = no per-request session.touch side effects.
Settings.cookieRollingSession = false

// ── destructive guard (BEFORE the connection is used for a DROP). ──────────
// `MONGO_CONNECTION_STRING ??=` above does NOT override an env value the
// developer already exported (local dev / CI) — and the drop below is raw
// `connection.dropDatabase()`, which bypasses the repo's name+env guard
// (ensureTestDatabase, no host check). Only clear a loopback `test-overleaf`
// db under NODE_ENV=test; otherwise refuse to touch that database.
{
  let refused
  let connUrl
  try {
    connUrl = new URL(Settings.mongo.url)
  } catch (e) {
    refused =
      `Refusing to parse connection string for the drop guard: ${e.message}` +
      ` — ensure MONGO_CONNECTION_STRING is a single-host mongodb:// URL, or point the harness at the smoke stack (SMOKE_MONGO_PORT=${MONGO_PORT}, SMOKE_REDIS_PORT=${REDIS_PORT})`
  }
  if (!refused) {
    const hostOk = ['127.0.0.1', 'localhost', '::1'].includes(connUrl.hostname.replace(/^\[|\]$/g, ''))
    if (!hostOk || connUrl.pathname !== `/${MONGO_DB}` || process.env.NODE_ENV !== 'test') {
      refused =
        `Refusing to drop database '${connUrl.pathname}' at '${connUrl.hostname}' (NODE_ENV='${process.env.NODE_ENV}')` +
        ` — the S22 SAML smoke only clears a loopback 'test-overleaf' db under NODE_ENV=test.` +
        ` Unexport a local MONGO_CONNECTION_STRING/MONGO_URL, or point the harness at the smoke stack (SMOKE_MONGO_PORT=${MONGO_PORT}, SMOKE_REDIS_PORT=${REDIS_PORT})`
    }
  }
  if (refused) throw new Error(refused)
}

// Real app infrastructure (the same singletons live-smoke.mjs uses). The
// `mongodb.mjs` `db` map is COLECTIONS only (no `.connection` key); the drop
// is via the raw Mongoose connection (same as tools/live-smoke.mjs).
const mongodbInfra = await import(
  new URL('../../../../app/src/infrastructure/mongodb.mjs', import.meta.url)
)
const Mongoose = (await import(
  new URL('../../../../app/src/infrastructure/Mongoose.mjs', import.meta.url)
)).default
await Mongoose.connectionPromise
await Mongoose.connection.dropDatabase()

// ── live IdP cert (ephemeral: regenerated on container restart). ───────────
// Fetched from the live IdP metadata at run time and written to tmpDir; this
// is the ONLY cert seam that is NOT static. The IdP signs BOTH Response and
// Assertion with this cert.
const idpMeta = await (
  await fetch(`${IDP_ORIGIN}/simplesaml/saml2/idp/metadata.php`)
).text()
const idpMetaCertMatch = idpMeta.match(
	/<ds:X509Certificate>([\s\S]*?)<\/ds:X509Certificate>/
)
const idpCertB64 = idpMetaCertMatch && idpMetaCertMatch[1]
if (!idpCertB64) throw new Error('IdP metadata has no X509Certificate (is the IdP up?)')
const idpCertPath = path.join(tmpDir, 'idp-cert.pem')
fs.writeFileSync(
  idpCertPath,
  `-----BEGIN CERTIFICATE-----\n${idpCertB64.replace(/\s+/g, '')
    .match(/.{1,64}/g)
    .join('\n')}\n-----END CERTIFICATE-----\n`,
)

// ── OUR SP metadata cert (s04/s05: the INLINE-PEM seam). ────────────────────
// node-saml v5 generateServiceProviderMetadata with no key pair produces
// UNSIGNED metadata (no <x509:Certificate>, no <ds:Signature> — verified in
// S22). So the "self-generated cert" that S17 assumed does NOT exist; for s05
// to exercise a real notAfter parse we generate a real (dummy) self-signed
// cert here and seed its INLINE PEM as ssoConfigs.spMetadata.publicCert
// (S17 shape: buildSPMetadataXml + the Phase-4 _sweepInline both expect a
// string cert). This is OUR SP's cert — a distinct artifact from the IdP's.
async function generateSpCertPem() {
  // A genuine self-signed X.509 (generated once with openssl; static). Validity
  // is irrelevant for the notAfter parse — it must just be a real cert node's
  // X509Certificate can parse. ``
  return (
    '-----BEGIN CERTIFICATE-----\n' +
    'MIIDOTCCAiGgAwIBAgIUGExfczgzsfv3ag1sw7wyY5W5rT0wDQYJKoZIhvcNAQEL\n' +
    'BQAwKzEVMBMGA1UEAwwMZmVkLXNtb2tlLVNQMRIwEAYDVQQKDAlmZWQtc21va2Uw\n' +
    'IBcNMjYwOTI1MTk0NjA1WhgPMjEyNjA5MDExOTQ2MDVaMCsxFTATBgNVBAMMDGZl\n' +
    'ZC1zbW9rZS1TUDESMBAGA1UECgwJZmVkLXNtb2tlMIIBIjANBgkqhkiG9w0BAQEF\n' +
    'AAOCAQ8AMIIBCgKCAQEAsf0FUMOyLBW0fnzTtu6mqMwYgtUBLRnx0f5pF9vP9BAs\n' +
    'WcD3IcZL6sLtkGCpuaQ94PN+Izy+1LX+rPGs2oqPEI+ODNiGcvMFDrlguenfFQMo\n' +
    'MGg0egLqSfEvdq7j/ETezDKbzdoXrwAd04n4mNtHDTxkXDrl28bfM2xbBqP3Ic7+\n' +
    'sqEtZhPxICb7RjyUgMWHFVyv0oBYKJK6iHEkTJyz+A4eqgTAM3PoNDULhzI+mQO7\n' +
    'bIKvcnZRcte1J9N2Y7eXZlK8sUXiuP3WMJNJD2hST0v99nHksBeHxIzUsxWmY3Ck\n' +
    '49qq0FxZAOKEvLpzbGpiv3rCSJR6hA2LfJ8YjzJgfwIDAQABo1MwUTAdBgNVHQ4E\n' +
    'FgQUnjtIPyh/AA3BOvpvwlZN5C7UmwMwHwYDVR0jBBgwFoAUnjtIPyh/AA3BOvpv\n' +
    'wlZN5C7UmwMwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAoWnV\n' +
    'KlVrs1Rykbiq1H/O1dSRPuWvj6ZzJIMVHtx4e3p3agweb0YtqjqqIBeYYhQlj0mw\n' +
    'pUwZrzjTK/D6QXqp+I5bZgUKz4DuA5jxy40QuwBoztA4aXX37TMvkjfTGiBLNCnA\n' +
    'x4O6x+My1vSbnld3b3YYjYBmavYn7FubM58YEMmS95zmMsuSxclvnBxxUHgXQQjH\n' +
    'sgpXypekqz9LPb/J+TXvQk5c9ho5oJg2eqnGKlI6UCVIu3r7oWt71k6GWKS2Bctl\n' +
    'eqztaomivfU/L0yczPNSaIJPOi7SCX3kujVzW6PAHs85yGHfc0bZh6quVNwI1VAh\n' +
    '+9ntM19LRRh+g8MYBA==\n-----END CERTIFICATE-----\n'
  )
}
const spCertB64 = (
  await generateSpCertPem()
)
  .replace(/^-----BEGIN CERTIFICATE-----\n/, '')
  .replace(/\n-----END CERTIFICATE-----\n$/, '')
  .replace(/\s+/g, '')

// ── seed ssoConfigs (the admin API's exact row shape, SSOAdminController) ──
// NOTE: `idpCert` on each provider is a FILE PATH — buildStrategyOptions calls
// readFilesContentFromEnv(provider.idpCert) which fs.readFileSync's it. It
// MUST be the IdP's own signing cert (the one that signs the SAMLResponse).
// spMetadata.publicCert is INLINE PEM (a different artifact: OUR SP's cert).
const providers = [
  {
    id: 'main', type: 'saml', enabled: true, order: 0,
    issuer: SITE_URL + '/saml',            // = the registered SP entity (IdP echoes → audience)
    entryPoint: IDP_ORIGIN + '/simplesaml/saml2/idp/SSOService.php',
    idpCert: idpCertPath,
    userIdField: 'uid',
    emailField: 'email',                   // R1 leg 1: IdP releases `email`
    firstNameField: 'givenName', lastNameField: 'lastName',
    authnRequestBinding: 'HTTP-Redirect',
    attrFilter: undefined,
  },
  {
    id: 'synth', type: 'saml', enabled: true, order: 1,
    issuer: SITE_URL + '/saml',
    entryPoint: IDP_ORIGIN + '/simplesaml/saml2/idp/SSOService.php',
    idpCert: idpCertPath,
    userIdField: 'uid',
    emailField: 'eduPersonScopedEmail',    // R1 leg 2: IdP does NOT release it
    authnRequestBinding: 'HTTP-Redirect',
    attrFilter: undefined,
  },
  {
    id: 'blocked', type: 'saml', enabled: true, order: 2,
    issuer: SITE_URL + '/saml',
    entryPoint: IDP_ORIGIN + '/simplesaml/saml2/idp/SSOService.php',
    idpCert: idpCertPath,
    userIdField: 'uid',
    emailField: 'email',
    attrFilter: [
      {
        role: 'blocked',
        attribute: 'email',
        values: ['user1@example.com'],
        match: 'equals',
      },
    ],
    authnRequestBinding: 'HTTP-Redirect',
  },
]
await mongodbInfra.db.ssoConfigs.updateOne(
  {
    _id: 'sso-settings',
  },
  {
    $set: {
      // INLINE PEM (S17 shape: buildSPMetadataXml + the Phase-4 _sweepInline
      // both expect a string cert, not a file path).
      spMetadata: {
        publicCert: `-----BEGIN CERTIFICATE-----\n${spCertB64}\n-----END CERTIFICATE-----\n`,
      },
      providers,
    },
  },
  { upsert: true },
)

// ── module under test + the app SSO chain ───────────────────────────────────
const samlModule = (
  await import(
    new URL('../../../../modules/authentication/saml/index.mjs', import.meta.url)
  )
).default
const AuthenticationController = (
  await import(
    new URL(
      '../../../../app/src/Features/Authentication/AuthenticationController.mjs',
      import.meta.url,
    )
  )
).default
const UserSessionsManager = (
  await import(
    new URL(
      '../../../../app/src/Features/User/UserSessionsManager.mjs',
      import.meta.url,
    )
  )
).default
// Stub the one redis-backed seam (session tracking) — same as live-smoke.mjs.
UserSessionsManager.promises.trackSession = async () => {}

// ── express app (Server.mjs order: nonCsrfRouter → csurf → passport) ───────
// Server.mjs: `await Modules.applyNonCsrfRouter(webRouter, …)` (line 231)
// BEFORE `webRouter.csrf = new CsrfClass(); webRouter.use(webRouter.csrf.middleware)`
// (line 234-235). We mirror that: the module's OWN nonCsrfRouter (SAML ACS
// + logout callback) is applied before the csrf middleware, then passport,
// then the module's router.
const app = express()
app.use((req, res, next) => {
  req.headers.host = new URL(SITE_URL).host
  next()
})
app.use(express.json())
app.use(express.urlencoded({ extended: true, limit: '2mb' }))
app.use(cookieParser())
app.use(expressSession({
  secret: ['saml-live-smoke-2025-00000000000000000000'],
  resave: false,
  saveUninitialized: true,
  cookie: { sameSite: 'lax' },
}))
// Non-CORS/Surf router (SAML ACS + logout) — BEFORE csrf (Server.mjs order).
samlModule.nonCsrfRouter.apply(app, null, null)
// csrf (csurf v1 is the middleware function itself; no `.middleware` prop).
app.use(csurf())
app.use(passport.initialize())
app.use(passport.session())
passport.serializeUser((user, cb) =>
  AuthenticationController.serializeUser(user, (e, light) => {
    if (e) return cb(e)
    cb(null, light)
  })
)
passport.deserializeUser((obj, cb) => AuthenticationController.deserializeUser(obj, cb))
app.use((req, res, next) => {
  req.deviceHistory = undefined
  next()
})

samlModule.router.apply(app, null, null)
// Register the SAML strategies for EVERY DB provider (mirrors the app's
// Modules.applyMiddleware passportSetup → SAMLModuleManager.passportSetup;
// here each is registered on demand, same effect).
{
  const SAMLModuleManager = (
    await import(
      new URL(
        '../../../../modules/authentication/saml/app/src/SAMLModuleManager.mjs',
        import.meta.url,
      )
    )
  ).default
  for (const p of providers) await SAMLModuleManager.ensureStrategy(p.id)
}

// module.start() — the Phase-4 cert-expiry sweep (S18, plan/10 Phase 4).
const { sweepSsoCertExpiry } = await import(
  new URL('../../../../modules/authentication/ssoCertExpiry.mjs', import.meta.url))
const sweepResult = await sweepSsoCertExpiry()

const server = app.listen(0, '127.0.0.1')
await new Promise((resolve) => server.on('listening', resolve))
const base = `http://127.0.0.1:${server.address().port}`

// ── the test-side IdP dance ─────────────────────────────────────────────────
// A cookie jar (per-host Map) is REQUIRED for the SSO chain: express-session
// sets `fedsmoke` on GET /saml/login/<providerId>; the ACS reads
// req.session.samlProviderId. Without it req.session is empty and
// SAMLAuthenticationController.passportLoginCallback falls back to '1'
// (env mode) → wrong provider → s01/s02/s03 assertions would be vacuous.
// Per-host cookie jar (app host + IdP host are distinct origins).
const cookieJars = new Map() // host -> Map(cookieName, cookieValue)
function cookieHeaderFor(host) {
  const jar = cookieJars.get(host) || new Map()
  return [...jar].map(([k, v]) => `${k}=${v}`).join('; ')
}
function ingestCookies(host, res) {
  let jar = cookieJars.get(host)
  if (!jar) { jar = new Map(); cookieJars.set(host, jar) }
  for (const c of res.headers.getSetCookie?.() ?? []) {
    const [kv] = c.split(';')
    const i = kv.indexOf('=')
    if (i < 0) continue
    jar.set(kv.slice(0, i).trim(), kv.slice(i + 1).split(';')[0].trim())
  }
}
async function idpDance(providerId) {
  // Fresh browser per dance: a new app session (fedsmoke + samlProviderId)
  // AND a clean IdP session (stale IdP cookies turn the next SSOService.php
  // hit into a "POST data" form page instead of a fresh login dance).
  cookieJars.delete('app')
  cookieJars.delete('idp')
  // 1) app login entrypoint → 302 + SAMLRequest (with cookie)
  const startRes = await fetch(`${base}/saml/login/${providerId}`, {
    redirect: 'manual',
    headers: { cookie: cookieHeaderFor('app') },
  })
  ingestCookies('app', startRes)
  if (startRes.status !== 302) {
    throw new Error(`login ${providerId} expected 302, got ${startRes.status}: ${await startRes.text()}`)
  }
  let res = startRes
  let url = res.headers.get('location')
  // 2) follow the IdP (SSOService 302 → loginuserpass form). Stop once the
// fetched body carries the AuthState form field (the redirect itself has no form).
  let body = ''
  for (let hop = 0; hop < 5 && !/name="AuthState"/.test(body); hop++) {
    const next = new URL(url, IDP_ORIGIN)
    res = await fetch(next.href, {
      redirect: 'manual',
      headers: { cookie: cookieHeaderFor('idp') },
    })
    ingestCookies('idp', res)
    body = await res.text()
    url = res.headers.get('location')
    if (!url) break
    url = new URL(url, IDP_ORIGIN).href
  }
  const authState = (body.match(/name="AuthState" value="([^"]+)"/) || [])[1]
  if (!authState) {
    throw new Error(`no login form reached (body: ${body.slice(0, 300)})`)
  }
  // 3) credentials → IdP auto-POST form with SAMLResponse (cookie-carrying)
  const resAfter = await fetch(res.url, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      cookie: cookieHeaderFor('idp'),
    },
    body: new URLSearchParams({
      username: IDP_USER,
      password: IDP_PASS,
      AuthState: authState,
    }).toString(),
  })
  ingestCookies('idp', resAfter)
  const after = await resAfter.text()
  const loc = resAfter.headers.get('location')
  let samlResponse
  if (loc && loc.includes('SAMLResponse=')) {
    samlResponse = new URL(loc, IDP_ORIGIN).searchParams.get('SAMLResponse')
  } else {
    samlResponse = (after.match(/name="SAMLResponse" value="([^"]+)"/) || [])[1]
  }
  if (!samlResponse) {
    throw new Error(`no SAMLResponse (status ${resAfter.status}: ${after.slice(0, 400)})`)
  }
  return samlResponse
}

async function loginWithProvider(providerId) {
  const samlResponse = await idpDance(providerId)
  return fetch(`${base}/saml/login/callback?_xsrf=`, {
    method: 'POST',
    headers: {
      'accept': 'application/json',
      'content-type': 'application/x-www-form-urlencoded',
      cookie: cookieHeaderFor('app'),
    },
    body: new URLSearchParams({ SAMLResponse: samlResponse }).toString(),
  })
}

// ── assertions ───────────────────────────────────────────────────────────────
const passed = []
const failed = []
const check = (name, ok, detail) => {
  ;(ok ? passed : failed).push(name)
  console.log(`  ${ok ? '✓' : '✗'} ${name}${ok ? '' : ` — ${detail || ''}`}`)
}

// s01 — real email (R1 leg 1): IdP releases `email` → real account path
{
  const res = await loginWithProvider('main')
  const json = await res.json()
  check('s01 login 200 + {redir}', res.status === 200 && !!json.redir, `status ${res.status} ${JSON.stringify(json).slice(0, 200)}`)
  const user = await mongodbInfra.db.users.findOne({ 'emails.email': 'user1@example.com' })
  check(
    's01 user.email = real IdP email',
    user?.emails?.[0]?.email === 'user1@example.com',
    JSON.stringify(user?.emails || user),
  )
  check('s01 ssoRoles.main.role local (no attrFilter match)', user?.ssoRoles?.main?.role === 'local', JSON.stringify(user?.ssoRoles))
  check('s01 ssoLoginProviderId main', user?.ssoLoginProviderId === 'main', JSON.stringify(user?.ssoLoginProviderId))
  const ident = user?.samlIdentifiers?.[0] || {}
  check('s01 samlIdentifiers[0] (providerId main, uid, no synthetic flag)', ident.providerId === 'main' && ident.externalUserId && !ident.syntheticEmail, JSON.stringify(ident))
  const audit = await mongodbInfra.db.userAuditLogEntries
    .findOne({ userId: user?._id, operation: 'login' })
  check('s01 audit login entry (method SAML login - main)', audit && (audit.info?.method || '').includes('SAML login - main'), JSON.stringify(audit?.info || audit))
}

// s02 — synthetic email (R1 leg 2): emailField points at a NOT-released attr
// (IdP sends eduPersonAffiliation, NOT eduPersonScopedEmail) → JIT 1@<siteHost>
// (uid='1' is the persistent identifier) + syntheticEmail flag
{
  const res = await loginWithProvider('synth')
  const json = await res.json()
  check('s02 synthetic login 200', res.status === 200 && !!json.redir, `status ${res.status} ${JSON.stringify(json).slice(0, 200)}`)
  const host = new URL(SITE_URL).host
  // uid='1' (the only persistent id the IdP releases) → synthetic email 1@host
  const user = await mongodbInfra.db.users.findOne({ 'emails.email': `1@${host}` })
  check(`s02 synthetic email 1@${host} created`, !!user, JSON.stringify(await mongodbInfra.db.users.countDocuments({})))
  const ident = user?.samlIdentifiers?.[0] || {}
  check('s02 identifier syntheticEmail flag true', ident.syntheticEmail === true, JSON.stringify(ident))
  // the flag survives re-login (update path re-flags)
  await loginWithProvider('synth')
  const again = await mongodbInfra.db.users.findOne({ 'emails.email': `1@${host}` })
  check('s02 flag persists on re-login', again?.samlIdentifiers?.[0]?.syntheticEmail === true, JSON.stringify(again?.samlIdentifiers))
}

// s03 — attrFilter `blocked` (P1c): denied at login; audit sso-login-denied;
// NO account; NO ssoRoles.blocked marker (denial precedes findOrCreateUser).
{
  const beforeCount = await mongodbInfra.db.users.countDocuments({})
  const res = await loginWithProvider('blocked')
  const json = await res.json()
  check('s03 blocked → 401 (not a redir)', res.status === 401 && !!json?.message, `status ${res.status} ${JSON.stringify(json).slice(0, 200)}`)
  const denied = await mongodbInfra.db.userAuditLogEntries
    .find({ operation: 'sso-login-denied' })
    .sort({ timestamp: -1 })
    .limit(1)
    .project({ info: 1, operation: 1 })
    .toArray()
  check(
    's03 sso-login-denied audit (provider blocked)',
    !!denied[0] && (denied[0].info?.providerId ?? '').includes('blocked'),
    JSON.stringify(denied[0] ?? denied),
  )
  const markerCount = await mongodbInfra.db.users.countDocuments({
    'ssoRoles.blocked': { $exists: true },
  })
  check('s03 no account + no blocked-provider marker', (await mongodbInfra.db.users.countDocuments({})) === beforeCount && markerCount === 0, `count ${beforeCount}→${await mongodbInfra.db.users.countDocuments({})}`)
}

// s04 — SP metadata endpoint (S17, plan 11 §2.1): 200 + XML + ACS + content-type
{
  const res = await fetch(`${base}/saml/meta`)
  const text = await res.text()
  check('s04 /saml/meta 200', res.status === 200, String(res.status))
  check('s04 content-type saml-metadata+xml', (res.headers.get('content-type') || '').includes('saml-metadata+xml'), res.headers.get('content-type'))
  check('s04 Content-Disposition attachment', !!res.headers.get('content-disposition')?.includes('-meta.xml'), res.headers.get('content-disposition'))
  check('s04 XML has EntityDescriptor + our AC', text.includes('EntityDescriptor') && text.includes(`${SITE_URL}/saml/login/callback`), text.slice(0, 200))
  check('s04 XML has SLO endpoint', text.includes(`${SITE_URL}/saml/logout/callback`), '')
}

// s05 — cert-expiry sweep (Phase 4 S18): module.start() ran
// sweepSsoCertExpiry() over the seeded certs; rows for sp + provider.
{
  const rows = sweepResult
  check('s05 sweep returned rows (module.start ran)', Array.isArray(rows) && rows.length >= 2, JSON.stringify(rows))
  const spRow = rows.find((r) => (r.label || '').includes('sp-metadata'))
  check('s05 sp-metadata:publicCert parsed (no error)', spRow && !spRow.error && spRow.daysLeft != null, JSON.stringify(spRow))
  const provRow = rows.find((r) => (r.label || '').includes('saml-provider:main'))
  check('s05 saml-provider:main cert parsed', provRow && !provRow.error, JSON.stringify(provRow))
}

server.close()
console.log(`\nS22 live SAML scenarios: ${passed.length} passed, ${failed.length} failed${failed.length ? ` (${failed.join(', ')})` : ''}`)
process.exit(failed.length ? 1 : 0)
