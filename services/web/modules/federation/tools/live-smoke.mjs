/**
 * live-smoke.mjs — the federation module against the REAL runtime.
 *
 * Single process, single origin (beta.example): one live express app plays
 * BOTH A (the RP initiating institution) and B (the home institution holding
 * the invitee's account — the oidc-provider OP). This is the
 * two-instance.sequential.test.mjs scenario matrix, 1:1, with the vi.mock
 * layer replaced by real infrastructure:
 *
 *   REAL:
 *     - Mongo      — FederationPeer / FederationKey / User / ProjectInvite /
 *                     ProjectAuditLogEntry
 *     - Redis      — PKCE state, jti dedup, JWKS cache, rate limits, and the
 *                     oidc-provider adapter (Session/Interaction/
 *                     AuthorizationCode/Grant docs + client SET index)
 *     - express    — a real listening server; outbound `fetch` of our own
 *                     origin is rewritten to the local port
 *     - oidc-provider v9 — the full auth/consent/code interaction dance
 *     - jose       — ES256 key bootstrap, S2S client assertions, id_token
 *     - UI surface (S20) — the module's `router` (admin REST incl. the
 *                     dashboard shell + wizard JSON, invite preview REST,
 *                     export wizard form/result views) and the module's
 *                     `appMiddleware` (leaf EC + /federation/federation-keys)
 *                     over real HTTP, with a mutable `loginAs` session switch
 *                     (alice default / admin for guard checks /
 *                     owner for the export consent dance)
 *   STUBS (the documented app-subsystem seams the two-instance test mocks —
 *     grant plumbing, project bytes):
 *     - CollaboratorsGetter.promises.getMemberIdPrivilegeLevel
 *     - CollaboratorsGetter.promises.getProjectOwnerId
 *     - CollaboratorsHandler.promises.addUserIdToProject
 *     - UserSessionsManager.promises.trackSession
 *
 * Run (from services/web/):
 *   MONGO_CONNECTION_STRING=mongodb://127.0.0.1:27107/fedsmoke \
 *   REDIS_HOST=127.0.0.1 REDIS_PORT=6380 \
 *   PUBLIC_URL=https://beta.example \
 *   SESSION_SECRET=any-32-plus-chars \
 *   timeout 180 node modules/federation/tools/live-smoke.mjs
 *
 * The script defaults those env vars to the dedicated docker ports, so a
 * bare invocation works. Env must be visible to @overleaf/settings at import.
 */

// ── env (SET BEFORE any settings-dependent import — Settings reads env at
//    module evaluation time; dynamic imports below run after this) ───────────
process.env.MONGO_CONNECTION_STRING ??= 'mongodb://127.0.0.1:27107/fedsmoke'
process.env.REDIS_HOST ??= '127.0.0.1'
process.env.REDIS_PORT ??= '6380'
process.env.PUBLIC_URL ??= 'https://beta.example'
process.env.SESSION_SECRET ??= 'fed-live-smoke-2025-0000000000000000000000'

import crypto from 'node:crypto'
import { SignJWT } from 'jose'
import express from 'express'
import pug from 'pug'

// ── real runtime (dynamic: Settings/Mongoose read env + connect at import) ──
const Settings = (await import('@overleaf/settings')).default
Settings.federation.enabled = true // master toggle (mutable plain object)
// S20 UI e2e: both default false — the admin guard (isUserSiteAdmin)
// hard-gates on `adminPrivilegeAvailable` before the `isAdmin` lookup, and
// the B-side export S2S action hard-gates on `federation.export.enabled`.
Settings.adminPrivilegeAvailable = true
Settings.federation.export.enabled = true

const S2sRouter = (await import('../s2s/S2sRouter.mjs')).default
const { mountBridge } = await import('../oidc/bridge.mjs')
const CallbackRouter = (await import('../rp/CallbackRouter.mjs')).default
const { getOidcProvider } = await import('../oidc/createProvider.mjs')
const { ensureBootstrapped } = await import('../oidf/keystore.mjs')
const { buildS2sRequest, getClientId, getS2sEndpoint } = await import(
  '../oidf/ClientAssertionClient.mjs'
)
const { FederatedInviteController } = await import(
  '../invite/FederatedInviteController.mjs'
)
const { FederationPeer } = await import('../app/models/FederationPeer.mjs')
const { User } = await import('../../../app/src/models/User.mjs')
const { ProjectInvite } = await import('../../../app/src/models/ProjectInvite.mjs')
const { ProjectAuditLogEntry } = await import(
  '../../../app/src/models/ProjectAuditLogEntry.mjs'
)
const CollaboratorsGetter = (
  await import(
    '../../../app/src/Features/Collaborators/CollaboratorsGetter.mjs'
  )
).default
const CollaboratorsHandler = (
  await import(
    '../../../app/src/Features/Collaborators/CollaboratorsHandler.mjs'
  )
).default
const UserSessionsManager = (
  await import(
    '../../../app/src/Features/User/UserSessionsManager.mjs'
  )
).default
const { Project } = await import('../../../app/src/models/Project.mjs')
const { FederationExportGrant } = await import(
  '../app/models/FederationExportGrant.mjs'
)
const db = (await import('../../../app/src/infrastructure/mongodb.mjs')).db
// S20 UI surface mounts (the module's own router + appMiddleware, index.mjs).
const AdminRouter = (await import('../admin/AdminRouter.mjs')).default
const InviteRouter = (await import('../invite/FederatedInviteRouter.mjs'))
  .default
const ExportRouter = (await import('../invite/FederatedExportRouter.mjs'))
  .default
const { leafHandler } = await import('../oidf/leaf.mjs')
const { leafJwksPayload, listPublicKeys } = await import('../oidf/keystore.mjs')

// ── Mongoose + Redis (the app's own infrastructure, same singletons the
//    module uses — no extra clients, no extra deps) ─────────────────────────
const MongooseInfra = (await import('../../../app/src/infrastructure/Mongoose.mjs'))
  .default
const mongoose = MongooseInfra.default ?? MongooseInfra
await mongoose.connectionPromise
await mongoose.connection.dropDatabase()
// Same client the module uses (Settings.redis.federation → web fallback).
// flushall() is safe: this Redis instance is dedicated to the smoke run.
const RedisWrapper = (await import('../../../app/src/infrastructure/RedisWrapper.mjs'))
  .default
const redis = RedisWrapper.client()

// ── seed: keystore (real ES256 over the real Mongo model) ───────────────────
await ensureBootstrapped()
const keyRow = await (await import('../app/models/FederationKey.mjs'))
  .FederationKey.findOne({ purpose: 'federation', state: 'active' })
const anchorJwks = JSON.stringify({ keys: [keyRow.publicKey] })
await FederationPeer.updateOne(
  { origin: 'beta.example' },
  {
    origin: 'beta.example',
    status: 'approved',
    direction: 'both',
    mode: 'pairwise',
    kid: keyRow.kid,
    anchorJwks,
    killOutstandingCodes: false,
  },
  { upsert: true },
)

// ── seed: the two local accounts (alice = the invitee, owner = the viewer) ──
// The invited project id (ProjectInvite.projectId is an ObjectId in the real
// schema — the wire payload carries `projectRef` separately). The invite row
// is seeded once and survives per-scenario flushall-free deletes only via
// resetState's re-upsert; runAuthorize upserts it fresh each time.
const INVITE_PROJECT_ID = new mongoose.Types.ObjectId().toHexString()
const inviteExists = () =>
  ProjectInvite.exists({ projectId: INVITE_PROJECT_ID, 'federated.status': 'active' })

const [alice, owner] = await User.create([
  {
    email: 'alice@beta.example',
    first_name: 'Alice',
    last_name: 'Beta',
    institution: 'Beta University',
    suspended: false,
    analyticsId: crypto.randomUUID(),
  },
  {
    email: 'owner@beta.example',
    first_name: 'Owner',
    last_name: 'One',
    institution: '',
    suspended: false,
    analyticsId: crypto.randomUUID(),
  },
])

// S20 UI e2e: the site admin (admin-guard positive path) + the B-side
// project the export wizard targets (2a: owner B-native, live consent
// grant to home A's client — minted on demand by the export scenarios).
const admin = await User.create({
  email: 'admin@beta.example',
  first_name: 'Admin',
  last_name: 'One',
  institution: '',
  suspended: false,
  isAdmin: true,
  analyticsId: crypto.randomUUID(),
})
const bProject = await Project.create({
  name: 'beta project',
  owner_ref: owner._id,
  version: 1,
  active: true,
})

// ── STUBS: the 4 app-subsystem seams (everything else is real) ─────────────
const grants = []
const sessions = []
CollaboratorsGetter.promises.getMemberIdPrivilegeLevel = async () => 'readAndWrite'
CollaboratorsGetter.promises.getProjectOwnerId = async () =>
  String(owner._id)
CollaboratorsHandler.promises.addUserIdToProject = async (...args) => {
  grants.push(args)
  return {}
}
UserSessionsManager.promises.trackSession = async (...args) => {
  sessions.push(args)
}

// ── app + mount (order LOCKED: S2S → bridge → callback → provider) ──────────
// `loginAs` is the mutable session switch: default alice (scenarios 01–16),
// admin for the admin-gated routes, owner for the export consent dance.
let loginAs = alice
const app = express()
app.use((req, res, next) => {
  req.headers.host = 'beta.example'
  next()
})
app.use(express.json())
app.use((req, res, next) => {
  // B-side login: the visitor is logged in as `loginAs` (the federated
  // invitee's account on this origin by default — single-origin variant).
  req.session = req.session ?? {}
  req.session.user = req.session.user ?? { _id: String(loginAs._id) }
  // Consent view: the bridge res.render's with the absolute template path.
  // Some controllers pass extensionless paths (`'federation'`) expecting
  // engine resolution — append `.pug` for the harness renderFile.
  res.render = (view, locals) =>
    new Promise((resolve, reject) => {
      const tpl = view.endsWith('.pug') ? view : `${view}.pug`
      pug.renderFile(tpl, locals || {}, (err, html) => {
        if (err) return reject(err)
        res.status(res.statusCode || 200).send(html)
        resolve()
      })
    })
  next()
})
S2sRouter.apply(app)
mountBridge(app)
CallbackRouter.apply(app)
app.use('/federation/oidc', async (req, res, next) => {
  try {
    const provider = await getOidcProvider()
    await provider.callback()(req, res, next)
  } catch (err) {
    next(err)
  }
})

// ── UI surface (S20): the module's `router` + `appMiddleware` (index.mjs) ──
AdminRouter.apply(app, null, null)
InviteRouter.apply(app, null, null)
ExportRouter.apply(app, null, null)
// Mirror `appMiddleware` (app-level leaf discovery + public key listing).
// The OIDF wire path is FIXED by the specification (not this repo's
// kebab URL rule) — disabled for that literal only (mirror index.mjs).
// eslint-disable-next-line @overleaf/prefer-kebab-url
app.get('/.well-known/openid-federation', (req, res, next) => {
  leafHandler(req, res, next)
})
app.get('/federation/federation-keys', async (req, res, next) => {
  try {
    const jwks = await leafJwksPayload()
    const keys = await listPublicKeys()
    return res.json({ kid: keys.map((k) => k.kid), jwks })
  } catch (error) {
    next(error)
  }
})

const server = app.listen(0, '127.0.0.1')
await new Promise(resolve => server.on('listening', resolve))
const base = `http://127.0.0.1:${server.address().port}`

// The A-side modules fetch `https://beta.example/...` (CodeExchange,
// callPeer, JWKS). Rewrite our own origin to the live local app.
const origFetch = globalThis.fetch
globalThis.fetch = (input, init) => {
  const raw = typeof input === 'string' ? input : String(input?.url ?? input)
  if (raw.startsWith('https://beta.example')) {
    const u = new URL(raw)
    return origFetch(`${base}${u.pathname}${u.search}`, init)
  }
  return origFetch(input, init)
}

// ── helpers (ported from two-instance.sequential.test.mjs) ──────────────────
const cookieHeader = jar => [...jar].map(([k, v]) => `${k}=${v}`).join('; ')

async function driveDance(authUrl) {
  const jar = new Map()
  let url = authUrl
  let method = 'GET'
  for (let hop = 0; hop < 24; hop += 1) {
    const u = new URL(url, 'https://beta.example')
    const local = `${base}${u.pathname}${u.search}`
    const res = await fetch(local, {
      method,
      redirect: 'manual',
      headers: { cookie: cookieHeader(jar) },
    })
    for (const c of res.headers.getSetCookie?.() ?? []) {
      const i = c.indexOf('=')
      if (i <= 0) continue
      jar.set(c.slice(0, i).trim(), c.slice(i + 1).split(';')[0].trim())
    }
    const loc = res.headers.get('location')
    if (res.status >= 300 && res.status < 400 && loc) {
      const abs = new URL(loc, 'https://beta.example')
      if (abs.pathname === '/federation/oidc/rp/callback' && abs.searchParams.has('code')) {
        return {
          code: abs.searchParams.get('code'),
          state: abs.searchParams.get('state'),
          cookies: cookieHeader(jar),
        }
      }
      url = abs.href
      method = 'GET'
      continue
    }
    if (res.status >= 500) {
      const raw = await res.text()
      const pre = raw.match(/<pre>([\s\S]*?)<\/pre>/)
      const title = raw.match(/<h1>([\s\S]*?)<\/h1>/)
      throw new Error(
        `dance HTTP ${res.status} at: ${u.href}\n  h1: ${title?.[1]}\n  pre: ${pre ? pre[1].trim() : ''}`,
      )
    }
    if (res.status === 200) {
      const m = url.match(/\/interact\/([^/?]+)/)
      if (m) {
        const html = await res.text()
        if (html.includes('consent-form')) {
          url = `/federation/oidc/interact/${m[1]}/consent`
          method = 'POST'
          continue
        }
      }
      throw new Error(`unexpected 200 during dance: ${url}`)
    }
    throw new Error(`dance error ${res.status} at: ${url}`)
  }
  throw new Error('driveDance: hop limit exceeded')
}

async function runAuthorize(anchor = 'alice@beta.example:beta.example') {
  const fakeReq = {
    body: {
      projectId: INVITE_PROJECT_ID,
      anchor,
      privileges: 'readAndWrite',
    },
    user: { _id: String(owner._id) },
    session: {},
  }
  const fakeRes = {
    statusCode: 200,
    location: null,
    body: undefined,
    status(c) {
      this.statusCode = c
      return this
    },
    json(o) {
      this.body = o
      return this
    },
    redirect(l) {
      this.location = l
      return this
    },
  }
  let handlerError
  await FederatedInviteController.handleAuthorize(
    fakeReq,
    fakeRes,
    error => (handlerError = error),
  )
  if (handlerError) throw handlerError
  if (fakeRes.location == null) {
    throw new Error(
      `handleAuthorize took an error path (status ${fakeRes.statusCode}): ${JSON.stringify(fakeRes.body)}`,
    )
  }
  return fakeRes
}

function postS2s(built) {
  return fetch(`${base}/federation/s2s`, {
    method: 'POST',
    redirect: 'manual',
    headers: {
      'Content-Type': 'application/json',
      client_assertion: built.headers.client_assertion,
    },
    body: JSON.stringify(built.body),
  })
}

// ── scenario state reset (real equivalents of the fake per-test flushall) ──
async function resetState() {
  await redis.flushall()
  grants.length = 0
  sessions.length = 0
  await FederationPeer.updateOne(
    { origin: 'beta.example' },
    { status: 'approved', killOutstandingCodes: false },
  )
  await ProjectAuditLogEntry.deleteMany({})
  await ProjectInvite.deleteMany({})
  Settings.federation.enabled = true
}

// ── scenario checks ──────────────────────────────────────────────────────────
const check = (name, cond, extra = undefined) => {
  if (cond) {
    console.log(`  PASS ${name}`)
  } else {
    console.log(`  FAIL ${name}${extra ? ` — ${JSON.stringify(extra)}` : ''}`)
    return check.failed += 1
  }
  return true
}
check.failed = 0

const CLIENT_SET = `federation:oidc:client:urn:overleaf-federation:client:beta.example`

const scenarios = [
  {
    name: '01 OIDC code dance: federated invite → consent → code → mirror session',
    fn: async () => {
      const res0 = await runAuthorize()
      check('authorize redirects to B auth URL', res0.location?.includes('/federation/oidc/auth?'))
      check('authorization uses S256 PKCE', res0.location?.includes('code_challenge_method=S256'))
      check('invite row seeded before the dance', await inviteExists())
      const dance = await driveDance(res0.location)
      check('code minted', Boolean(dance.code))
      check('state present', Boolean(dance.state))

      const cb = await fetch(
        `${base}/federation/oidc/rp/callback?code=${encodeURIComponent(dance.code)}&state=${encodeURIComponent(dance.state)}`,
        { redirect: 'manual', headers: { cookie: dance.cookies } },
      )
      check('callback 302', cb.status === 302, { status: cb.status })
      check('callback → /project/<inviteProjectId>',
        cb.headers.get('Location') === `/project/${INVITE_PROJECT_ID}`)

      const mirror = await User.findOne({
        'federation.origin': 'beta.example',
        'federation.localName': 'alice@beta.example',
      }).lean()
      check('mirror row (origin, localName), no email', mirror && mirror.email === '')

      check('grant applied (projectId, null, mirrorId, readAndWrite)',
        grants.length === 1 &&
          grants[0][0] === INVITE_PROJECT_ID &&
          grants[0][1] === null &&
          String(grants[0][2]) === String(mirror?._id) &&
          grants[0][3] === 'readAndWrite',
        grants[0])
      const invite = await ProjectInvite.findOne({ projectId: INVITE_PROJECT_ID }).lean()
      check('invite row upserted (federated.authorized)',
        invite && invite.federated?.authorized === true &&
        invite.federated?.localName === 'alice@beta.example')
      check('session tracked', sessions.length === 1)
      const audit = await ProjectAuditLogEntry.findOne({
        operation: 'federation_session_issued',
      }).lean()
      check('audit row federation_session_issued', Boolean(audit))
    },
  },
  {
    name: '02 PKCE one-shot: replayed callback is refused',
    fn: async () => {
      const res0 = await runAuthorize()
      const dance = await driveDance(res0.location)
      const cbUrl =
        `${base}/federation/oidc/rp/callback` +
        `?code=${encodeURIComponent(dance.code)}&state=${encodeURIComponent(dance.state)}`
      const first = await fetch(cbUrl, { redirect: 'manual', headers: { cookie: dance.cookies } })
      check('first callback 302', first.status === 302, { status: first.status })
      const second = await fetch(cbUrl, { redirect: 'manual', headers: { cookie: dance.cookies } })
      check('replay 401', second.status === 401, { status: second.status })
      const body = await second.json()
      check('replay body invalid grant request', body.message === 'invalid grant request')
    },
  },
  {
    name: '03 S2S invited: approved preview (existing local user)',
    fn: async () => {
      const built = await buildS2sRequest('beta.example', 'invited', {
        invitee: { origin: 'beta.example', localName: 'alice@beta.example' },
      })
      const res = await postS2s(built)
      const data = await res.json()
      check('200 ok', res.status === 200 && data.ok === true, data)
      check('approved + displayName', data.payload?.approved === true &&
        data.payload?.displayName === 'Alice Beta', data)
    },
  },
  {
    name: '04 S2S invited: soft deny (nonexistent local user)',
    fn: async () => {
      const built = await buildS2sRequest('beta.example', 'invited', {
        invitee: { origin: 'beta.example', localName: 'ghost@beta.example' },
      })
      const res = await postS2s(built)
      const data = await res.json()
      check('200 ok business', res.status === 200 && data.ok === true, { status: res.status })
      check('approved:false, displayName null',
        data.payload?.approved === false && data.payload?.displayName === null, data)
    },
  },
  {
    name: '05 S2S authorize-invite: approved (B is the oracle) + audit row',
    fn: async () => {
      const built = await buildS2sRequest('beta.example', 'authorize-invite', {
        invitee: { origin: 'beta.example', localName: 'alice@beta.example' },
        project: { ref: 'proj-1' },
      })
      const res = await postS2s(built)
      const data = await res.json()
      check('approved payload (institution)', res.status === 200 &&
        data.payload?.approved === true &&
        data.payload?.institution === 'Beta University', data)
      const audit = await ProjectAuditLogEntry.findOne({
        operation: 'federated_invite_approved',
      }).lean()
      check('audit row federated_invite_approved', Boolean(audit))
    },
  },
  {
    name: '06 S2S authorize-invite: unknown invitee → business refusal + audit row',
    fn: async () => {
      const built = await buildS2sRequest('beta.example', 'authorize-invite', {
        invitee: { origin: 'beta.example', localName: 'ghost@beta.example' },
        project: { ref: 'proj-1' },
      })
      const res = await postS2s(built)
      const data = await res.json()
      check('business refusal invitee-unknown', data.ok === false &&
        data.code === 'invitee-unknown', data)
      const audit = await ProjectAuditLogEntry.findOne({
        operation: 'federated_invite_denied',
      }).lean()
      check('audit row federated_invite_denied', Boolean(audit))
    },
  },
  {
    name: '07 S2S replay: second delivery of the same assertion is refused',
    fn: async () => {
      const built = await buildS2sRequest('beta.example', 'invited', {
        invitee: { origin: 'beta.example', localName: 'alice@beta.example' },
      })
      const first = await postS2s(built)
      check('first 200', first.status === 200, { status: first.status })
      const second = await postS2s(built)
      const data = await second.json()
      check('replay 401 replay-jti', second.status === 401 && data.code === 'replay-jti', data)
    },
  },
  {
    name: '08 S2S bad signature → 401 bad-signature',
    fn: async () => {
      const built = await buildS2sRequest('beta.example', 'invited', {
        invitee: { origin: 'beta.example', localName: 'alice@beta.example' },
      })
      // Flip a MIDDLE char of the signature (a last-char flip can land in
      // the dropped base64url padding bits and decode identically).
      const parts = built.headers.client_assertion.split('.')
      const sig = parts[2]
      const mid = Math.floor(sig.length / 2)
      const flipped = sig[mid] === 'A' ? 'B' : 'A'
      const bad = `${parts[0]}.${parts[1]}.${sig.slice(0, mid)}${flipped}${sig.slice(mid + 1)}`
      const res = await postS2s({ ...built, headers: { ...built.headers, client_assertion: bad } })
      const data = await res.json()
      check('401 bad-signature', res.status === 401 && data.code === 'bad-signature', data)
    },
  },
  {
    name: '09 S2S unknown kid → 401 unknown-kid (key not pinned)',
    fn: async () => {
      const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
      const jwk = kp.privateKey.export({ format: 'jwk' })
      const now = Math.floor(Date.now() / 1000)
      const unsigned = await new SignJWT({
        iss: getClientId(),
        sub: getClientId(),
        jti: crypto.randomUUID(),
        aud: getS2sEndpoint(),
      })
        .setProtectedHeader({ alg: 'ES256', kid: 'not-pinned' })
        .setIssuedAt(now)
        .setExpirationTime(now + 300)
        .sign(jwk)
      const built = {
        headers: { 'Content-Type': 'application/json', client_assertion: unsigned },
        body: {
          action: 'invited',
          from: 'beta.example',
          to: 'beta.example',
          ts: Date.now(),
          payload: { invitee: { origin: 'beta.example', localName: 'alice@beta.example' } },
        },
      }
      const res = await postS2s(built)
      const data = await res.json()
      check('401 unknown-kid', res.status === 401 && data.code === 'unknown-kid', data)
    },
  },
  {
    name: '10 S2S rate limit: budget exceeded → 429 + Allow-Retry-After',
    fn: async () => {
      let first429 = -1
      let lastData
      let lastRetry
      for (let i = 0; i < 31; i += 1) {
        const built = await buildS2sRequest('beta.example', 'authorize-invite', {
          invitee: { origin: 'beta.example', localName: 'alice@beta.example' },
          project: { ref: 'proj-1' },
        })
        const res = await postS2s(built)
        if (res.status === 429 && first429 < 0) {
          first429 = i
          lastRetry = res.headers.get('Allow-Retry-After')
          lastData = await res.json()
        }
      }
      check('a 429 landed within the 31', first429 > 0, { first429 })
      check('429 code rate-limited', lastData?.code === 'rate-limited', lastData)
      check('Allow-Retry-After header present', Boolean(lastRetry), lastRetry)
    },
  },
  {
    name: '11a S2S revoke + killOutstandingCodes: codes swept, sessions survive',
    fn: async () => {
      const res0 = await runAuthorize()
      const dance = await driveDance(res0.location)
      check('fresh code minted', Boolean(dance.code))

      const beforeCodes = await redis.smembers(CLIENT_SET)
      check('client SET has a code', beforeCodes.some(k => k.startsWith('federation:oidc:AuthorizationCode:')),
        beforeCodes)
      const beforeSessions = await redis.keys('federation:oidc:Session:*')
      const beforeSubs = await redis.keys('federation:oidc:sub:*')
      const beforeGrants = await redis.keys('federation:oidc:Grant:*')
      check('sessions exist before sweep', beforeSessions.length >= 1)

      await FederationPeer.updateOne({ origin: 'beta.example' }, { killOutstandingCodes: true })
      const built = await buildS2sRequest('beta.example', 'revoke', {})
      const res = await postS2s(built)
      const data = await res.json()
      check('revoke ok', res.status === 200 && data.ok === true && data.payload?.origin === undefined, data)
      const peer = await FederationPeer.findOne({ origin: 'beta.example' }).lean()
      check('peer status revoked', peer?.status === 'revoked')

      const afterCodes = await redis.smembers(CLIENT_SET)
      check('sweep emptied the client SET', afterCodes.length === 0, afterCodes)
      for (const docKey of beforeCodes) {
        check(`swept doc gone: ${docKey.slice(0, 40)}…`, (await redis.get(docKey)) === null)
      }
      const afterSessions = await redis.keys('federation:oidc:Session:*')
      const afterSubs = await redis.keys('federation:oidc:sub:*')
      const afterGrants = await redis.keys('federation:oidc:Grant:*')
      check('B-side sessions survive (not over-cross)',
        JSON.stringify(afterSessions) === JSON.stringify(beforeSessions))
      check('sub index survives', JSON.stringify(afterSubs) === JSON.stringify(beforeSubs))
      check('Grant doc survives', JSON.stringify(afterGrants) === JSON.stringify(beforeGrants))

      // While the peer is revoked, a second S2S revoke is refused at the
      // peer pre-lookup (approved-only, 03 §6); the ACTION-level idempotency
      // (match filter, no double transition) is unit-covered (revoke.test.mjs).
      const again = await postS2s(await buildS2sRequest('beta.example', 'revoke', {}))
      const againData = await again.json()
      check('second revoke refused at pre-lookup (peer-not-approved)',
        again.status === 401 && againData.code === 'peer-not-approved', againData)

      // Re-approve for scenario 11b (fresh revoked transition).
      await FederationPeer.updateOne(
        { origin: 'beta.example' },
        { status: 'approved', killOutstandingCodes: false },
      )
    },
  },
  {
    name: '11b S2S revoke: trust + follow-up refused + audit row',
    fn: async () => {
      const built = await buildS2sRequest('beta.example', 'revoke', {})
      const res = await postS2s(built)
      const data = await res.json()
      check('revoke ok', res.status === 200 && data.ok === true)
      const peer = await FederationPeer.findOne({ origin: 'beta.example' }).lean()
      check('peer status revoked', peer?.status === 'revoked')
      const audit = await ProjectAuditLogEntry.findOne({
        operation: 'federation_peer_trust_revoked',
      }).lean()
      check('audit row federation_peer_trust_revoked', Boolean(audit))

      const followUp = await buildS2sRequest('beta.example', 'authorize-invite', {
        invitee: { origin: 'beta.example', localName: 'alice@beta.example' },
        project: { ref: 'proj-1' },
      })
      const up = await postS2s(followUp)
      const upData = await up.json()
      check('follow-up 401 peer-not-approved',
        up.status === 401 && upData.code === 'peer-not-approved', upData)
    },
  },
  {
    name: '12 S2S federation off → 200 machine-readable refusal',
    fn: async () => {
      Settings.federation.enabled = false
      const built = await buildS2sRequest('beta.example', 'invited', {
        invitee: { origin: 'beta.example', localName: 'alice@beta.example' },
      })
      const res = await postS2s(built)
      const data = await res.json()
      check('200 federation-off', res.status === 200 && data.ok === false &&
        data.code === 'federation-off', data)
    },
  },
  {
    name: '13 OIDF discovery over HTTP: leaf EC + federation-keys',
    fn: async () => {
      const leaf = await fetch(`${base}/.well-known/openid-federation`, {
        headers: { Accept: 'application/entity-statement+jwt' },
      })
      const leafBody = await leaf.text()
      check('leaf 200', leaf.status === 200, { status: leaf.status })
      check(
        'leaf content-type entity-statement+jwt',
        (leaf.headers.get('Content-Type') || '').startsWith(
          'application/entity-statement+jwt',
        ),
        leaf.headers.get('Content-Type'),
      )
      check(
        'leaf no-store cache',
        (leaf.headers.get('Cache-Control') || '').includes('no-store'),
      )
      const parts = leafBody.split('.')
      check(
        'leaf is a 3-part signed EC',
        parts.filter((p) => p.length > 0).length === 3,
      )

      const keysRes = await fetch(`${base}/federation/federation-keys`)
      const data = await keysRes.json()
      check('federation-keys 200', keysRes.status === 200, { status: keysRes.status })
      check(
        'bootstrap kid listed',
        Array.isArray(data.kid) && data.kid.includes(keyRow.kid),
        data.kid,
      )
      check(
        'jwks payload has keys',
        Array.isArray(data.jwks?.keys) && data.jwks.keys.length >= 1,
      )
    },
  },
  {
    name: '14 admin dashboard over HTTP: non-admin redirect / admin 200 shell',
    fn: async () => {
      // Non-admin (alice: no `isAdmin` bit) hits `_redirectToRestricted`.
      loginAs = alice
      const denied = await fetch(`${base}/admin/federation`, {
        redirect: 'manual',
      })
      check('non-admin 302', denied.status === 302, { status: denied.status })
      check(
        'non-admin redirect → /restricted?from=',
        (denied.headers.get('Location') || '').startsWith('/restricted?from='),
        denied.headers.get('Location'),
      )

      // Admin (admin user seeded isAdmin: true + adminPrivilegeAvailable).
      loginAs = admin
      const page = await fetch(`${base}/admin/federation`, {
        redirect: 'manual',
      })
      const html = await page.text()
      check('admin dashboard 200', page.status === 200, { status: page.status })
      check(
        'shell meta name=federation content=admin',
        html.includes('name="federation" content="admin"'),
        html.slice(0, 400),
      )
      check('wizard-list container present', html.includes('id="wizard-list"'))
    },
  },
  {
    name: '15 admin REST over HTTP: wizard JSON + peers/keys/audit',
    fn: async () => {
      // A fresh S2S receipt (federation audit row) is required both for
      // wizard step 5 (s2s-proven) and for the audit-listing assertion.
      const built = await buildS2sRequest('beta.example', 'authorize-invite', {
        invitee: { origin: 'beta.example', localName: 'alice@beta.example' },
        project: { ref: 'proj-1' },
      })
      const s2s = await postS2s(built)
      const s2sData = await s2s.json()
      check('S2S receipt 200 ok', s2s.status === 200 && s2sData.ok === true, s2sData)

      const wizRes = await fetch(`${base}/admin/federation/wizard`)
      const wiz = await wizRes.json()
      check('wizard 200', wizRes.status === 200, { status: wizRes.status })
      check(
        'wizard ok + 5 steps all done',
        wiz.ok === true &&
          wiz.steps.length === 5 &&
          wiz.steps.every((s) => s.done === true),
        wiz,
      )
      check(
        'wizard settings incl s2sFetchTimeoutMs',
        typeof wiz.settings?.s2sFetchTimeoutMs === 'number',
        wiz.settings,
      )
      check(
        'wizard step names (module→leaf→s2s)',
        wiz.steps.map((s) => s.name).join(',') ===
          'module-enabled,identity-key,first-peer-approved,leaf-published,s2s-proven',
        wiz.steps.map((s) => s.name),
      )

      const peers = await (await fetch(`${base}/admin/federation/peers`)).json()
      check(
        'peers: beta.example approved',
        peers.peers?.some((p) => p.origin === 'beta.example' && p.status === 'approved'),
        peers.peers,
      )

      const keysData = await (await fetch(`${base}/admin/federation/keys`))
        .json()
      check(
        'keys: bootstrap kid active',
        keysData.keys?.some((k) => k.kid === keyRow.kid && k.state === 'active'),
        keysData.keys,
      )

      const auditData = await (await fetch(`${base}/admin/federation/audit`))
        .json()
      check(
        'audit: federation rows listed',
        auditData.entries?.some(
          (e) => e.operation === 'federated_invite_approved',
        ),
        auditData.entries?.map((e) => e.operation),
      )
    },
  },
  {
    name: '16 invite preview REST over HTTP (was in-process only)',
    fn: async () => {
      loginAs = alice
      const res = await fetch(
        `${base}/api/federation/invite/preview?anchor=${encodeURIComponent('alice@beta.example:beta.example')}`,
      )
      const data = await res.json()
      check('preview 200', res.status === 200, { status: res.status })
      check(
        'approved + displayName',
        data.approved === true && data.displayName === 'Alice Beta',
        data,
      )
    },
  },
  {
    name: '17 export wizard REST: form render + refusal path (no consent grant)',
    fn: async () => {
      loginAs = alice
      const form = await fetch(`${base}/federation/export`)
      const formHtml = await form.text()
      check('export form 200', form.status === 200, { status: form.status })
      check(
        'form lists the beta.example peer',
        formHtml.includes('value="beta.example"'),
        formHtml.slice(0, 400),
      )
      check('form has fed-csrf meta', formHtml.includes('name="fed-csrf"'))

      const denied = await fetch(`${base}/federation/export`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          origin: 'beta.example',
          projectId: String(bProject._id),
        }),
      })
      await denied.text()
      check('export refused 403 (no live consent)', denied.status === 403, {
        status: denied.status,
      })
      const audit = await ProjectAuditLogEntry.findOne({
        operation: 'federation_export_denied',
      }).lean()
      check('audit row federation_export_denied', Boolean(audit))
    },
  },
  {
    name: '18 export wizard happy path: re-driven consent → S2S → PAT result view',
    fn: async () => {
      // `resetState()` flushed Redis (the consent grant is gone): re-drive
      // the dance AS OWNER so a live (owner, beta-client) grant exists —
      // the export POST (S2S export-project) only checks that B-native
      // owner holds a live consent grant to home A's client (09 §2.1). It
      // does NOT consume the A-side `rp/callback` (that's the v1 identity
      // mirror, a separate path) — the grant is minted at the consent step
      // inside `driveDance`, before the code is issued.
      loginAs = owner
      const res0 = await runAuthorize('owner@beta.example:beta.example')
      const dance = await driveDance(res0.location)
      check('consent code minted (owner)', Boolean(dance.code))

      // loginAs must stay owner for the export POST? No — the POST is
      // requireLogin (any A-side user); the B-side checks (owner, beta
      // -client) against the grant minted above. Keep it owner for clarity.
      const res = await fetch(`${base}/federation/export`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          origin: 'beta.example',
          projectId: String(bProject._id),
        }),
      })
      const html = await res.text()
      check('export result 200', res.status === 200, { status: res.status })
      const pat = html.match(/olp_[A-Za-z0-9]{36}/)?.[0]
      check('PAT rendered (olp_ + 36 chars)', Boolean(pat))
      check(
        'clone command carries beta.example/git',
        html.includes('beta.example/git/'),
      )
      check('scope federation:git_bridge', html.includes('federation:git_bridge'))

      // The raw PAT is never persisted: sha256 + prefix only (2a/09 §3).
      const patDoc = await db.oauthAccessTokens
        .findOne({ scope: 'federation:git_bridge', user_id: String(owner._id) })
        .catch(() => null)
      check(
        'sha256 PAT doc (partial prefix)',
        Boolean(patDoc) && patDoc.accessTokenPartial === pat?.substring(0, 8),
        patDoc,
      )
      check('raw PAT not persisted', Boolean(patDoc) && !JSON.stringify(patDoc).includes(pat))

      const ledger = await FederationExportGrant.findOne({
        projectId: String(bProject._id),
      }).lean()
      check(
        'ledger row exported (owner)',
        Boolean(ledger) &&
          ledger.status === 'exported' &&
          String(ledger.owner) === String(owner._id),
        ledger,
      )
      const audit = await ProjectAuditLogEntry.findOne({
        operation: 'federation_export_requested',
      }).lean()
      check('audit row federation_export_requested', Boolean(audit))
    },
  },
]

// ── run ──────────────────────────────────────────────────────────────────────
let failures = 0
let index = 0
for (const s of scenarios) {
  index += 1
  await resetState()
  console.log(`\n── scenario ${String(index).padStart(2, '0')}: ${s.name}`)
  try {
    await s.fn()
  } catch (error) {
    console.log(`  EXCEPTION: ${error.stack || error.message}`)
    check.failed += 1
  }
  failures = check.failed
}

Settings.federation.enabled = true
console.log(`\n${scenarios.length} scenarios · ${failures === 0 ? 'ALL PASS' : `${failures} CHECK(S) FAILED`}`)
console.log(`base=${base}\n`)

globalThis.fetch = origFetch
server.close()
await redis.quit().catch(() => {})
process.exit(failures === 0 ? 0 : 1)