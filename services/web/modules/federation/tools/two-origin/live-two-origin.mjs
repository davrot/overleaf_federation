/**
 * live-two-origin.mjs — content-bridge 2d (plan 09 §6): the two-real-
 * origins (A≠B) live docker smoke. Goal step 4 of 4 for content-bridge
 * v2 (Goal 3ea7bb53 / 3dad1c9e).
 *
 * A and B are two REAL express instances on two origins (alpha.example /
 * beta.example) sharing one real Mongo + one real Redis (docker). This is
 * the closure check for content-bridge v2:
 *   1 v1 identity dance on A (RP) → login + consent at B's OP → mirror +
 *     the CONSENT GRANT (accountId=owner@beta, client=urn:…:client:alpha)
 *     — the exact binding 2a's export-project requires (plan 09 §2.1)
 *   2 A-side export wizard (2b) → S2S export-project → B mints the
 *     federation:git_bridge PAT (2a)
 *   3 live PAT checks against B's git-bridge REST surface:
 *       GET  /api/v0/docs/<id>           read  → reaches the controller
 *                                          (auth passed; 400 = missing
 *                                          project-history sidecar,
 *                                          deterministic)
 *       POST /api/v0/docs/<id>/snapshots write → 403 (2c guard: the
 *                                          federation:-scoped PAT is
 *                                          refused before any
 *                                          controller/oracle; a normal
 *                                          PAT passes the guard → 500
 *                                          controller)
 *   4 S2S export-project rate limit (10/120s per (caller, project) →
 *     429 on the 11th)
 *   5 S2S revoke (A→B) → B marks the alpha peer revoked + 2c sweep
 *     (ledger → revoked + the minted PAT deleted, scope-guarded)
 *   6 post-revoke: dead PAT → 401 everywhere + wizard 502
 *     (peer-not-approved) + S2S 401 peer-not-approved
 *
 * Real end to end (no vi.mock layer): Mongo (User/Project/ProjectInvite/
 * ProjectAuditLogEntry/FederationPeer/FederationKey + oauthAccessTokens),
 * Redis (PKCE state, jti dedup, JWKS cache, rate limits + oidc-provider
 * adapter docs incl. the consent Grant + the (owner, alpha-client)
 * account index), express + oidc-provider v9 + jose, two processes.
 *
 * Fakes (the documented v1 live-smoke stub layer, SESSION 10):
 *   - login sessions (per-process fake-login middleware; carol/owner
 *     rows are REAL in the shared Mongo)
 *   - the 4 app-subsystem seams v1 already stubs: CollaboratorsGetter ×2,
 *     CollaboratorsHandler.addUserIdToProject,
 *     UserSessionsManager.trackSession
 *
 * Shared keystore (documented simplification, property of the v1 single-
 * origin smoke): the driver bootstraps the keystore ONCE (shared db)
 * before spawning B, so both origins sign with the same pinned ES256 key
 * (TOFU admin pin ×2, peer rows both directions).
 *
 * Run (from services/web/; containers fed-smoke-mongo 27107 +
 * fed-smoke-redis 6380):
 *   timeout 240 node modules/federation/tools/two-origin/live-two-origin.mjs
 * The driver owns the fedsmoke2 db (drop + reseed) and spawns
 * live-smoke-b.mjs (origin B). Env defaults are baked in.
 */

process.env.MONGO_CONNECTION_STRING ??= 'mongodb://127.0.0.1:27107/fedsmoke2'
process.env.REDIS_HOST ??= '127.0.0.1'
process.env.REDIS_PORT ??= '6380'
process.env.PUBLIC_URL ??= 'https://alpha.example'
process.env.SESSION_SECRET ??= 'fed-live-smoke-2025-0000000000000000000000'

import crypto from 'node:crypto'
import { spawn } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const A_ORIGIN = 'alpha.example'
const B_ORIGIN = 'beta.example'
const TOOL_DIR = path.dirname(fileURLToPath(import.meta.url))

// ── real runtime (dynamic: Settings/Mongoose read env + connect at import)
const Settings = (await import('@overleaf/settings')).default
Settings.federation.enabled = true

const { ensureBootstrapped } = await import('../../oidf/keystore.mjs')
const { FederationKey } = await import('../../app/models/FederationKey.mjs')
const { FederationPeer } = await import('../../app/models/FederationPeer.mjs')
const { FederationExportGrant } = await import(
  '../../app/models/FederationExportGrant.mjs'
)
const { User } = await import('../../../../app/src/models/User.mjs')
const { Project } = await import('../../../../app/src/models/Project.mjs')
const { ProjectAuditLogEntry } = await import(
  '../../../../app/src/models/ProjectAuditLogEntry.mjs'
)
const S2sRouter = (await import('../../s2s/S2sRouter.mjs')).default
const CallbackRouter = (await import('../../rp/CallbackRouter.mjs')).default
const { accountIndexKey } = await import('../../oidc/RedisOidcProviderAdapter.mjs')
const { federationClientId } = await import('../../oidc/clients.mjs')
const { buildS2sRequest } = await import('../../oidf/ClientAssertionClient.mjs')
const { FederatedInviteController } = await import(
  '../../invite/FederatedInviteController.mjs'
)
const { handleExport } = await import('../../invite/FederatedExportController.mjs')
const GitBridgePATManager = (await import(
  '../../../git-bridge/app/src/GitBridgePATManager.mjs'
)).default
const Express = (await import('express')).default
const CollaboratorsGetter = (
  await import('../../../../app/src/Features/Collaborators/CollaboratorsGetter.mjs')
).default
const CollaboratorsHandler = (
  await import('../../../../app/src/Features/Collaborators/CollaboratorsHandler.mjs')
).default
const UserSessionsManager = (
  await import('../../../../app/src/Features/User/UserSessionsManager.mjs')
).default
const db = (await import('../../../../app/src/infrastructure/mongodb.mjs')).db
const RedisWrapperModule = (
  await import('../../../../app/src/infrastructure/RedisWrapper.mjs')
).default
const redis = RedisWrapperModule.client('federation')

const MongooseInfra = (
  await import('../../../../app/src/infrastructure/Mongoose.mjs')
).default
const mongoose = MongooseInfra.default ?? MongooseInfra
await mongoose.connectionPromise
// The driver OWNS the shared db for the smoke run (B child seeds nothing).
await mongoose.connection.dropDatabase()
// Fresh Redis (S2S rate-limit keys + oidc-provider adapter docs from any
// prior run must not leak into scenario 01/04's deterministic export budget
// — dedicated smoke container, v1 live-smoke precedent).
await redis.flushall()

// ── stubs: the 4 app-subsystem seams (everything else is real) ────────────
const grants = []
const sessions = []
let carol
let owner
CollaboratorsGetter.promises.getMemberIdPrivilegeLevel = async () => 'readAndWrite'
CollaboratorsGetter.promises.getProjectOwnerId = async () => String(carol?._id ?? '')
CollaboratorsHandler.promises.addUserIdToProject = async (...args) => {
  grants.push(args)
  return {}
}
UserSessionsManager.promises.trackSession = async (...args) => {
  sessions.push(args)
}

// ── seed: keystore (both origins pin the SAME key) ─────────────────────────
await ensureBootstrapped()
const keyRow = await FederationKey.findOne({ purpose: 'federation', state: 'active' })
const anchorJwks = JSON.stringify({ keys: [keyRow.publicKey] })
for (const origin of [A_ORIGIN, B_ORIGIN]) {
  await FederationPeer.updateOne(
    { origin },
    {
      origin,
      status: 'approved',
      direction: 'both',
      mode: 'pairwise',
      kid: keyRow.kid,
      anchorJwks,
      killOutstandingCodes: false,
    },
    { upsert: true },
  )
}

// ── seed: the two real accounts + the two projects ─────────────────────────
;[carol, owner] = await User.create([
  {
    email: 'carol@alpha.example',
    first_name: 'Carol',
    last_name: 'Alpha',
    institution: 'Alpha College',
    suspended: false,
    analyticsId: crypto.randomUUID(),
  },
  {
    email: 'owner@beta.example',
    first_name: 'Owner',
    last_name: 'Beta',
    institution: 'Beta University',
    suspended: false,
    analyticsId: crypto.randomUUID(),
  },
])
const projA = await Project.create({
  name: 'alpha project',
  owner_ref: carol._id,
  version: 1,
  active: true,
})
// The B-side project the export targets (2a: owner B-native, live consent
// grant to home A's client).
const bProject = await Project.create({
  name: 'beta project',
  owner_ref: owner._id,
  version: 1,
  active: true,
})

// ── A express (origin alpha, the driver process) ────────────────────────────
const app = Express()
app.use(Express.json())
app.use((req, res, next) => {
  // Fake login: the visitor on A is CAROL (owner of projA). REAL row.
  req.session = req.session ?? {}
  req.session.user = req.session.user ?? { _id: String(carol._id) }
  next()
})
S2sRouter.apply(app)
CallbackRouter.apply(app)
app.use('/federation/oidc', async (req, res, next) => {
  try {
    const { getOidcProvider } = await import('../../oidc/createProvider.mjs')
    const provider = await getOidcProvider()
    await provider.callback()(req, res, next)
  } catch (err) {
    next(err)
  }
})

// ── spawn the B child (origin beta.example, real express + OP + git-bridge)
const B_CHILD = path.join(TOOL_DIR, 'live-smoke-b.mjs')
function spawnB() {
  const child = spawn(process.execPath, [B_CHILD], {
    env: { ...process.env, PUBLIC_URL: `https://${B_ORIGIN}` },
    stdio: ['ignore', 'pipe', 'inherit'],
  })
  return new Promise((resolve, reject) => {
    let buf = ''
    let settled = false
    const finish = (err, val) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (err) reject(err)
      else resolve(val)
    }
    const timer = setTimeout(
      () => finish(new Error('B child: no READY_B in 90s')),
      90_000,
    )
    child.stdout.on('data', chunk => {
      buf += chunk.toString()
      let nl
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl)
        buf = buf.slice(nl + 1)
        const m = /^READY_B (\d+)\s*$/.exec(line)
        if (m) return finish(null, { child, port: Number(m[1]) })
      }
    })
    child.on('exit', code => finish(new Error(`B child exited ${code} before READY_B`)))
    child.on('error', err => finish(err))
  })
}

// ── helpers ──────────────────────────────────────────────────────────────────
let failed = 0
function ok(name, cond, extra) {
  if (cond) {
    console.log(`  PASS ${name}`)
  } else {
    console.log(
      `  FAIL ${name}${extra !== undefined ? ` — ${JSON.stringify(extra)}` : ''}`,
    )
    failed += 1
  }
  return cond
}

const cookieHeader = jar => [...jar].map(([k, v]) => `${k}=${v}`).join('; ')

async function runAuthorize() {
  const fakeReq = {
    body: {
      projectId: String(projA._id),
      anchor: `owner@beta.example:${B_ORIGIN}`,
      privileges: 'readAndWrite',
    },
    user: { _id: String(carol._id) },
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
      `handleAuthorize error path (status ${fakeRes.statusCode}): ${JSON.stringify(fakeRes.body)}`,
    )
  }
  return fakeRes
}

// Drive B's OP dance to a minted code (v1 live-smoke proven loop: every
// intermediate hop is on beta; the final redirect is A's callback, which is
// returned and NOT followed — the scenario fetches it separately).
async function driveDance(authUrl) {
  const jar = new Map()
  let url = authUrl
  let method = 'GET'
  for (let hop = 0; hop < 24; hop += 1) {
    const u = new URL(url, `https://${B_ORIGIN}`)
    const target = `${betaBase}${u.pathname}${u.search}`
    const res = await fetch(target, {
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
      const abs = new URL(loc, `https://${B_ORIGIN}`)
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
      throw new Error(`dance HTTP ${res.status} at: ${u.href} — ${pre ? pre[1].trim() : ''}`)
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

// ── orchestration ────────────────────────────────────────────────────────────
const { child, port } = await spawnB()
const betaBase = `http://127.0.0.1:${port}`
const server = app.listen(0, '127.0.0.1')
await new Promise(resolve => server.on('listening', resolve))
const alphaBase = `http://127.0.0.1:${server.address().port}`

// The A-side modules fetch https://beta.example/… (S2S, JWKS, token) and
// https://alpha.example/… — rewrite to the live local servers (the dance +
// S2S + code-exchange wire use the public origins per 01 §6).
const origFetch = globalThis.fetch
globalThis.fetch = (input, init) => {
  const raw = typeof input === 'string' ? input : String(input?.url ?? input)
  if (raw.startsWith(`https://${B_ORIGIN}`) || raw.startsWith(`https://${A_ORIGIN}`)) {
    const u = new URL(raw)
    const target = raw.startsWith(`https://${B_ORIGIN}`) ? betaBase : alphaBase
    return origFetch(`${target}${u.pathname}${u.search}`, init)
  }
  return origFetch(input, init)
}

const postS2sB = built =>
  origFetch(`${betaBase}/federation/s2s`, {
    method: 'POST',
    redirect: 'manual',
    headers: {
      'Content-Type': 'application/json',
      client_assertion: built.headers.client_assertion,
    },
    body: JSON.stringify(built.body),
  })

let wizardPat
let lastSweptPat

const scenarios = [
  {
    name: '01 v1 identity dance (cross-origin) → mirror + consent grant',
    fn: async () => {
      const res0 = await runAuthorize()
      ok(
        'authorize 302 to B auth URL',
        res0.location?.includes('/federation/oidc/auth?'),
        res0.location,
      )
      ok(
        'authorization client is alpha',
        res0.location?.includes(
          `client_id=${encodeURIComponent(federationClientId(A_ORIGIN))}`,
        ),
      )
      ok(
        'authorization uses S256 PKCE',
        res0.location?.includes('code_challenge_method=S256'),
      )
      const dance = await driveDance(res0.location)
      ok('code minted', Boolean(dance.code))
      ok('state present', Boolean(dance.state))

      const cb = await fetch(
        `${alphaBase}/federation/oidc/rp/callback?code=${encodeURIComponent(dance.code)}&state=${encodeURIComponent(dance.state)}`,
        { redirect: 'manual', headers: { cookie: dance.cookies } },
      )
      ok('callback 302', cb.status === 302, { status: cb.status })
      ok(
        'callback → /project/<projA>',
        cb.headers.get('Location') === `/project/${projA._id}`,
        cb.headers.get('Location'),
      )

      const mirror = await User.findOne({
        'federation.origin': B_ORIGIN,
        'federation.localName': 'owner@beta.example',
      }).lean()
      ok('mirror row (origin, localName), no email', mirror && mirror.email === '')
      ok(
        'grant applied (projA, null, mirrorId, readAndWrite)',
        grants.length === 1 &&
          grants[0][0] === String(projA._id) &&
          grants[0][3] === 'readAndWrite' &&
          String(grants[0][2]) === String(mirror?._id),
        grants[0],
      )
      ok('session tracked', sessions.length === 1)
      const auditSession = await ProjectAuditLogEntry.findOne({
        operation: 'federation_session_issued',
      }).lean()
      ok('audit row federation_session_issued', Boolean(auditSession))
      // The CONSENT GRANT is live — the 2a binding (B wrote it to the
      // shared Redis during the dance, adapter upsert with accountId +
      // clientId).
      const members = await redis.smembers(
        accountIndexKey(String(owner._id), federationClientId(A_ORIGIN)),
      )
      ok('consent-grant account index has a grant', members.length >= 1, members)
    },
  },
  {
    name: '02 export wizard (2b) → S2S export-project (2a) → PAT',
    fn: async () => {
      const local = { view: null, locals: null }
      const fakeReq = {
        body: { origin: B_ORIGIN, projectId: String(bProject._id) },
        user: { _id: String(carol._id) },
        session: {},
      }
      const fakeRes = {
        statusCode: 200,
        locals: { csrfToken: 'smoke' },
        status(c) {
          this.statusCode = c
          return this
        },
        json(o) {
          this.body = o
          return this
        },
        render(v, l) {
          local.view = v
          local.locals = l
          return this
        },
      }
      let handlerError
      try {
        await handleExport(fakeReq, fakeRes, error => (handlerError = error))
      } catch (e) {
        handlerError = e
      }
      if (handlerError) throw new Error(`wizard error: ${handlerError.message}`)
      ok('wizard 200', fakeRes.statusCode === 200, { status: fakeRes.statusCode })
      const pat = local?.locals?.project?.pat
      wizardPat = pat
      ok('PAT rendered (olp_ + 36 chars)', /^olp_[A-Za-z0-9]{36}$/.test(pat ?? ''))
      ok(
        'git_url is the B mount URL',
        local?.locals?.project?.gitUrl === `https://${B_ORIGIN}/git/${bProject._id}`,
        local?.locals?.project?.gitUrl,
      )
      ok(
        'scope federation:git_bridge',
        local?.locals?.project?.scope === 'federation:git_bridge',
      )

      // The raw PAT is never persisted: sha256 + prefix only (09 §3).
      // The export PAT doc stores `user_id` as a STRING (2a: `String(
      // owner._id)`), so match on the string form.
      const patDoc = await db.oauthAccessTokens
        .findOne({ scope: 'federation:git_bridge', user_id: String(owner._id) })
        .catch(() => null)
      ok(
        'sha256 PAT doc (scope, owner, partial)',
        patDoc && patDoc.accessTokenPartial === pat.substring(0, 8),
        patDoc ? [patDoc.accessTokenPartial, patDoc.scope] : null,
      )
      ok('raw PAT not persisted', patDoc && !JSON.stringify(patDoc).includes(pat))
      const ledger = await FederationExportGrant.findOne({
        projectId: String(bProject._id),
        homeOrigin: A_ORIGIN,
      }).lean()
      ok(
        'ledger row (owner, project, home=alpha, exported)',
        ledger &&
          String(ledger.owner) === String(owner._id) &&
          ledger.status === 'exported' &&
          String(ledger.patId) === String(patDoc?._id ?? ''),
        ledger ? { status: ledger.status, patId: ledger.patId } : null,
      )
      const auditReq = await ProjectAuditLogEntry.findOne({
        operation: 'federation_export_requested',
      }).lean()
      ok('audit row federation_export_requested', Boolean(auditReq))
    },
  },
  {
    name: '03 live git-bridge (B REST): read passes, write 403 (2c guard)',
    fn: async () => {
      const headers = { authorization: `Bearer ${wizardPat}` }
      const read = await fetch(`${betaBase}/api/v0/docs/${bProject._id}`, {
        headers,
        redirect: 'manual',
      })
      // Read: auth passes (owner oracle via owner_ref, real Mongo) →
      // controller → 400 from the (absent) project-history sidecar. A 401 /
      // 403 here would mean the export PAT was refused on READ — a
      // regression (it is read-only, not read-blocked).
      ok('export-PAT read reaches controller (400, sidecar down)', read.status === 400, {
        status: read.status,
      })
      const writeExport = await fetch(`${betaBase}/api/v0/docs/${bProject._id}/snapshots`, {
        method: 'POST',
        redirect: 'manual',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ latestVerId: 1, files: 'f', postbackUrl: 'http://postback' }),
      })
      // THE 2d signature: the federation:-scoped export PAT is refused at
      // the write choke point, before any controller/oracle (2c guard).
      ok('export-PAT write → 403 (2c guard)', writeExport.status === 403, {
        status: writeExport.status,
      })
      // A NORMAL git_bridge PAT passes the guard (oracle → owner → allowed)
      // and reaches the controller (500, sidecar down) — proving the guard
      // is scope-keyed, not a blanket refusal.
      const normalPat = await GitBridgePATManager.createToken(String(owner._id))
      const writeNormal = await fetch(`${betaBase}/api/v0/docs/${bProject._id}/snapshots`, {
        method: 'POST',
        redirect: 'manual',
        headers: {
          authorization: `Bearer ${normalPat.accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ latestVerId: 1, files: 'f', postbackUrl: 'http://postback' }),
      })
      ok('normal-PAT write passes guard (500, sidecar down)', writeNormal.status === 500, {
        status: writeNormal.status,
      })
      const info = await fetch(`${betaBase}/oauth/token/info`, {
        headers,
        redirect: 'manual',
      })
      ok('token/info 200 for the export PAT', info.status === 200, { status: info.status })
      await GitBridgePATManager.deleteToken(normalPat._id, String(owner._id))
    },
  },
  {
    name: '04 S2S export-project rate limit (429 + Allow-Retry-After)',
    fn: async () => {
      // Budget 10/120s per (caller origin, B project). The wizard already
      // used 1 of 10; 9 more land (fresh PATs, idempotent ledger), the 11th
      // is refused.
      for (let i = 0; i < 9; i += 1) {
        const built = await buildS2sRequest(B_ORIGIN, 'export-project', {
          projectId: String(bProject._id),
        })
        const res = await postS2sB(built)
        const data = await res.json().catch(() => ({}))
        if (res.status !== 200 || data.ok !== true) {
          throw new Error(`re-export ${i + 1} refused: ${res.status} ${JSON.stringify(data)}`)
        }
        lastSweptPat = data.payload.pat
      }
      const builtOver = await buildS2sRequest(B_ORIGIN, 'export-project', {
        projectId: String(bProject._id),
      })
      const res = await postS2sB(builtOver)
      const data = await res.json().catch(() => ({}))
      ok('11th export → 429', res.status === 429, { status: res.status })
      ok('429 code rate-limited', data.code === 'rate-limited', data)
      ok('Allow-Retry-After header', Boolean(res.headers.get('Allow-Retry-After')))
      const ledgerCount = await FederationExportGrant.countDocuments({
        projectId: String(bProject._id),
        homeOrigin: A_ORIGIN,
      })
      ok('ledger idempotent (1 row after 10 mints)', ledgerCount === 1, ledgerCount)
    },
  },
  {
    name: '05 S2S revoke (A→B) → peer revoked + export sweep (2c)',
    fn: async () => {
      const built = await buildS2sRequest(B_ORIGIN, 'revoke', {})
      const res = await postS2sB(built)
      const data = await res.json().catch(() => ({}))
      ok('revoke ok', res.status === 200 && data.ok === true, data)
      const peer = await FederationPeer.findOne({ origin: A_ORIGIN }).lean()
      ok('alpha peer status revoked (on B)', peer?.status === 'revoked', peer?.status)
      const ledger = await FederationExportGrant.findOne({
        projectId: String(bProject._id),
        homeOrigin: A_ORIGIN,
      }).lean()
      ok('ledger row → revoked', ledger?.status === 'revoked', ledger?.status)
      const patDocCount = await db.oauthAccessTokens.countDocuments({
        scope: 'federation:git_bridge',
      })
      // 10 minted (wizard + 9); the sweep deletes the LEDGER's PAT
      // (scope-guarded) → 9 docs (the rest linger until their 1h TTL —
      // documented 2a re-export property).
      ok('sweep deleted the minted PAT (10 → 9)', patDocCount === 9, patDocCount)
      const audit = await ProjectAuditLogEntry.findOne({
        operation: 'federation_export_swept',
      }).lean()
      ok('audit row federation_export_swept', Boolean(audit))
    },
  },
  {
    name: '06 post-revoke: dead PAT 401 everywhere + wizard 502',
    fn: async () => {
      const headers = { authorization: `Bearer ${lastSweptPat}` }
      const info = await fetch(`${betaBase}/oauth/token/info`, {
        headers,
        redirect: 'manual',
      })
      ok('token/info 401 (swept PAT)', info.status === 401, { status: info.status })
      const read = await fetch(`${betaBase}/api/v0/docs/${bProject._id}`, {
        headers,
        redirect: 'manual',
      })
      ok('read 401 (swept PAT)', read.status === 401, { status: read.status })
      const write = await fetch(`${betaBase}/api/v0/docs/${bProject._id}/snapshots`, {
        method: 'POST',
        redirect: 'manual',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ latestVerId: 1, files: 'f', postbackUrl: 'http://x' }),
      })
      ok('write 401 (swept PAT)', write.status === 401, { status: write.status })

      const fakeReq = {
        body: { origin: B_ORIGIN, projectId: String(bProject._id) },
        user: { _id: String(carol._id) },
        session: {},
      }
      const fakeRes = {
        statusCode: 200,
        locals: { csrfToken: 'smoke' },
        status(c) {
          this.statusCode = c
          return this
        },
        render(v, l) {
          this.rendered = [v, l]
          return this
        },
      }
      try {
        await handleExport(fakeReq, fakeRes, error =>
          console.log(`  wizard error: ${error?.message ?? error}`),
        )
      } catch (error) {
        console.log(`  wizard error (caught): ${error?.message ?? error}`)
      }
      ok('wizard 502 after revoke (peer-not-approved)', fakeRes.statusCode === 502, {
        status: fakeRes.statusCode,
      })
      const denied = await ProjectAuditLogEntry.findOne({
        operation: 'federation_export_denied',
      }).lean()
      ok('audit row federation_export_denied', Boolean(denied))
    },
  },
  {
    name: '07 post-revoke S2S refused at the peer pre-lookup',
    fn: async () => {
      const built = await buildS2sRequest(B_ORIGIN, 'invited', {
        invitee: { origin: B_ORIGIN, localName: 'owner@beta.example' },
      })
      const res = await postS2sB(built)
      const data = await res.json().catch(() => ({}))
      ok('401 peer-not-approved', res.status === 401 && data.code === 'peer-not-approved', data)
    },
  },
]

async function main() {
  for (const s of scenarios) {
    console.log(`\n── ${s.name}`)
    try {
      await s.fn()
    } catch (error) {
      console.log(`  EXCEPTION: ${error.stack || error.message}`)
      failed += 1
    }
  }
}

try {
  await main()
} catch (error) {
  console.log(`\n  EXCEPTION (fatal): ${error.stack || error.message}`)
  failed += 1
} finally {
  child.kill('SIGTERM')
}

globalThis.fetch = origFetch
await redis.quit().catch(() => {})
console.log(
  `\n${scenarios.length} scenarios · ${failed === 0 ? 'ALL PASS' : `${failed} CHECK(S) FAILED`}`,
)
console.log(`beta=${betaBase} alpha=${alphaBase}\n`)
process.exit(failed === 0 ? 0 : 1)
