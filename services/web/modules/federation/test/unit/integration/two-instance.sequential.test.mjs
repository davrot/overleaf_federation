/**
 * Two-instance federation integration (Sequential project — run alone, fileParallelism: false).
 *
 * ONE live express app plays BOTH A (the RP initiating institution) and B (the home
 * institution holding the invitee's account). Trust model — single-origin variant:
 *
 *   A.origin = B.origin = beta.example   (Settings.siteUrl = https://beta.example)
 *
 * REAL: oidc-provider v9.12.2 (the B-side OP — live auth/consent/code dance), jose
 * (ES256 key generation + client assertions + id_token verify), the S2S wire shape
 * (client assertion in the `client_assertion` header), the keystore (module-local
 * FederationKey mock), the OIDF client-assertion client, the PKCE/state store, the
 * S2S router + all three actions + replay + rate-limit, and the A-side grant
 * callback (mirror row + collaborator grant + session mint).
 *
 * MOCKED: the 4 app/src models + 3 app/src services + Redis (Map-backed fake, the
 * @overleaf/redis-wrapper contract). `vi.mock` factories read `globalThis.__*`
 * stores set by this file (hoisting: factories must not reference module scope).
 *
 * The dance (probe9-validated, production bridge + v9 interaction flow):
 *   GET  /federation/oidc/auth?...            → 303 → interact/<u1>   (prompt=login)
 *   GET  interact/<u1>                        → B is "logged in" (mock session) → 303 (login finished)
 *   GET  <resume URL>                         → prompt=consent → 303 → interact/<u2> (new uid)
 *   GET  interact/<u2>                        → bridge renders consent.pug (200 HTML)
 *   POST interact/<u2>/consent                → grant + 303 (consent finished)
 *   GET  <resume URL>                         → 302 → redirect_uri?code&state
 *   GET  /federation/oidc/rp/callback?code&state → CodeExchange → mirror → grant → 302 intent.url
 *
 * Scenario list (HANDOFF SESSION 6 item 3):
 *   1. OIDC code dance: federated invite → consent → code → mirror session (happy path)
 *   2. PKCE one-shot: replayed callback is refused (401)
 *   3. S2S invited: approved preview (existing local user)
 *   4. S2S invited: soft deny (nonexistent local user — still `ok: true`)
 *   5. S2S authorize-invite: approved (B is the oracle) + audit row
 *   6. S2S authorize-invite: unknown invitee → business refusal + audit row
 *   7. S2S replay: second delivery of the same assertion → 401 replay-jti
 *   8. S2S bad signature → 401 bad-signature
 *   9. S2S unknown kid → 401 unknown-kid (key not pinned)
 *  10. S2S rate limit: budget exceeded → 429 + Allow-Retry-After
 *  11. S2S revoke: trust revoked (idempotent), follow-up refused, audit row
 *  12. S2S federation off → 200 machine-readable refusal (always-mounted router)
 */

import { afterAll, beforeAll, beforeEach, expect, test, vi } from 'vitest'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'
import express from 'express'
import pug from 'pug'
import { SignJWT } from 'jose'

import Settings from '@overleaf/settings'

import S2sRouter from '../../../s2s/S2sRouter.mjs'
import { mountBridge } from '../../../oidc/bridge.mjs'
import CallbackRouter from '../../../rp/CallbackRouter.mjs'
import { getOidcProvider } from '../../../oidc/createProvider.mjs'
import { ensureBootstrapped } from '../../../oidf/keystore.mjs'
import {
  buildS2sRequest,
  getClientId,
  getS2sEndpoint,
} from '../../../oidf/ClientAssertionClient.mjs'
import { FederatedInviteController } from '../../../invite/FederatedInviteController.mjs'

// ── vi.mock: @overleaf/settings (live mutable — the federation-off scenario flips
//    `federation.enabled`). Bootstrap already mocks logger + metrics. ──────────
vi.mock('@overleaf/settings', () => {
  const s = {
    siteUrl: 'https://beta.example',
    security: { sessionSecret: 'federation-test-session-secret-0000000000000000' },
    federation: { enabled: true, keyRotationGraceDays: 14, institutionAuthorityHints: [] },
    redis: { web: { host: '127.0.0.1', port: 6379 } },
  }
  globalThis.__SETTINGS = s
  return { default: s }
})

// ── vi.mock: module-local models (the keystore + peer stores) ────────────────
vi.mock('../../../app/models/FederationKey.mjs', () => {
  globalThis.__KEYS = globalThis.__KEYS ?? []
  const chain = value => ({
    lean: () => chain(value),
    sort: () => chain(value),
    then: (a, b) => Promise.resolve(value).then(a, b),
  })
  const keyMatches = (filter, row) =>
    Object.entries(filter).every(([k, v]) => {
      if (k === '_id') return String(row[k]) === String(v)
      if (v !== null && typeof v === 'object' && '$ne' in v) return row[k] !== v.$ne
      if (v !== null && typeof v === 'object' && '$lt' in v) return row[k] < v.$lt
      return row[k] === v
    })
  const model = {
    findOne: filter => chain(globalThis.__KEYS.find(r => keyMatches(filter, r)) ?? null),
    find: filter => chain(globalThis.__KEYS.filter(r => keyMatches(filter, r))),
    create: doc => {
      const row = { _id: `fk-${globalThis.__KEYS.length}`, ...doc }
      globalThis.__KEYS.push(row)
      return Promise.resolve(row)
    },
    updateOne: (filter, update) => {
      const rows = globalThis.__KEYS.filter(r => keyMatches(filter, r))
      for (const row of rows) Object.assign(row, update)
      return { matchedCount: rows.length, modifiedCount: rows.length }
    },
  }
  return { FederationKey: model, default: model }
})

vi.mock('../../../app/models/FederationPeer.mjs', () => {
  globalThis.__PEERS = globalThis.__PEERS ?? []
  const model = {
    findOne: filter => {
      const found = globalThis.__PEERS.find(p => p.origin === filter.origin) ?? null
      return {
        lean: () => Promise.resolve(found),
        then: (a, b) => Promise.resolve(found).then(a, b),
      }
    },
    find: filter => Promise.resolve(
      globalThis.__PEERS.filter(p => !filter.status || p.status === filter.status),
    ),
    updateOne: (filter, update) => {
      const row = globalThis.__PEERS.find(p => p.origin === filter.origin)
      if (!row) return { matchedCount: 0, modifiedCount: 0 }
      if (filter.status?.$ne != null && row.status === filter.status.$ne) {
        return { matchedCount: 0, modifiedCount: 0 }
      }
      Object.assign(row, update)
      return { matchedCount: 1, modifiedCount: 1 }
    },
    create: doc => {
      const row = { _id: `peer-${doc.origin}`, ...doc }
      globalThis.__PEERS.push(row)
      return Promise.resolve(row)
    },
  }
  return { FederationPeer: model }
})

// ── vi.mock: app/src models + services ───────────────────────────────────────
vi.mock('../../../../../app/src/models/User.mjs', () => {
  globalThis.__USERS = globalThis.__USERS ?? []
  const chain = value => ({
    lean: () => Promise.resolve(value),
    then: (a, b) => Promise.resolve(value).then(a, b),
  })
  const findUser = filter =>
    globalThis.__USERS.find((u) => {
      if (filter.federation?.origin != null) {
        return (
          u.federation?.origin === filter.federation.origin &&
          u.federation?.localName === filter.federation.localName
        )
      }
      if (filter['federation.origin'] != null) {
        return (
          u.federation?.origin === filter['federation.origin'] &&
          u.federation?.localName === filter['federation.localName']
        )
      }
      if (filter.email != null) return u.email === filter.email
      if (filter._id != null) return String(u._id) === String(filter._id)
      return false
    }) ?? null
  const model = {
    findOne: filter => chain(findUser(filter)),
    findById: id =>
      Promise.resolve(
        globalThis.__USERS.find(u => String(u._id) === String(id)) ?? null,
      ),
    create: doc => {
      const row = { _id: doc._id ?? `u-${globalThis.__USERS.length}`, ...doc }
      globalThis.__USERS.push(row)
      return Promise.resolve(row)
    },
    find: filter =>
      Promise.resolve(
        globalThis.__USERS.filter(
          u => !filter.email || u.email === filter.email,
        ),
      ),
  }
  return { User: model, UserSchema: {} }
})

vi.mock('../../../../../app/src/models/ProjectInvite.mjs', () => {
  globalThis.__INVITES = globalThis.__INVITES ?? []
  return {
    ProjectInvite: {
      findOneAndUpdate: (...args) => {
        globalThis.__INVITES.push(args)
        return Promise.resolve({ _id: 'project-invite-1' })
      },
    },
  }
})

vi.mock('../../../../../app/src/models/ProjectAuditLogEntry.mjs', () => {
  globalThis.__AUDIT_ROWS = globalThis.__AUDIT_ROWS ?? []
  return {
    ProjectAuditLogEntry: {
      create: doc => {
        globalThis.__AUDIT_ROWS.push(doc)
        return Promise.resolve({ _id: 'project-audit-1' })
      },
    },
  }
})

vi.mock('../../../../../app/src/infrastructure/RedisWrapper.mjs', () => ({
  default: {
    client: () => globalThis.__REDIS,
    cleanupTestRedis: async () => {},
  },
}))

vi.mock('../../../../../app/src/Features/Collaborators/CollaboratorsHandler.mjs', () => ({
  default: {
    promises: {
      addUserIdToProject: (...args) => {
        globalThis.__GRANTS = globalThis.__GRANTS ?? []
        globalThis.__GRANTS.push(args)
        return Promise.resolve({})
      },
    },
  },
}))

vi.mock('../../../../../app/src/Features/Collaborators/CollaboratorsGetter.mjs', () => ({
  default: {
    promises: {
      getMemberIdPrivilegeLevel: async () => 'readAndWrite',
      getProjectOwnerId: async () => 'owner-1',
    },
  },
}))

vi.mock('../../../../../app/src/Features/User/UserSessionsManager.mjs', () => ({
  default: {
    promises: {
      trackSession: (...args) => {
        globalThis.__SESSIONS = globalThis.__SESSIONS ?? []
        globalThis.__SESSIONS.push(args)
        return Promise.resolve()
      },
    },
  },
}))

// ── fake redis (the @overleaf/redis-wrapper contract: get/set/get+EX/PX/NX/del/
//    incr/expire/ttl/pttl/s*/flushall for the adapter) ─────────────────────────
function makeFakeRedis() {
  const kv = new Map()
  const tlls = new Map()
  const sets = new Map()
  return {
    async get(k) {
      return kv.has(k) ? kv.get(k) : null
    },
    async set(k, v, ...args) {
      let nx = false
      let expMs = null
      for (let i = 0; i < args.length; i += 1) {
        const a = args[i]
        if (a === 'NX') {
          nx = true
        } else if (a === 'EX' || a === 'PX') {
          expMs = a === 'EX' ? Number(args[i + 1]) * 1000 : Number(args[i + 1])
          i += 1
        }
      }
      if (nx && kv.has(k)) return null
      kv.set(k, String(v))
      if (expMs != null) tlls.set(k, expMs)
      else tlls.delete(k)
      return 'OK'
    },
    async del(...ks) {
      let n = 0
      for (const k of ks) {
        if (kv.delete(k)) n += 1
        tlls.delete(k)
        if (sets.delete(k)) n += 1
      }
      return n
    },
    async incr(k) {
      const n = Number(kv.get(k) ?? 0) + 1
      kv.set(k, String(n))
      return n
    },
    async expire(k, seconds) {
      if (!kv.has(k)) return 0
      tlls.set(k, seconds * 1000)
      return 1
    },
    async ttl(k) {
      if (!kv.has(k)) return -2
      return tlls.has(k) ? Math.max(1, Math.ceil(tlls.get(k) / 1000)) : -1
    },
    async pttl(k) {
      if (!kv.has(k)) return -2
      return tlls.has(k) ? tlls.get(k) : -1
    },
    async sadd(k, ...members) {
      let s = sets.get(k)
      if (!s) {
        s = new Set()
        sets.set(k, s)
      }
      let added = 0
      for (const m of members) {
        if (!s.has(String(m))) {
          s.add(String(m))
          added += 1
        }
      }
      return added
    },
    async srem(k, ...members) {
      const s = sets.get(k) ?? new Set()
      let n = 0
      for (const m of members) {
        if (s.delete(String(m))) n += 1
      }
      if (s.size === 0) sets.delete(k)
      else sets.set(k, s)
      return n
    },
    async scard(k) {
      return sets.get(k)?.size ?? 0
    },
    async smembers(k) {
      return [...(sets.get(k) ?? [])]
    },
    // Test-only enumeration (ioredis KEYS with prefix match) — the
    // production adapter never calls keys(); the sweep test uses it to
    // assert which docs survive.
    async keys(pattern) {
      const keys = []
      for (const k of kv.keys()) {
        if (pattern === '*') keys.push(k)
        else if (pattern.endsWith('*')) {
          const prefix = pattern.slice(0, -1)
          if (k.startsWith(prefix)) keys.push(k)
        } else if (k === pattern) keys.push(k)
      }
      return keys
    },
    async flushall() {
      kv.clear()
      tlls.clear()
      sets.clear()
    },
  }
}

// ── per-test seed ─────────────────────────────────────────────────────────────
function seedStore() {
  globalThis.__GRANTS ??= []
  globalThis.__SESSIONS ??= []
  globalThis.__INVITES ??= []
  globalThis.__AUDIT_ROWS ??= []
  globalThis.__PEERS ??= []
  globalThis.__USERS ??= []
  globalThis.__PEERS.length = 0
  globalThis.__PEERS.push({
    _id: 'peer-beta.example',
    origin: 'beta.example',
    status: 'approved',
    direction: 'both',
    mode: 'pairwise',
    kid: globalThis.__FED_SEED?.kid,
    anchorJwks: globalThis.__FED_SEED?.anchorJwks,
  })
  globalThis.__USERS.length = 0
  globalThis.__USERS.push({
    _id: 'u-alice',
    email: 'alice@beta.example',
    first_name: 'Alice',
    last_name: 'Beta',
    institution: 'Beta University',
    suspended: false,
  })
  globalThis.__USERS.push({
    _id: 'owner-1',
    email: 'owner@beta.example',
    first_name: 'Owner',
    last_name: 'One',
    institution: '',
    suspended: false,
  })
  globalThis.__AUDIT_ROWS.length = 0
  globalThis.__GRANTS.length = 0
  globalThis.__INVITES.length = 0
  globalThis.__SESSIONS.length = 0
}

// ── app + provider + fetch wrapper ────────────────────────────────────────────
let base
let server
let origFetch

beforeAll(async () => {
  globalThis.__REDIS = makeFakeRedis()
  seedStore()
  // Real keystore over the mocked FederationKey model → real ES256 keys.
  await ensureBootstrapped()
  const fedKey = globalThis.__KEYS.find(
    k => k.purpose === 'federation' && k.state === 'active',
  )
  expect(fedKey).toBeTruthy()
  globalThis.__FED_SEED = {
    kid: fedKey.kid,
    anchorJwks: JSON.stringify({ keys: [fedKey.publicKey] }),
  }
  globalThis.__PEERS[0].kid = fedKey.kid
  globalThis.__PEERS[0].anchorJwks = globalThis.__FED_SEED.anchorJwks
  seedStore()

  const app = express()
  app.use((req, res, next) => {
    req.headers.host = 'beta.example'
    next()
  })
  app.use(express.json())
  app.use((req, res, next) => {
    // B-side login: the visitor is logged in as ALICE (the federated
    // invitee's account on this origin — single-origin variant).
    req.session = req.session ?? {}
    req.session.user = req.session.user ?? { _id: 'u-alice' }
    // Consent view (05 §1): the bridge calls res.render with a view name; we
    // ignore the name and render the real template from an absolute path
    // (the production view path is the same file, mounted at app.views).
    res.render = (view, locals) =>
      new Promise((resolve, reject) => {
        const file = fileURLToPath(
          new URL('../../../app/views/consent.pug', import.meta.url),
        )
        pug.renderFile(file, locals || {}, (err, html) => {
          if (err) return reject(err)
          res.status(res.statusCode || 200).send(html)
          resolve()
        })
      })
    next()
  })
  // Mount order (05 §1.1, index.mjs LOCKED): S2S → bridge → callback → provider.
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

  server = app.listen(0, '127.0.0.1', () => {
    base = `http://127.0.0.1:${server.address().port}`
    // The A-side modules fetch `https://<origin>/...` (CodeExchange, callPeer).
    // Rewrite our own origin to the live local app.
    origFetch = globalThis.fetch
    globalThis.fetch = (input, init) => {
      const raw =
        typeof input === 'string' ? input : String(input?.url ?? input)
      if (raw.startsWith('https://beta.example')) {
        const u = new URL(raw)
        return origFetch(`${base}${u.pathname}${u.search}`, init)
      }
      return origFetch(input, init)
    }
  })
})

afterAll(async () => {
  globalThis.fetch = origFetch
  await new Promise(resolve => server.close(resolve))
})

beforeEach(() => {
  globalThis.__REDIS = makeFakeRedis()
  seedStore()
  Settings.federation.enabled = true
})

// ── test helpers ──────────────────────────────────────────────────────────────
const cookieHeader = jar =>
  [...jar].map(([k, v]) => `${k}=${v}`).join('; ')

/**
 * Drive the B-side OIDC dance from `authUrl`, following Location headers over
 * a cookie jar. Stops at the final 302 to the registered redirect_uri
 * (carrying code + state). Returns { code, state, cookies }.
 */
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
    if (res.status === 200) {
      const m = url.match(/\/interact\/([^/?]+)/)
      if (m) {
        const html = await res.text()
        if (html.includes('consent-form')) {
          // Consent HTML: POST empty body to the grant form (no inputs —
          // the form action is the grantUrl local).
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

/**
 * In-process A-side `handleAuthorize(fakeReq, fakeRes)` — avoid the CSRF
 * router guard (the production router is standard express session + CSRF,
 * exercised elsewhere). Returns the fakeRes with the captured `redirect(authUrl)`.
 */
async function runAuthorize() {
  const fakeReq = {
    body: {
      projectId: 'proj-1',
      anchor: 'alice@beta.example:beta.example',
      privileges: 'readAndWrite',
    },
    user: { _id: 'viewer-1' },
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

// ── 1: OIDC code dance (full happy path) ─────────────────────────────────────
test('OIDC code dance: federated invite → consent → code → mirror session', async () => {
  const res0 = await runAuthorize()
  expect(res0.location).toContain('/federation/oidc/auth?')
  expect(res0.location).toContain('code_challenge_method=S256')
  const dance = await driveDance(res0.location)
  expect(dance.code).toBeTruthy()
  expect(dance.state).toBeTruthy()

  // The A-side callback: exchange + mirror + grant + session + 302.
  const cb = await fetch(
    `${base}/federation/oidc/rp/callback?code=${encodeURIComponent(dance.code)}&state=${encodeURIComponent(dance.state)}`,
    { redirect: 'manual', headers: { cookie: dance.cookies } },
  )
  expect(cb.status).toBe(302)
  expect(cb.headers.get('Location')).toBe('/project/proj-1')

  // Mirror row: (origin, localName) with NO email (04 §1).
  const mirror = globalThis.__USERS.find(
    u => u.email === '' && u.federation?.localName === 'alice@beta.example',
  )
  expect(mirror).toBeTruthy()
  expect(mirror.federation.origin).toBe('beta.example')

  // Grant: mirror becomes a collaborator at the invite's privilege.
  expect(globalThis.__GRANTS).toHaveLength(1)
  expect(globalThis.__GRANTS[0]).toEqual(['proj-1', null, mirror._id, 'readAndWrite'])

  // Federation invite row was upserted (04 §3).
  expect(globalThis.__INVITES).toHaveLength(1)
  const [, inviteUpdate] = globalThis.__INVITES[0]
  expect(inviteUpdate['federated.localName']).toBe('alice@beta.example')
  expect(inviteUpdate['federated.authorized']).toBe(true)

  // Session minted (mock trackSession) + audit row (no code in the row).
  expect(globalThis.__SESSIONS).toHaveLength(1)
  expect(
    globalThis.__AUDIT_ROWS.some(r =>
      JSON.stringify(r).includes('federation_session_issued'),
    ),
  ).toBe(true)
})

// ── 2: PKCE one-shot (replayed callback refused) ─────────────────────────────
test('OIDC PKCE one-shot: replayed callback is refused', async () => {
  const res0 = await runAuthorize()
  const dance = await driveDance(res0.location)
  const cbUrl =
    `${base}/federation/oidc/rp/callback` +
    `?code=${encodeURIComponent(dance.code)}` +
    `&state=${encodeURIComponent(dance.state)}`
  const first = await fetch(cbUrl, {
    redirect: 'manual',
    headers: { cookie: dance.cookies },
  })
  expect(first.status).toBe(302)
  // The PKCE state is single-use (Redis consume, 05 §3.3 step 1): a second
  // exchange of the same (code, state) is refused — no session, no 302.
  const second = await fetch(cbUrl, {
    redirect: 'manual',
    headers: { cookie: dance.cookies },
  })
  expect(second.status).toBe(401)
  expect(await second.json()).toMatchObject({ message: 'invalid grant request' })
})

// ── 3: S2S invited: approved preview (existing local user) ──────────────────
test('S2S invited: approved preview for an existing local user', async () => {
  const built = await buildS2sRequest('beta.example', 'invited', {
    invitee: { origin: 'beta.example', localName: 'alice@beta.example' },
  })
  const res = await postS2s(built)
  expect(res.status).toBe(200)
  const data = await res.json()
  expect(data.ok).toBe(true)
  expect(data.payload.approved).toBe(true)
  expect(data.payload.displayName).toBe('Alice Beta')
})

// ── 4: S2S invited: soft deny (nonexistent local user) ───────────────────────
test('S2S invited: soft deny for a nonexistent local user', async () => {
  const built = await buildS2sRequest('beta.example', 'invited', {
    invitee: { origin: 'beta.example', localName: 'ghost@beta.example' },
  })
  const res = await postS2s(built)
  expect(res.status).toBe(200)
  const data = await res.json()
  expect(data.ok).toBe(true)
  expect(data.payload.approved).toBe(false)
  expect(data.payload.displayName).toBeNull()
})

// ── 5: S2S authorize-invite: approved + audit row ────────────────────────────
test('S2S authorize-invite: approved (B is the oracle) + audit row', async () => {
  const built = await buildS2sRequest('beta.example', 'authorize-invite', {
    invitee: { origin: 'beta.example', localName: 'alice@beta.example' },
    project: { ref: 'proj-1' },
  })
  const res = await postS2s(built)
  expect(res.status).toBe(200)
  const data = await res.json()
  expect(data.ok).toBe(true)
  expect(data.payload.approved).toBe(true)
  expect(data.payload.displayName).toBe('Alice Beta')
  expect(data.payload.institution).toBe('Beta University')
  // 04 §8 row: federated_invite_approved (hashed assertion meta — never raw).
  expect(
    globalThis.__AUDIT_ROWS.some(r => r.operation === 'federated_invite_approved'),
  ).toBe(true)
})

// ── 6: S2S authorize-invite: unknown invitee → business refusal ─────────────
test('S2S authorize-invite: unknown invitee → business refusal + audit row', async () => {
  const built = await buildS2sRequest('beta.example', 'authorize-invite', {
    invitee: { origin: 'beta.example', localName: 'ghost@beta.example' },
    project: { ref: 'proj-1' },
  })
  const res = await postS2s(built)
  expect(res.status).toBe(200)
  const data = await res.json()
  expect(data.ok).toBe(false)
  expect(data.code).toBe('invitee-unknown')
  expect(
    globalThis.__AUDIT_ROWS.some(r => r.operation === 'federated_invite_denied'),
  ).toBe(true)
})

// ── 7: S2S replay (second delivery of the same assertion → 401) ──────────────
test('S2S replay: second delivery of the same assertion is refused', async () => {
  const built = await buildS2sRequest('beta.example', 'invited', {
    invitee: { origin: 'beta.example', localName: 'alice@beta.example' },
  })
  const first = await postS2s(built)
  expect(first.status).toBe(200)
  const second = await postS2s(built)
  expect(second.status).toBe(401)
  const data = await second.json()
  expect(data.code).toBe('replay-jti')
})

// ── 8: S2S bad signature → 401 ───────────────────────────────────────────────
test('S2S bad signature → 401 bad-signature', async () => {
  const built = await buildS2sRequest('beta.example', 'invited', {
    invitee: { origin: 'beta.example', localName: 'alice@beta.example' },
  })
  // Tamper the JWT signature segment. The LAST base64url char of a 64-byte
  // ES256 signature encodes only the low bits of the final byte, so a
  // flip there can decode to the IDENTICAL signature (verified live: the
  // flipped JWS still passed ES256 verification). Flip a MIDDLE char —
  // always changes decoded bits, so verification deterministically fails.
  const a = built.headers.client_assertion
  const parts = a.split('.')
  const sig = parts[2]
  const mid = Math.floor(sig.length / 2)
  const flipped = sig[mid] === 'A' ? 'B' : 'A'
  const bad = `${parts[0]}.${parts[1]}.${sig.slice(0, mid)}${flipped}${sig.slice(mid + 1)}`
  const res = await postS2s({ ...built, headers: { ...built.headers, client_assertion: bad } })
  expect(res.status).toBe(401)
  const data = await res.json()
  expect(data.code).toBe('bad-signature')
})

// ── 9: S2S unknown kid (key not pinned by the admin) → 401 ───────────────────
test('S2S unknown kid → 401 unknown-kid', async () => {
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
    headers: {
      'Content-Type': 'application/json',
      client_assertion: unsigned,
    },
    body: {
      action: 'invited',
      from: 'beta.example',
      to: 'beta.example',
      ts: Date.now(),
      payload: { invitee: { origin: 'beta.example', localName: 'alice@beta.example' } },
    },
  }
  const res = await postS2s(built)
  expect(res.status).toBe(401)
  const data = await res.json()
  expect(data.code).toBe('unknown-kid')
})

// ── 10: S2S rate limit (budget exceeded → 429 + Allow-Retry-After) ───────────
test('S2S rate limit: budget exceeded → 429 + Allow-Retry-After', async () => {
  const statuses = []
  let lastRes
  let lastData
  for (let i = 0; i < 31; i += 1) {
    const built = await buildS2sRequest('beta.example', 'authorize-invite', {
      invitee: { origin: 'beta.example', localName: 'alice@beta.example' },
      project: { ref: 'proj-1' },
    })
    const res = await postS2s(built)
    statuses.push(res.status)
    if (res.status === 429) {
      lastRes = res
      lastData = await res.json()
    }
  }
  const first429 = statuses.indexOf(429)
  expect(first429).toBeGreaterThan(0)
  expect(first429).toBeLessThanOrEqual(31)
  expect(lastData.code).toBe('rate-limited')
  expect(lastRes.headers.get('Allow-Retry-After')).toBeTruthy()
})

// ── 11a: S2S revoke with `killOutstandingCodes` (04 §5 / 06 §178) ──────
test('S2S revoke + flag ON: outstanding codes swept, sessions + grants survive (not over-cross)', async () => {
  // Fresh dance: mint a real code (and, on token-exchange, access/refresh
  // tokens) via the REAL adapter, so the client SET index is populated
  // from production paths.
  Settings.federation.enabled = true
  const res0 = await runAuthorize()
  const dance = await driveDance(res0.location)
  expect(dance.code).toBeTruthy()

  const clientId = 'urn:overleaf-federation:client:beta.example'
  const clientSet = `federation:oidc:client:${clientId}`
  const redis = globalThis.__REDIS

  // Sanity: the dance minted token docs for this client.
  const beforeCodes = await redis.smembers(clientSet)
  expect(beforeCodes.length).toBeGreaterThanOrEqual(1)
  expect(
    beforeCodes.some(k => k.startsWith('federation:oidc:AuthorizationCode:')),
  ).toBe(true)
  const beforeSessions = await redis.keys('federation:oidc:Session:*')
  expect(beforeSessions.length).toBeGreaterThanOrEqual(1)
  const beforeSubs = await redis.keys('federation:oidc:sub:*')
  expect(beforeSubs.length).toBeGreaterThanOrEqual(1)
  const beforeGrants = await redis.keys('federation:oidc:Grant:*')

  // Flip the peer row flag ON (the admin page / API surfaces this in a
  // later goal; the row shape is the same).
  globalThis.__PEERS[0].killOutstandingCodes = true

  // S2S revoke from the peer (single-origin test: A→B on beta.example).
  const built = await buildS2sRequest('beta.example', 'revoke', {})
  const res = await postS2s(built)
  expect(res.status).toBe(200)
  expect(await res.json()).toEqual({ ok: true, payload: {} })
  expect(globalThis.__PEERS[0].status).toBe('revoked')

  // 04 §5: every outstanding code / token doc for the revoked client is
  // destroyed.
  const afterCodes = await redis.smembers(clientSet)
  expect(afterCodes).toEqual([])
  for (const docKey of beforeCodes) {
    expect(await redis.get(docKey)).toBeNull()
  }

  // 06 §178 not over-cross: B-side sessions are NOT logged out by A's
  // admin — the Session doc and its sub-index survive the sweep.
  const afterSessions = await redis.keys('federation:oidc:Session:*')
  expect(afterSessions).toEqual(beforeSessions)
  const afterSubs = await redis.keys('federation:oidc:sub:*')
  expect(afterSubs).toEqual(beforeSubs)

  // 06 §174: the consent Grant doc is not swept (sweep is GRANTABLE
  // token models only; v9 Grant extends BaseToken and carries `clientId`
  // in its payload — exclusion is by the model gate in the adapter).
  const afterGrants = await redis.keys('federation:oidc:Grant:*')
  expect(afterGrants).toEqual(beforeGrants)

  // Re-approve so test 11 exercises its OWN fresh revoked transition
  // (this one already consumed the fresh transition + trustRevoked audit
  // + sweep side effect for its assertions above).
  globalThis.__PEERS[0].status = 'approved'
  delete globalThis.__PEERS[0].killOutstandingCodes
})

// ── 11: S2S revoke (trust revoked, idempotent, follow-up refused) ────────────
test('S2S revoke: trust revoked + follow-up refused + audit row', async () => {
  const built = await buildS2sRequest('beta.example', 'revoke', {})
  const res = await postS2s(built)
  expect(res.status).toBe(200)
  expect(await res.json()).toEqual({ ok: true, payload: {} })
  expect(globalThis.__PEERS[0].status).toBe('revoked')
  expect(
    globalThis.__AUDIT_ROWS.some(
      r => r.operation === 'federation_peer_trust_revoked',
    ),
  ).toBe(true)

  // Follow-up S2S from a revoked origin is refused at the peer pre-lookup
  // (before crypto — 06 §2 "verify → dedup → apply, or refuse").
  const followUp = await buildS2sRequest('beta.example', 'authorize-invite', {
    invitee: { origin: 'beta.example', localName: 'alice@beta.example' },
    project: { ref: 'proj-1' },
  })
  const up = await postS2s(followUp)
  expect(up.status).toBe(401)
  const upData = await up.json()
  expect(upData.code).toBe('peer-not-approved')
})

// ── 12: S2S federation off (always-mounted router → machine refusal) ─────────
test('S2S federation off → 200 machine-readable refusal', async () => {
  Settings.federation.enabled = false
  const built = await buildS2sRequest('beta.example', 'invited', {
    invitee: { origin: 'beta.example', localName: 'alice@beta.example' },
  })
  const res = await postS2s(built)
  expect(res.status).toBe(200)
  const data = await res.json()
  expect(data.ok).toBe(false)
  expect(data.code).toBe('federation-off')
})
