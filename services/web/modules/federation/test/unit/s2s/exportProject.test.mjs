// S2S `export-project` action unit tests (content-bridge v2, plan 09 §2,
// SESSION 11 LOCKED build list).
//
// B-side handler: settings gate → payload sanity → project lookup →
// owner B-native → consent-grant binding (REAL `findByAccountAndClient`
// on a fake redis) → PAT mint (fresh raw per request, sha256-persisted)
// → ledger upsert → `{ git_url, pat, expires_at }`.
//
// Business refusals: `{ ok: false, code }` envelope (200 in-band — NOT
// 401; SESSION 11 reconciliation). Plan 09 "401s" = code-taxonomy.
//
// Mocked (globalThis-driven per bootstrap.mjs resetModules/resetAllMocks):
//   - @overleaf/settings (LIVE GETTER on `federation` — per-test toggle)
//   - mongoose models (chainable thenables via globalThis thunks)
//   - mongodb raw (insertOne for the PAT doc)
//   - RedisWrapper (federation client = fake with a pttl map)
// Real: `findByAccountAndClient` + account-index SET, `S2S_ERRORS`,
// `federationClientId`.

import { createHash } from 'node:crypto'
import { vi, describe, it, expect, beforeEach } from 'vitest'

vi.mock('@overleaf/settings', () => {
  const s = {}
  Object.defineProperty(s, 'siteUrl', { get: () => 'https://beta.example' })
  Object.defineProperty(s, 'security', {
    get: () => ({ sessionSecret: 'unit-test-secret' }),
  })
  Object.defineProperty(s, 'federation', {
    get: () => globalThis.__exportSettings,
  })
  return { default: s }
})

vi.mock('@overleaf/logger', () => ({
  default: { info: () => {}, error: () => {}, warn: () => {}, debug: () => {} },
}))

vi.mock('../../../../../app/src/infrastructure/mongodb.mjs', () => ({
  db: {
    oauthAccessTokens: {
      insertOne: (doc) => globalThis.__patInsert(doc),
    },
  },
}))

vi.mock('../../../../../app/src/infrastructure/RedisWrapper.mjs', () => ({
  default: {
    client: async (name) => {
      if (name !== 'federation') throw new Error(`unexpected: ${name}`)
      return globalThis.__fedRedis
    },
  },
}))

// Chainable mongoose-thenable: a CUSTOM thenable that mirrors the
// action's chain `Model.findOne().select('..').lean().catch(() => null)`
// and is awaited (via `then: ok`). Internally delegates to a REAL
// promise so both happy + reject paths settle; the registered
// `.catch(f)` runs on reject (mongoose-miss shape: getValue() throws).
function chainable(getValue) {
  let catchHandler = null
  const obj = {
    select: () => obj,
    lean: () => obj,
    catch: (f) => {
      catchHandler = f
      return obj
    },
    then: (ok) =>
      Promise.resolve()
        .then(() => getValue())
        .catch((err) => (catchHandler ? catchHandler(err) : Promise.reject(err)))
        .then(ok),
  }
  return obj
}

vi.mock('../../../../../app/src/models/Project.mjs', () => ({
  Project: { findOne: () => chainable(() => globalThis.__projectOneFn()) },
}))
vi.mock('../../../../../app/src/models/User.mjs', () => ({
  User: { findOne: () => chainable(() => globalThis.__userOneFn()) },
}))

vi.mock('../../../app/models/FederationExportGrant.mjs', () => ({
  FederationExportGrant: {
    updateOne: (filter, update, opts) => {
      globalThis.__ledgerWrites.push({ filter, update, opts })
      return Promise.resolve({})
    },
  },
}))

// verify.mjs (under test: S2S_ERRORS) imports ClientAssertionClient →
// keystore → FederationKey → Mongoose (mongoose.connect at module scope).
// Sever it (revoke.test precedent) — the export action needs none of it.
vi.mock('../../../oidf/ClientAssertionClient.mjs', () => ({
  getS2sEndpoint: () => 'https://beta.example/federation/s2s',
  buildS2sRequest: async () => ({ headers: {}, body: {} }),
}))

// verify.mjs (S2S_ERRORS — real, under test) AND clients.mjs (REAL —
// federationClientId is under test) import FederationPeer → mongoose.
// Sever it (revoke.test precedent) so no module-scope mongoose.connect.
vi.mock('../../../app/models/FederationPeer.mjs', () => ({
  FederationPeer: { find: async () => [], findOne: () => undefined },
}))

import exportProject, { EXPORT_SCOPE } from '../../../s2s/actions/exportProject.mjs'
import { S2S_ERRORS } from '../../../oidf/verify.mjs'

function makeFakeRedis(pttlMap) {
  const strings = new Map()
  const sets = new Map()
  return {
    __strings: strings,
    __sets: sets,
    get: async (k) => (strings.has(k) ? strings.get(k) : null),
    set: async (k, v) => {
      strings.set(k, v)
      return 'OK'
    },
    del: async (k) => {
      let n = 0
      if (strings.delete(k)) n++
      if (sets.delete(k)) n++
      return n
    },
    pttl: async (k) => (pttlMap.has(k) ? pttlMap.get(k) : -2),
    expire: async () => 1,
    sadd: async (k, ...members) => {
      const s = sets.get(k) ?? new Set()
      for (const m of members) s.add(m)
      sets.set(k, s)
      return 1
    },
    srem: async (k, ...members) => {
      const s = sets.get(k) ?? new Set()
      for (const m of members) s.delete(m)
      sets.set(k, s)
      return 1
    },
    smembers: async (k) => [...(sets.get(k) ?? new Set())],
    scard: async (k) => (sets.get(k) ? sets.get(k).size : 0),
  }
}

const OWNER = 'owner-42'
const PROJECT = 'project-b-1'
const CALLER = 'home-a.example'
const CLIENT_A = 'urn:overleaf-federation:client:home-a.example'

beforeEach(() => {
  globalThis.__pttlMap = new Map()
  globalThis.__fedRedis = makeFakeRedis(globalThis.__pttlMap)
  globalThis.__exportSettings = {
    enabled: true,
    export: { enabled: true, maxExportTtlSeconds: 86400 },
  }
  globalThis.__projectOneFn = () => {
    throw new Error('cast: project not found')
  }
  globalThis.__userOneFn = () => {
    throw new Error('cast: user not found')
  }
  globalThis.__patDocs = []
  globalThis.__patInsert = (doc) => {
    globalThis.__patDocs.push(doc)
    return Promise.resolve({ insertedId: `pat-id-${globalThis.__patDocs.length}` })
  }
  globalThis.__ledgerWrites = []
})

function seedLiveGrant(grantId = 'consent-g1') {
  const fake = globalThis.__fedRedis
  const docKey = `federation:oidc:Grant:${grantId}`
  fake.__strings.set(docKey, JSON.stringify({ accountId: OWNER, clientId: CLIENT_A, jti: grantId }))
  fake.__sets.set(`federation:oidc:account:${OWNER}:${CLIENT_A}`, new Set([docKey]))
  globalThis.__pttlMap.set(docKey, 30 * 86400 * 1000)
}

function nativeOwner() {
  globalThis.__projectOneFn = () => ({ _id: PROJECT, owner_ref: OWNER })
  globalThis.__userOneFn = () => ({ _id: OWNER, federation: undefined, suspended: false })
}

describe('export-project (B-side, plan 09 §2)', () => {
  it('settings off → export-disabled (ok:false envelope)', async () => {
    globalThis.__exportSettings.export = { enabled: false }
    nativeOwner()
    seedLiveGrant()
    const res = await exportProject({ body: { payload: { projectId: PROJECT } }, callerOrigin: CALLER })
    expect(res.ok).toBe(false)
    expect(res.code).toBe(S2S_ERRORS.EXPORT_DISABLED)
    expect(globalThis.__patDocs).toHaveLength(0)
  })

  it('malformed payload (no projectId) → project-not-owned', async () => {
    nativeOwner()
    seedLiveGrant()
    const res = await exportProject({ body: { payload: {} }, callerOrigin: CALLER })
    expect(res.ok).toBe(false)
    expect(res.code).toBe(S2S_ERRORS.PROJECT_NOT_OWNED)
  })

  it('project not found → project-not-owned', async () => {
    nativeOwner()
    seedLiveGrant()
    globalThis.__projectOneFn = () => {
      throw new Error('cast: not found')
    }
    const res = await exportProject({ body: { payload: { projectId: PROJECT } }, callerOrigin: CALLER })
    expect(res).toMatchObject({ ok: false, code: S2S_ERRORS.PROJECT_NOT_OWNED })
  })

  it('project without owner_ref → project-not-owned', async () => {
    nativeOwner()
    seedLiveGrant()
    globalThis.__projectOneFn = () => ({ _id: PROJECT, owner_ref: null })
    const res = await exportProject({ body: { payload: { projectId: PROJECT } }, callerOrigin: CALLER })
    expect(res).toMatchObject({ ok: false, code: S2S_ERRORS.PROJECT_NOT_OWNED })
  })

  it('owner missing → project-not-owned', async () => {
    nativeOwner()
    seedLiveGrant()
    globalThis.__userOneFn = () => {
      throw new Error('cast')
    }
    const res = await exportProject({ body: { payload: { projectId: PROJECT } }, callerOrigin: CALLER })
    expect(res).toMatchObject({ ok: false, code: S2S_ERRORS.PROJECT_NOT_OWNED })
  })

  it('owner is a mirror row (federation subdoc) → project-not-owned', async () => {
    nativeOwner()
    seedLiveGrant()
    globalThis.__userOneFn = () => ({
      _id: OWNER,
      federation: { origin: CALLER },
      suspended: false,
    })
    const res = await exportProject({ body: { payload: { projectId: PROJECT } }, callerOrigin: CALLER })
    expect(res).toMatchObject({ ok: false, code: S2S_ERRORS.PROJECT_NOT_OWNED })
    expect(globalThis.__patDocs).toHaveLength(0)
  })

  // Mongoose materializes a POPULATED EMPTY `{}` subdoc on native
  // `User.create` (no default, inline schema) — it is still `owner.federation`
  // truthy, so the mirror mark has to be `federation.origin`, NOT bare
  // subdoc presence (caught live, 2d smoke: 2a refused every export
  // "owner missing/mirror").
  it('owner with an EMPTY federation subdoc (native mongoose create) is NOT a mirror → exported', async () => {
    nativeOwner()
    seedLiveGrant()
    globalThis.__userOneFn = () => ({
      _id: OWNER,
      federation: {},
      suspended: false,
    })
    const res = await exportProject({ body: { payload: { projectId: PROJECT } }, callerOrigin: CALLER })
    expect(res.ok).toBe(true)
    expect(globalThis.__patDocs).toHaveLength(1)
  })

  it('owner suspended → project-not-owned', async () => {
    nativeOwner()
    seedLiveGrant()
    globalThis.__userOneFn = () => ({ _id: OWNER, federation: undefined, suspended: true })
    const res = await exportProject({ body: { payload: { projectId: PROJECT } }, callerOrigin: CALLER })
    expect(res).toMatchObject({ ok: false, code: S2S_ERRORS.PROJECT_NOT_OWNED })
  })

  it('no live consent grant → export-no-consent (no mint)', async () => {
    nativeOwner()
    const res = await exportProject({ body: { payload: { projectId: PROJECT } }, callerOrigin: CALLER })
    expect(res.ok).toBe(false)
    expect(res.code).toBe(S2S_ERRORS.EXPORT_NO_CONSENT)
    expect(globalThis.__patDocs).toHaveLength(0)
    expect(globalThis.__ledgerWrites).toHaveLength(0)
  })

  it('happy path → fresh PAT + git_url + expires_at (snake_case), sha256 persisted, raw never stored', async () => {
    nativeOwner()
    seedLiveGrant()
    const res = await exportProject({ body: { payload: { projectId: PROJECT } }, callerOrigin: CALLER })
    expect(res.ok).toBe(true)
    const p = res.payload
    // snake_case keys (SESSION 11 LOCKED; plan 09 §2 gitUrl naming
    // superseded — the 2b wizard reads these).
    expect(p.git_url).toBe(`https://beta.example/git/${PROJECT}`)
    expect(typeof p.pat).toBe('string')
    expect(p.pat.startsWith('olp_')).toBe(true)
    expect(p.pat.length).toBe(40)
    expect(typeof p.expires_at).toBe('number')
    // the minted doc: sha256 only (64 hex chars) + partial first-8;
    // the RAW token is never a field of the doc.
    const doc = globalThis.__patDocs.at(-1)
    const expectedHash = createHash('sha256').update(p.pat).digest('hex')
    expect(doc.accessToken).toBe(expectedHash)
    expect(doc.accessTokenPartial).toBe(p.pat.substring(0, 8))
    expect(doc.scope).toBe(EXPORT_SCOPE)
    expect(doc.type).toBe('personal_access_token')
    expect(doc.user_id).toBe(OWNER)
    expect(doc.pat).toBeUndefined()
  })

  it('idempotent re-export → fresh raw PAT per receipt (ledger row refreshed, same filter)', async () => {
    nativeOwner()
    seedLiveGrant()
    const r1 = await exportProject({ body: { payload: { projectId: PROJECT } }, callerOrigin: CALLER })
    const r2 = await exportProject({ body: { payload: { projectId: PROJECT } }, callerOrigin: CALLER })
    expect(r1.ok).toBe(true)
    expect(r2.ok).toBe(true)
    expect(r2.payload.pat).not.toBe(r1.payload.pat)
    // ledger upsert is on (owner, projectId, homeOrigin) — both writes
    // refresh the same row (2c sweep anchor).
    expect(globalThis.__ledgerWrites).toHaveLength(2)
    for (const w of globalThis.__ledgerWrites) {
      expect(w.filter).toMatchObject({ owner: OWNER, projectId: PROJECT, homeOrigin: CALLER })
      expect(w.update.$set.status).toBe('exported')
      // `upsert: true` is mandatory — without it `updateOne` is a no-op
      // (the `$setOnInsert` never applies and no ledger row exists for
      // 2c to sweep; caught live, 2d smoke).
      expect(w.opts).toEqual({ upsert: true })
    }
  })

  it('TTL clamp: requested expiry beyond max → clamps to maxExportTtlSeconds', async () => {
    nativeOwner()
    seedLiveGrant()
    globalThis.__exportSettings.export.maxExportTtlSeconds = 3600
    const expiresAt = Math.floor(Date.now() / 1000) + 864000
    const res = await exportProject({
      body: { payload: { projectId: PROJECT }, expiresAt },
      callerOrigin: CALLER,
    })
    expect(res.ok).toBe(true)
    const nowSec = Math.floor(Date.now() / 1000) + 1
    expect(res.payload.expires_at - nowSec).toBeLessThanOrEqual(3600 + 2)
    expect(globalThis.__patDocs.at(-1).expiresAt.getTime()).toBeLessThanOrEqual(nowSec * 1000 + 3600 * 1000 + 2000)
  })

  it('TTL clamp: grant remaining shorter than request → clamps to grant remaining', async () => {
    nativeOwner()
    seedLiveGrant('short-g')
    globalThis.__pttlMap.set(`federation:oidc:Grant:short-g`, 5000 * 1000) // 5000 s ≈ 1.39 h
    const expiresAt = Math.floor(Date.now() / 1000) + 86400
    const res = await exportProject({
      body: { payload: { projectId: PROJECT }, expiresAt },
      callerOrigin: CALLER,
    })
    expect(res.ok).toBe(true)
    const nowSec = Math.floor(Date.now() / 1000) + 1
    expect(res.payload.expires_at - nowSec).toBeLessThanOrEqual(5000 + 2)
  })

  it('grant doc gone by TTL (pttl -1) → soft degrade: TTL = max cap (no failure)', async () => {
    nativeOwner()
    seedLiveGrant()
    const fake = globalThis.__fedRedis
    const docKey = `federation:oidc:Grant:consent-g1`
    fake.__strings.delete(docKey) // simulates TTL expiry
    globalThis.__pttlMap.set(docKey, -2)
    // membership still in the SET (stale) → findByAccountAndClient skips
    // (doc missing → null → no-consent). That is the CORRECT behavior:
    // a dead grant is a dead consent (re-consent required).
    const res = await exportProject({ body: { payload: { projectId: PROJECT } }, callerOrigin: CALLER })
    expect(res.ok).toBe(false)
    expect(res.code).toBe(S2S_ERRORS.EXPORT_NO_CONSENT)
  })

  it('ledger failure must not break a legitimate export (PAT still returned)', async () => {
    nativeOwner()
    seedLiveGrant()
    // Force the ledger write to throw (the action .catch logs it and
    // the PAT is still returned — 2c's sweep is best-effort on top).
    const { FederationExportGrant } = await import('../../../app/models/FederationExportGrant.mjs')
    const realUpdateOne = FederationExportGrant.updateOne
    Object.defineProperty(FederationExportGrant, 'updateOne', {
      value: async () => {
        throw new Error('mongo down')
      },
      configurable: true,
    })
    try {
      const res = await exportProject({ body: { payload: { projectId: PROJECT } }, callerOrigin: CALLER })
      expect(res.ok).toBe(true)
      expect(globalThis.__patDocs).toHaveLength(1)
    } finally {
      Object.defineProperty(FederationExportGrant, 'updateOne', { value: realUpdateOne, configurable: true })
    }
  })
})
