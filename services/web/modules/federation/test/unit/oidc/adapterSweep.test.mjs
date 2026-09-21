// `RedisOidcProviderAdapter` client sweep index unit tests (04 §5
// `killOutstandingCodes`, 06 §178 "not over-cross").
//
// The index (`federation:oidc:client:<clientId>`) is a SET of doc keys
// minted for one client. In oidc-provider 9, `Grant extends BaseToken` and
// BaseToken IN_PAYLOAD includes `clientId` — EVERY BaseToken-derived doc
// (AuthorizationCode, AccessToken, Grant, …) persists a `clientId`. So the
// sweep index is gated on the GRANTABLE MODEL set (token models) rather
// than on `clientId` presence: a `Grant` doc DOES carry `clientId`, yet a
// consent Grant must NOT be swept (06 §174: revocation kills NEW grants,
// not the consent record). Session/Interaction extend BaseModel (no
// `clientId`) and enter the index neither in principle nor by gate.

import { vi, describe, it, expect, beforeEach } from 'vitest'

// RedisWrapper is the adapter's only dynamic edge (default lazy path);
// mock it so the default `revokeClientCodes(clientId)` path is
// exercised too. The mock client is globalThis-driven (see
// test/unit/bootstrap.mjs resetAllMocks + resetModules note).
vi.mock('../../../../../app/src/infrastructure/RedisWrapper.mjs', () => ({
  default: {
    client: (name) => {
      if (name !== 'federation') {
        throw new Error(`unexpected client name: ${name}`)
      }
      return globalThis.__adapterRedis
    },
  },
}))

// Minimal ioredis-shaped fake: strings + SETs (S members).
function makeFakeRedis() {
  const strings = new Map()
  const sets = new Map()
  return {
    __strings: strings,
    __sets: sets,
    get: async (k) => (strings.has(k) ? strings.get(k) : null),
    set: async (k, v, ...args) => {
      strings.set(k, v)
      // EX/PX args are accepted, not simulated (TTL is orthogonal here).
      return 'OK'
    },
    del: async (k) => {
      let n = 0
      if (strings.delete(k)) n++
      if (sets.delete(k)) n++
      return n
    },
    pttl: async (k) => (strings.has(k) ? -1 : -2),
    expire: async () => 1,
    sadd: async (k, ...members) => {
      const s = sets.get(k) ?? new Set()
      let added = 0
      for (const m of members) {
        if (!s.has(m)) {
          s.add(m)
          added++
        }
      }
      sets.set(k, s)
      return added
    },
    srem: async (k, ...members) => {
      const s = sets.get(k) ?? new Set()
      let removed = 0
      for (const m of members) {
        if (s.delete(m)) removed++
      }
      sets.set(k, s)
      return removed
    },
    smembers: async (k) => [...(sets.get(k) ?? new Set())],
    scard: async (k) => sets.get(k) ? sets.get(k).size : 0,
  }
}

import createAdapter, {
  revokeClientCodes,
  _makeTestFactory,
} from '../../../oidc/RedisOidcProviderAdapter.mjs'
import { federationClientId } from '../../../oidc/clients.mjs'

const CLIENT_ID = federationClientId('beta.example')

describe('adapter client sweep index (04 §5 / 06 §178)', () => {
  beforeEach(() => {
    globalThis.__adapterRedis = makeFakeRedis()
  })

  it('upsert(token doc with clientId) → doc key is indexed under the client', async () => {
    const fake = globalThis.__adapterRedis
    const factory = _makeTestFactory(fake)
    const codes = factory('AuthorizationCode')
    await codes.upsert('c1', { grantId: 'g1', clientId: CLIENT_ID, sessionUid: 's1' }, 120)

    const members = await fake.smembers(`federation:oidc:client:${CLIENT_ID}`)
    expect(members).toEqual(['federation:oidc:AuthorizationCode:c1'])
    // The grant index is maintained in parallel (existing behavior).
    expect(await fake.scard(`federation:oidc:grant:g1`)).toBe(1)
  })

  it('upsert(Session, no clientId) → enters sub-index ONLY (06 §178 not over-cross at the index)', async () => {
    const fake = globalThis.__adapterRedis
    const factory = _makeTestFactory(fake)
    const sessions = factory('Session')
    await sessions.upsert('s1', { uid: 'u1', sessionUid: 's1' }, 3600)

    expect(await fake.get(`federation:oidc:sub:u1`)).toBe('s1')
    // A Session doc carries no `clientId` → it can never enter the
    // sweep index even in principle.
    const members = await fake.smembers(`federation:oidc:client:${CLIENT_ID}`)
    expect(members).toEqual([])
  })

  it('upsert(Grant, WITH clientId in payload) → NOT indexed (model gate, 06 §174)', async () => {
    const fake = globalThis.__adapterRedis
    const factory = _makeTestFactory(fake)
    const grants = factory('Grant')
    await grants.upsert('gr1', { clientId: CLIENT_ID, accountId: 'a1' }, 3600)

    // The doc is persisted (v9 does persist Grant docs: Grant extends
    // BaseToken, IN_PAYLOAD includes clientId)…
    expect(await fake.get(`federation:oidc:Grant:gr1`)).not.toBeNull()
    // …but never enters the client sweep index: consent records are
    // excluded by the GRANTABLE model gate (06 §174) even though the
    // payload carries `clientId`.
    expect(await fake.smembers(`federation:oidc:client:${CLIENT_ID}`)).toEqual([])
    // A sweep is a no-op AND leaves the Grant doc intact — the consent
    // record survives revocation.
    expect(await revokeClientCodes(CLIENT_ID, fake)).toBe(0)
    expect(await fake.get(`federation:oidc:Grant:gr1`)).not.toBeNull()
  })

  it('destroy(code) → removes doc AND drops it from the client index', async () => {
    const fake = globalThis.__adapterRedis
    const factory = _makeTestFactory(fake)
    const codes = factory('AuthorizationCode')
    await codes.upsert('c1', { clientId: CLIENT_ID }, 120)
    await codes.upsert('c2', { clientId: CLIENT_ID }, 120)
    await codes.destroy('c1')

    const members = await fake.smembers(`federation:oidc:client:${CLIENT_ID}`)
    expect(members).toEqual(['federation:oidc:AuthorizationCode:c2'])
  })

  it('revokeClientCodes → destroys every member doc, deletes the set, returns the count', async () => {
    const fake = globalThis.__adapterRedis
    const factory = _makeTestFactory(fake)
    const codes = factory('AuthorizationCode')
    const tokens = factory('AccessToken')
    await codes.upsert('c1', { grantId: 'g1', clientId: CLIENT_ID }, 120)
    await tokens.upsert('t1', { grantId: 'g2', clientId: CLIENT_ID }, 60)

    const destroyed = await revokeClientCodes(CLIENT_ID, fake)
    expect(destroyed).toBe(2)
    expect(await fake.get(`federation:oidc:AuthorizationCode:c1`)).toBeNull()
    expect(await fake.get(`federation:oidc:AccessToken:t1`)).toBeNull()
    expect(await fake.scard(`federation:oidc:client:${CLIENT_ID}`)).toBe(0)
    // Grant SETs were cleaned by the per-doc destroy (scard 0 → del).
    expect(await fake.scard(`federation:oidc:grant:g1`)).toBe(0)
  })

  it('revokeClientCodes is idempotent: an absent index returns 0', async () => {
    const fake = globalThis.__adapterRedis
    expect(await revokeClientCodes(CLIENT_ID, fake)).toBe(0)
  })

  it('revokeClientCodes tolerates stale members (doc already expired by TTL)', async () => {
    const fake = globalThis.__adapterRedis
    const factory = _makeTestFactory(fake)
    const codes = factory('AuthorizationCode')
    await codes.upsert('c1', { clientId: CLIENT_ID }, 120)
    // Simulate TTL expiry: doc gone, SET membership not (the adapter
    // does not run a reaper; real Redis TTLs the doc directly, the
    // SET is reclaimed on its last real SREM by the next destroy or by
    // the sweep itself).
    await fake.del(`federation:oidc:AuthorizationCode:c1`)

    const destroyed = await revokeClientCodes(CLIENT_ID, fake)
    expect(destroyed).toBe(1)
    expect(await fake.scard(`federation:oidc:client:${CLIENT_ID}`)).toBe(0)
  })

  it('default path (no injected client) uses RedisWrapper.client("federation")', async () => {
    const fake = globalThis.__adapterRedis
    const factory = createAdapter()
    const codes = factory('AuthorizationCode')
    await codes.upsert('c1', { clientId: CLIENT_ID }, 120)
    expect(await fake.get(`federation:oidc:AuthorizationCode:c1`)).not.toBeNull()
    await revokeClientCodes(CLIENT_ID)
    expect(await fake.get(`federation:oidc:AuthorizationCode:c1`)).toBeNull()
  })
})
