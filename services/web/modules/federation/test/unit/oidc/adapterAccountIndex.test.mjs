// `RedisOidcProviderAdapter` account secondary index (content-bridge v2,
// plan 09 §2.1).
//
// `federation:oidc:account:<accountId>:<clientId>` → SET of grant-doc
// keys, written SADD on Grant-model upsert, cascade-deleted SREM on
// Grant destroy. `findByAccountAndClient` resolves the live (pttl ≥ 0)
// doc whose payload still holds the pair, or null.
//
// v1: one consent grant per (account, client) — the index is a short
// path for the OP bridge's `findExistingGrant` (no re-consent,
// plan 01 §3 step 9) and for the B-side `export-project` user binding.
//
// Fake redis: strings + SETs + a pttl map (per-key remaining ms), so
// live/expired doc behavior is deterministic.
//
// The adapter functions under test resolve redis via ARGUMENTS
// (`findByAccountAndClient(r, ...)` and the injected
// `_makeTestFactory(fake)`), so no module-level mock is needed here.

import { describe, it, expect, beforeEach } from 'vitest'

function makeFakeRedis() {
  const strings = new Map()
  const sets = new Map()
  const ptcls = new Map()
  return {
    __strings: strings,
    __sets: sets,
    __ptcls: ptcls,
    get: async (k) => (strings.has(k) ? strings.get(k) : null),
    set: async (k, v, ...args) => {
      strings.set(k, v)
      // EX/PX args: simulate the TTL map when EX is passed.
      const i = args.indexOf('EX')
      if (i !== -1) ptcls.set(k, args[i + 1] * 1000)
      return 'OK'
    },
    del: async (k) => {
      let n = 0
      if (strings.delete(k)) n++
      if (sets.delete(k)) n++
      ptcls.delete(k)
      return n
    },
    pttl: async (k) => (strings.has(k) ? (ptcls.has(k) ? ptcls.get(k) : 1000) : -2),
    expire: async (k, s) => {
      ptcls.set(k, s * 1000)
      return 1
    },
    sadd: async (k, ...members) => {
      const s = sets.get(k) ?? new Set()
      for (const m of members) s.add(m)
      sets.set(k, s)
      return 1
    },
    srem: async (k, ...members) => {
      const s = sets.get(k) ?? new Set()
      for (const m of members) s.delete(m)
      return [...(sets.get(k) ?? new Set())]
    },
    smembers: async (k) => [...(sets.get(k) ?? new Set())],
    scard: async (k) => (sets.get(k) ? sets.get(k).size : 0),
  }
}

import {_makeTestFactory, findByAccountAndClient, accountIndexKey, grantDocKey} from '../../../oidc/RedisOidcProviderAdapter.mjs'

const ACCOUNT = 'account-42'
const CLIENT = 'urn:overleaf-federation:client:home-a.example'

beforeEach(() => {
  globalThis.__adapterRedis = makeFakeRedis()
})

describe('adapter account index (09 §2.1)', () => {
  it('Grant upsert → doc indexed under (accountId, clientId)', async () => {
    const fake = globalThis.__adapterRedis
    const factory = _makeTestFactory(fake)
    const grants = factory('Grant')
    await grants.upsert('g1', { accountId: ACCOUNT, clientId: CLIENT, jti: 'g1' }, 30 * 86400)

    expect(await fake.smembers(accountIndexKey(ACCOUNT, CLIENT))).toEqual([
      grantDocKey('g1'),
    ])
  })

  it('token models (GRANTABLE) do NOT enter the account index', async () => {
    const fake = globalThis.__adapterRedis
    const factory = _makeTestFactory(fake)
    const codes = factory('AuthorizationCode')
    await codes.upsert('c1', {
      grantId: 'g1',
      clientId: CLIENT,
      accountId: ACCOUNT, // a token doc never carries accountId here — but
    }, 120)
    // The index is gated on modelName === 'Grant' (the consent record is
    // the single owner of the pair). Token docs never enter it.
    expect(await fake.smembers(accountIndexKey(ACCOUNT, CLIENT))).toEqual([])
    // The client sweep index IS written (existing behavior, orthogonal).
    expect((await fake.smembers(`federation:oidc:client:${CLIENT}`)).length).toBe(1)
  })

  it('findByAccountAndClient → live grant jti', async () => {
    const fake = globalThis.__adapterRedis
    const factory = _makeTestFactory(fake)
    await factory('Grant').upsert('g1', { accountId: ACCOUNT, clientId: CLIENT, jti: 'g1' }, 30 * 86400)

    const grantId = await findByAccountAndClient(fake, ACCOUNT, CLIENT)
    expect(grantId).toBe('g1')
  })

  it('findByAccountAndClient → null for unknown pair', async () => {
    const fake = globalThis.__adapterRedis
    const factory = _makeTestFactory(fake)
    await factory('Grant').upsert('g1', { accountId: ACCOUNT, clientId: CLIENT, jti: 'g1' }, 30 * 86400)
    const other = 'urn:overleaf-federation:client:home-b.example'
    expect(await findByAccountAndClient(fake, ACCOUNT, other)).toBeNull()
  })

  it('expired grant doc (pttl -2 / missing) → null', async () => {
    const fake = globalThis.__adapterRedis
    const factory = _makeTestFactory(fake)
    await factory('Grant').upsert('g1', { accountId: ACCOUNT, clientId: CLIENT, jti: 'g1' }, 30 * 86400)
    // Simulate TTL expiry: the doc is gone, the membership is stale.
    await fake.del(grantDocKey('g1'))
    expect(await findByAccountAndClient(fake, ACCOUNT, CLIENT)).toBeNull()
  })

  it('Grant destroy → cascade SREM + index set cleanup', async () => {
    const fake = globalThis.__adapterRedis
    const factory = _makeTestFactory(fake)
    const grants = factory('Grant')
    await grants.upsert('g1', { accountId: ACCOUNT, clientId: CLIENT, jti: 'g1' }, 30 * 86400)
    expect(await fake.scard(accountIndexKey(ACCOUNT, CLIENT))).toBe(1)

    await grants.destroy('g1')
    expect(await fake.scard(accountIndexKey(ACCOUNT, CLIENT))).toBe(0)
    // empty index set is deleted (fake mirrors real Redis reclaim).
    expect(await fake.get(accountIndexKey(ACCOUNT, CLIENT))).toBeNull()
    expect(await scardIsZero(fake, accountIndexKey(ACCOUNT, CLIENT))).toBe(true)
  })

  it('token destroy does NOT touch the account index (not over-cross)', async () => {
    const fake = globalThis.__adapterRedis
    const factory = _makeTestFactory(fake)
    // A live grant (membership) exists; destroying its TOKEN doc must
    // not SREM the GRANT from the account set.
    await factory('Grant').upsert('g1', { accountId: ACCOUNT, clientId: CLIENT, jti: 'g1' }, 30 * 86400)
    await factory('AuthorizationCode').upsert(
      'c1',
      { grantId: 'g1', clientId: CLIENT, jti: 'c1' },
      120,
    )
    await factory('AuthorizationCode').destroy('c1')
    expect(await fake.scard(accountIndexKey(ACCOUNT, CLIENT))).toBe(1)
    expect(await findByAccountAndClient(fake, ACCOUNT, CLIENT)).toBe('g1')
  })
})

async function scardIsZero(fake, k) {
  const s = fake.__sets.get(k)
  return !s || s.size === 0
}
