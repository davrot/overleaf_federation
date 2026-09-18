import { vi, describe, it, expect, beforeEach } from 'vitest'
import { generateSigningKey } from '@oidfed/core'

// In-memory stub: supports exactly the query surface the keystore uses.
// State lives on `globalThis` so it survives `vi.resetModules()` (the
// factory closure is re-created on reimport, but always reads the same store).
vi.mock('../../../app/models/FederationKey.mjs', () => {
  const store = (globalThis.__FK = globalThis.__FK || { rows: [], n: 0 })
  const rows = () => store.rows

  function filterMatch(filter, doc) {
    for (const [k, v] of Object.entries(filter)) {
      if (typeof v === 'object' && v !== null && '$ne' in v) {
        if (doc[k] === v.$ne) return false
      } else if (typeof v === 'object' && v !== null) {
        for (const op of ['$lt', '$lte', '$gt', '$gte']) {
          if (op in v) {
            const val = doc[k]
            const target = v[op]
            const cmp = val < target ? -1 : val > target ? 1 : 0
            if (op === '$lt' && !(cmp < 0)) return false
            if (op === '$lte' && !(cmp <= 0)) return false
            if (op === '$gt' && !(cmp > 0)) return false
            if (op === '$gte' && !(cmp >= 0)) return false
          }
        }
      } else if (doc[k] !== v) {
        return false
      }
    }
    return true
  }

  function makeChain(filter, isFind) {
    let sortSpec = null
    function resolve() {
      let matched = rows().filter((d) => filterMatch(filter, d))
      if (sortSpec) {
        const [key, dir] = Object.entries(sortSpec)[0]
        matched = [...matched].sort((a, b) => {
          const cmp = a[key] < b[key] ? -1 : a[key] > b[key] ? 1 : 0
          return dir === 1 || dir === 'ascending' ? cmp : -cmp
        })
      }
      return isFind ? matched : matched[0] ?? null
    }
    const chain = {
      sort(spec) {
        sortSpec = spec
        return chain
      },
      lean() {
        return Promise.resolve(resolve())
      },
      then(fn) {
        return Promise.resolve(resolve()).then((r) => fn(r))
      },
    }
    return chain
  }

  // Model default-exports the mock; named exports mirror the real files.
  const model = {
    async create(doc) {
      store.n++
      const stored = { _id: store.n, ...doc }
      store.rows.push(stored)
      return stored
    },
    findOne(filter) {
      return makeChain(filter, false)
    },
    find(filter) {
      return makeChain(filter, true)
    },
    async updateOne(filter, updates) {
      const idx = store.rows.findIndex((d) => filterMatch(filter, d))
      if (idx === -1) return { modifiedCount: 0 }
      store.rows[idx] = { ...store.rows[idx], ...updates }
      return { modifiedCount: 1 }
    },
  }

  return {
    default: model,
    FederationKey: model,
    __resetRows: () => {
      store.rows = []
      store.n = 0
    },
    __getRows: () => store.rows,
    __setRows: (next) => {
      store.rows = next
    },
  }
})

vi.mock('@overleaf/settings', () => ({
  default: {
    federation: {
      enabled: true,
      keyRotationGraceDays: 14,
    },
  },
}))

vi.mock('@overleaf/logger', () => ({
  default: {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
  },
}))

function resetMocks() {
  vi.resetModules()
}

describe('Federation keystore (02 §5, 04 §4)', () => {
  let mod
  let model
  let modelReset
  let modelGet
  let modelSet

  beforeEach(async () => {
    resetMocks()
    const modelModule = await import('../../../app/models/FederationKey.mjs')
    model = modelModule.default
    modelReset = modelModule.__resetRows
    modelGet = modelModule.__getRows
    modelSet = modelModule.__setRows
    modelReset()

    mod = await import('../../../oidf/keystore.mjs')
    mod._clearKeySetCache()
  })

  async function seedOne(purpose = 'federation') {
    const { publicKey, privateKey } = await generateSigningKey('ES256')
    const now = Math.floor(Date.now() / 1000)
    await model.create({
      purpose,
      kid: publicKey.kid,
      algorithm: 'ES256',
      publicKey,
      privateKey,
      state: 'active',
      expiresAt: now + 48 * 3600,
      publishedAt: now,
      stateChangedAt: now,
    })
  }

  it('bootstrap generates both keys when neither exists', async () => {
    await mod.ensureBootstrapped()
    const rows = modelGet()
    const feds = rows.filter(r => r.purpose === 'federation')
    const oidcs = rows.filter(r => r.purpose === 'oidc')
    expect(feds.length).toBe(1)
    expect(oidcs.length).toBe(1)
    expect(feds[0].state).toBe('active')
    expect(oidcs[0].state).toBe('active')
  })

  it('bootstrap is idempotent', async () => {
    await seedOne('federation')
    await seedOne('oidc')
    await mod.ensureBootstrapped()
    const rows = modelGet()
    expect(rows.filter(r => r.purpose === 'federation').length).toBe(1)
    expect(rows.filter(r => r.purpose === 'oidc').length).toBe(1)
  })

  describe('FederationKeyLifecycleProvider (federation purpose)', () => {
    it('getFederationKeySet returns { signer, publicJwk, keys }', async () => {
      await seedOne()
      const provider = mod.createKeyProvider()
      const keyset = await provider.getFederationKeySet()
      expect(keyset.signer).toBeDefined()
      expect(keyset.publicJwk).toBeDefined()
      expect(typeof keyset.publicJwk.kid).toBe('string')
      // `keys` (array of public JWKs) is a superset of what the leaf serves
      expect(Array.isArray(keyset.keys)).toBe(true)
      expect(keyset.keys.length).toBeGreaterThanOrEqual(1)
    })

    it('serves published + active + retiring keys in `keys` (02 §5 grace)', async () => {
      const { publicKey, privateKey } = await generateSigningKey('ES256')
      const now = Math.floor(Date.now() / 1000)
      modelSet([
        {
          purpose: 'federation',
          kid: 'kid-published',
          algorithm: 'ES256',
          publicKey: {
            kty: 'EC',
            kid: 'kid-published',
            crv: 'P-256',
            x: 'aaa',
            y: 'bbb',
            alg: 'ES256',
            use: 'sig',
          },
          privateKey: { kty: 'EC', kid: 'kid-published' },
          state: 'published',
          publishedAt: now,
          stateChangedAt: now,
          expiresAt: now + 48 * 3600,
        },
        {
          purpose: 'federation',
          kid: publicKey.kid,
          algorithm: 'ES256',
          publicKey,
          privateKey,
          state: 'active',
          publishedAt: now,
          stateChangedAt: now,
          expiresAt: now + 48 * 3600,
        },
        {
          purpose: 'federation',
          kid: 'kid-retiring',
          algorithm: 'ES256',
          publicKey: {
            kty: 'EC',
            kid: 'kid-retiring',
            crv: 'P-256',
            x: 'eee',
            y: 'fff',
            alg: 'ES256',
            use: 'sig',
          },
          privateKey: { kty: 'EC', kid: 'kid-retiring' },
          state: 'retiring',
          publishedAt: now,
          stateChangedAt: now,
          expiresAt: now + 48 * 3600,
        },
        {
          purpose: 'federation',
          kid: 'kid-revoked',
          algorithm: 'ES256',
          publicKey: {
            kty: 'EC',
            kid: 'kid-revoked',
            crv: 'P-256',
            x: 'ggg',
            y: 'hhh',
            alg: 'ES256',
            use: 'sig',
          },
          privateKey: { kty: 'EC', kid: 'kid-revoked' },
          state: 'revoked',
          publishedAt: now,
          stateChangedAt: now,
          expiresAt: now + 48 * 3600,
          revokedAt: now,
          revokeReason: 'test',
        },
      ])
      mod._clearKeySetCache()
      const provider = mod.createKeyProvider()
      const keyset = await provider.getFederationKeySet()
      const kids = keyset.keys.map(k => k.kid)
      expect(kids).toContain('kid-published')
      expect(kids).toContain(publicKey.kid)
      expect(kids).toContain('kid-retiring')
      expect(kids).not.toContain('kid-revoked')
    })

    it('throws if no `active` federation key exists', async () => {
      modelSet([
        {
          purpose: 'federation',
          kid: 'kid-published',
          algorithm: 'ES256',
          publicKey: { kty: 'EC', kid: 'kid-published' },
          privateKey: { kty: 'EC', kid: 'kid-published' },
          state: 'published',
          publishedAt: 0,
          stateChangedAt: 0,
        },
      ])
      mod._clearKeySetCache()
      const provider = mod.createKeyProvider()
      let err = null
      try {
        await provider.getFederationKeySet()
      } catch (e) {
        err = e
      }
      expect(err).not.toBeNull()
      expect(String(err.message)).toMatch(/No active federation/)
    })
  })

  describe('leaf + historical payloads (02 §2, 04 §5)', () => {
    it('leafJwksPayload serves published + active + retiring (not revoked)', async () => {
      const now = Math.floor(Date.now() / 1000)
      modelSet([
        { purpose: 'federation', kid: 'k1', state: 'published',
          publicKey: { kid: 'k1', kty: 'EC', crv: 'P-256', x: '1', y: '2', alg: 'ES256', use: 'sig' },
          privateKey: { kid: 'k1', kty: 'EC' },
          publishedAt: now },
        { purpose: 'federation', kid: 'k2', state: 'active',
          publicKey: { kid: 'k2', kty: 'EC', crv: 'P-256', x: '3', y: '4', alg: 'ES256', use: 'sig' },
          privateKey: { kid: 'k2', kty: 'EC' },
          publishedAt: now },
        { purpose: 'federation', kid: 'k3', state: 'revoked',
          publicKey: { kid: 'k3', kty: 'EC', crv: 'P-256', x: '5', y: '6', alg: 'ES256', use: 'sig' },
          privateKey: { kid: 'k3', kty: 'EC' },
          publishedAt: now, revokedAt: now, revokeReason: 'test' },
      ])
      const payload = await mod.leafJwksPayload()
      expect(payload.keys.map(k => k.kid).sort()).toEqual(['k1', 'k2'])
    })

    it('historicalKeySetPayload shape per npm HistoricalKeysPayloadSchema', async () => {
      const now = Math.floor(Date.now() / 1000)
      modelSet([
        {
          purpose: 'federation', kid: 'k1', state: 'active',
          publicKey: { kid: 'k1', kty: 'EC', crv: 'P-256', x: '1', y: '2', alg: 'ES256', use: 'sig' },
          privateKey: { kid: 'k1', kty: 'EC' },
          publishedAt: now, expiresAt: now + 5,
        },
      ])
      const payload = await mod.historicalKeySetPayload('https://a.example')
      expect(payload.iss).toBe('https://a.example')
      expect(typeof payload.iat).toBe('number')
      expect(payload.keys.length).toBe(1)
      expect(payload.keys[0].kty).toBe('EC')
      expect(payload.keys[0].kid).toBe('k1')
      expect(payload.keys[0].exp).toBe(now + 5)
    })
  })

  describe('grace sweep (07 §2)', () => {
    it('moves `retiring` keys past the window to `revoked`', async () => {
      const now = Math.floor(Date.now() / 1000)
      modelSet([
        {
          purpose: 'federation', kid: 'old', state: 'retiring',
          publishedAt: now - 15 * 3600 * 24, stateChangedAt: now - 15 * 3600 * 24,
        },
        {
          purpose: 'federation', kid: 'current', state: 'active',
          publishedAt: now, stateChangedAt: now,
        },
      ])
      const swept = await mod.retireExpiredKeys()
      expect(swept).toBe(1)
      const old = modelGet().find(r => r.kid === 'old')
      const current = modelGet().find(r => r.kid === 'current')
      expect(old.state).toBe('revoked')
      expect(current.state).toBe('active')
    })

    it('leaves `retiring` keys inside the window alone', async () => {
      const now = Math.floor(Date.now() / 1000)
      modelSet([
        {
          purpose: 'federation', kid: 'fresh', state: 'retiring',
          publishedAt: now, stateChangedAt: now,
        },
      ])
      const swept = await mod.retireExpiredKeys()
      expect(swept).toBe(0)
      const doc = modelGet().find(r => r.kid === 'fresh')
      expect(doc.state).toBe('retiring')
    })
  })

  describe('rotation (admin, P1 §7)', () => {
    it('publishKey moves a key into `published` and serves it', async () => {
      modelSet([
        {
          purpose: 'federation', kid: 'a', state: 'active',
          publicKey: { kid: 'a', kty: 'EC', crv: 'P-256', x: '1', y: '2', alg: 'ES256', use: 'sig' },
          privateKey: { kid: 'a', kty: 'EC' },
          publishedAt: 0, stateChangedAt: 0,
        },
      ])
      const provider = mod.createKeyProvider()
      const { publicKey, privateKey } = await generateSigningKey('ES256')
      await provider.publishKey({ publicKey, privateKey })
      const rows = modelGet()
      const published = rows.find(r => r.kid === publicKey.kid)
      expect(published.state).toBe('published')
    })

    it('switchActiveKey moves old active -> retiring, new published -> active', async () => {
      const { publicKey, privateKey } = await generateSigningKey('ES256')
      const now = Math.floor(Date.now() / 1000)
      const newKid = publicKey.kid
      modelSet([
        { purpose: 'federation', kid: 'a', state: 'active',
          publicKey: { kid: 'a', kty: 'EC', crv: 'P-256', x: '1', y: '2', alg: 'ES256', use: 'sig' },
          privateKey: { kid: 'a', kty: 'EC' },
          publishedAt: now, stateChangedAt: now },
        { purpose: 'federation', kid: newKid, state: 'published',
          publicKey,
          privateKey,
          publishedAt: now, stateChangedAt: now },
      ])
      const provider = mod.createKeyProvider()
      await provider.switchActiveKey(newKid)
      const rows = modelGet()
      expect(rows.find(r => r.kid === 'a').state).toBe('retiring')
      expect(rows.find(r => r.kid === newKid).state).toBe('active')
      // Retiring key is still served (02 §5 grace)
      const keyset = await provider.getFederationKeySet()
      const served = keyset.keys.map(k => k.kid)
      expect(served).toHaveLength(2)
      expect(served).toContain('a')
      expect(served).toContain(newKid)
    })

    it('revokeKey moves a key to `revoked` and removes it from served keys', async () => {
      const { publicKey, privateKey } = await generateSigningKey('ES256')
      modelSet([
        { purpose: 'federation', kid: publicKey.kid, state: 'active',
          publicKey,
          privateKey,
          publishedAt: 0, stateChangedAt: 0 },
        { purpose: 'federation', kid: 'b', state: 'retiring',
          publicKey: { kid: 'b', kty: 'EC', crv: 'P-256', x: '1', y: '2', alg: 'ES256', use: 'sig' },
          privateKey: { kid: 'b', kty: 'EC' },
          publishedAt: 0, stateChangedAt: 0 },
      ])
      mod._clearKeySetCache()
      const provider = mod.createKeyProvider()
      await provider.revokeKey('b', 'test')
      const rows = modelGet()
      expect(rows.find(r => r.kid === 'b').state).toBe('revoked')
      const keyset = await provider.getFederationKeySet()
      expect(keyset.keys.map(k => k.kid)).toEqual([publicKey.kid])
    })
  })
})
