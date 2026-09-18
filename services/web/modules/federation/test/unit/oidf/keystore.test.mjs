import { vi, beforeAll, beforeEach, afterAll } from 'vitest'
import mongoose from 'mongoose'
import { start, stop } from 'mongodb-memory-server'

import generateSigningKey from '@oidfed/core'

vi.mock('@overleaf/settings', () => ({
  default: {
    federation: {
      enabled: true,
      keyRotationGraceDays: 14,
    },
  },
  __esModule: true,
}))

vi.mock('@overleaf/logger', () => ({
  default: { info: vi.fn(), error: vi.fn(), debug: vi.fn(), warn: vi.fn() },
}))

beforeAll(async () => {
  const memServer = await start()
  const uri = memServer.getUri('0')
  await mongoose.connect(uri, {
    autoIndex: false,
  })
  this.memServer = memServer
  return uri
})

afterAll(async () => {
  await stop()
})

describe('Federation keystore', () => {
  const keyStore = vi.hoisted(() => ({
    default: {
      get: vi.fn().mockResolvedValue(undefined),
      set: vi.fn().mockResolvedValue(undefined),
    },
  }))

  beforeAll(async () => {
    vi.doMock('@overleaf/redis-wrapper', () => ({
      default: {
        client: (feature) => keyStore.default,
      },
    }))
  })

  let ensureBootstrapped

  beforeEach(async () => {
    await mongoose.connection.dropCollection('federationKeys')
    await mongoose.connection.dropCollection('federationPeers')
    const mod = await import('../oidf/keystore.mjs')
    ensureBootstrapped = mod.ensureBootstrapped
  })

  afterAll(async () => {
    await mongoose.disconnect()
  })

  describe('bootstrap', () => {
    it('generates a key pair for both federation + oidc purposes (first run)', async () => {
      const { FederationKey } = await import(
        '../app/models/FederationKey.mjs'
      )
      await ensureBootstrapped()
      const federation = await FederationKey.findOne({
        purpose: 'federation',
      }).lean()
      const oidc = await FederationKey.findOne({
        purpose: 'oidc',
      }).lean()
      expect(federation).toBeTruthy()
      expect(oidc).toBeTruthy()
      expect(federation.state).toEqual('active')
      expect(oidc.state).toEqual('active')
      expect(federation.privateKey.kid).toBeDefined()
      expect(federation.publicKey.kid).toBeDefined()
    })

    it('does not duplicate keys on second run', async () => {
      const { FederationKey } = await import(
        '../app/models/FederationKey.mjs'
      )
      await ensureBootstrapped()
      await ensureBootstrapped()
      const count = await FederationKey.countDocuments({
        purpose: 'federation',
      })
      expect(count).toEqual(1)
    })
  })

  describe('FederationKeyLifecycleProvider', () => {
    let mod

    beforeEach(async () => {
      mod = await import('../oidf/keystore.mjs')
      mod._clearKeySetCache()
      await ensureBootstrapped()
    })

    it('getFederationKeySet resolves the (unique) active key signer', async () => {
      const keyset = await mod.createKeyProvider().getFederationKeySet()
      expect(keyset.signer).toBeDefined()
      expect(keyset.publicJwk).toBeDefined()
      expect(keyset.publicJwk.kid).toBe(keyset.signer.kid)
      // `keys` contains ONLY the federation-purpose, non-revoked public JWKs
      expect(keyset.keys.length).toBeGreaterThanOrEqual(1)
      expect(keyset.publicJwk.keys.length).toBeGreaterThanOrEqual(1)
    })

    it('publishKey adds a key in `published` state (not signed yet)', async () => {
      const { generateSigningKey } = await import('@oidfed/core')
      const { publicKey, privateKey } = await generateSigningKey('ES256')
      await mod.createKeyProvider().publishKey({ publicKey, privateKey })
      const pub = await (
        await import('../app/models/FederationKey.mjs')
      ).FederationKey.findOne({
        purpose: 'federation',
        kid: publicKey.kid,
      }).lean()
      expect(pub.state).toEqual('published')

      // Both keys appear in the set (active + published)
      const keyset = await mod.createKeyProvider().getFederationKeySet()
      expect(keyset.keys.map((k) => k.kid)).toContain(publicKey.kid)
    })

    it('switchActiveKey moves old active -> retiring, new published -> active', async () => {
      const { generateSigningKey } = await import('@oidfed/core')
      const { publicKey, privateKey } = await generateSigningKey('ES256')
      await mod.createKeyProvider().publishKey({ publicKey, privateKey })
      await mod.createKeyProvider().switchActiveKey(publicKey.kid)
      const [first, second] = await (
        await import('../app/models/FederationKey.mjs')
      ).FederationKey.find({ purpose: 'federation' }).sort({
        publishedAt: 1,
      }).lean()
      expect(first.state).toEqual('retiring')
      expect(second.state).toEqual('active')
      // Retiring key is still served (02 §5 grace window)
      const keyset = await mod.createKeyProvider().getFederationKeySet()
      const kids = keyset.keys.map((k) => k.kid)
      expect(kids).toContain(first.kid)
      expect(kids).toContain(second.kid)
    })

    it('revokeKey marks state `revoked` and removes from served set', async () => {
      const { generateSigningKey } = await import('@oidfed/core')
      const k0 = await (
        await import('../app/models/FederationKey.mjs')
      ).FederationKey.findOne({
        purpose: 'federation',
      }).lean()
      const { publicKey, privateKey } = await generateSigningKey('ES256')
      await mod.createKeyProvider().publishKey({ publicKey, privateKey })
      await mod.createKeyProvider().revokeKey(k0.kid, 'test')
      const keyset = await mod.createKeyProvider().getFederationKeySet()
      expect(keyset.keys.map((k) => k.kid)).not.toContain(k0.kid)
    })
  })

  describe('leaf payload + history', () => {
    beforeEach(async () => {
      const mod = await import('../oidf/keystore.mjs')
      mod._clearKeySetCache()
      await ensureBootstrapped()
    })

    it('leafJwksPayload serves published + active + retiring (not revoked)', async () => {
      const { generateSigningKey } = await import('@oidfed/core')
      const k0 = await (
        await import('../app/models/FederationKey.mjs')
      ).FederationKey.findOne({
        purpose: 'federation',
      }).lean()
      const pub = await (await import('../app/models/FederationKey.mjs'))
        .FederationKey.findOne({
          purpose: 'federation',
        }).lean()
      const { publicKey, privateKey } = await generateSigningKey('ES256')
      await (await import('../oidf/keystore.mjs')).createKeyProvider().publishKey(
        { publicKey, privateKey },
      )
      const payload = await (
        await import('../oidf/keystore.mjs')
      ).leafJwksPayload()
      expect(payload.keys.length).toEqual(2)
    })

    it('historicalKeySetPayload shape per npm HistoricalKeysPayloadSchema', async () => {
      const payload = await (await import('../oidf/keystore.mjs'))
        .historicalKeySetPayload('https://a.example')
      expect(payload.iss).toEqual('https://a.example')
      expect(typeof payload.iat).toBe('number')
      for (const k of payload.keys) {
        expect(k.kty).toEqual('EC')
        expect(k.kid).toBeDefined()
        expect(k.exp).toBeGreaterThan(0)
      }
    })
  })

  describe('grace sweep', () => {
    beforeEach(async () => {
      const mod = await import('../oidf/keystore.mjs')
      mod._clearKeySetCache()
      await ensureBootstrapped()
    })

    it('moves old `retiring` keys past the window to `revoked`', async () => {
      const now = Math.floor(Date.now() / 1000)
      const (
        {
          // We want a key that is `retiring` and whose `stateChangedAt`
          // is older than `Settings.federation.keyRotationGraceDays * 3600 * 24`
        },
      ) = await (
        await import('../app/models/FederationKey.mjs')
      ).FederationKey.findOne({
        purpose: 'federation',
      }).lean()
      // Make it `retiring` and old
      await (await import('../app/models/FederationKey.mjs')).FederationKey.updateOne(
        { purpose: 'federation' },
        {
          state: 'retiring',
          stateChangedAt: now - 15 * 3600 * 24,
        },
      )
      const swept = await (
        await import('../oidf/keystore.mjs')
      ).retireExpiredKeys()
      expect(swept).toEqual(1)
      const doc = await (
        await import('../app/models/FederationKey.mjs')
      ).FederationKey.findOne({
        purpose: 'federation',
      }).lean()
      expect(doc.state).toEqual('revoked')
    })

    it('leaves `retiring` keys inside the window alone', async () => {
      await (
        await import('../app/models/FederationKey.mjs')
      ).FederationKey.updateOne(
        { purpose: 'federation' },
        { state: 'retiring' },
      )
      const swept = await (
        await import('../oidf/keystore.mjs')
      ).retireExpiredKeys()
      expect(swept).toEqual(0)
    })
  })
})
