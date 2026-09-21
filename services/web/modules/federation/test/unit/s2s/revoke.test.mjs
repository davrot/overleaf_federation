// S2S `revoke` action unit tests (03 §4.3, 04 §5) — focused on the
// provider-memo invalidation: a successful `revoked` transition MUST
// invalidate the memoized oidc-provider (clients[] = grant minting),
// while the idempotent double-receipt MUST stay side-effect-free
// (no reset, no double write).
//
// Mocked:
//   - oidc/createProvider (the memo reset spy — the module is otherwise
//     heavy/DB-bound; the action only needs `_resetProviderMemo`)
//   - FederationPeer model (`updateOne` driven from globalThis)
//   - oidf/verify (real `S2S_ERRORS` constants via importActual)
//
// The vi.mock factories read `globalThis.__*` because
// test/unit/bootstrap.mjs runs `vi.resetAllMocks()` + `vi.resetModules()`
// in afterEach (a module-level vi.fn implementation would be erased).

import { vi, describe, it, expect, beforeEach } from 'vitest'

vi.mock('@overleaf/settings', () => ({
  default: {
    siteUrl: 'https://alpha.example',
    security: { sessionSecret: 'unit-test-secret' },
    federation: { enabled: true },
  },
}))

vi.mock('@overleaf/logger', () => ({
  default: {
    info: () => {},
    error: () => {},
    warn: () => {},
    debug: () => {},
  },
}))

// Stop the import graph before keystore → FederationKey → Mongoose (no
// mongo in unit tests) — the verify module only needs the endpoint shape.
vi.mock('../../../oidf/ClientAssertionClient.mjs', () => ({
  getS2sEndpoint: () => 'https://alpha.example/federation/s2s',
  buildS2sRequest: async () => ({ headers: {}, body: {} }),
}))

// verify.mjs's other app/src edge (no redis in unit tests).
vi.mock('../../../../../app/src/infrastructure/RedisWrapper.mjs', () => ({
  default: {
    client: () => ({}),
  },
}))


vi.mock('../../../oidc/createProvider.mjs', () => ({
  _resetProviderMemo: () => {
    globalThis.__providerResets = (globalThis.__providerResets ?? 0) + 1
    return true
  },
}))

vi.mock('../../../app/models/FederationPeer.mjs', () => ({
  FederationPeer: {
    updateOne: async (filter, update) => globalThis.__revokeUpdateOneResult ?? {
      matchedCount: 1,
      modifiedCount: 1,
    },
  },
}))

import revoke from '../../../s2s/actions/revoke.mjs'

describe('S2S revoke action (03 §4.3, 04 §5)', () => {
  beforeEach(() => {
    globalThis.__providerResets = 0
    globalThis.__revokeUpdateOneResult = undefined
  })

  it('revoked transition → provider memo invalidated (grant minting stops)', async () => {
    globalThis.__revokeUpdateOneResult = { matchedCount: 1, modifiedCount: 1 }
    const result = await revoke({
      body: { payload: { origin: 'this-connection' } },
      callerOrigin: 'beta.example',
    })
    expect(result.ok).toBe(true)
    expect(globalThis.__providerResets).toBe(1)
  })

  it('idempotent double receipt (already revoked) → ok, NO provider reset', async () => {
    // `status != 'revoked'` match finds nothing: a no-op write.
    globalThis.__revokeUpdateOneResult = { matchedCount: 0, modifiedCount: 0 }
    const result = await revoke({
      body: { payload: { origin: 'this-connection' } },
      callerOrigin: 'beta.example',
    })
    expect(result.ok).toBe(true)
    expect(globalThis.__providerResets).toBe(0)
  })

  it('revoke an origin other than the caller → peer-unknown (contract error)', async () => {
    const result = await revoke({
      body: { payload: { origin: 'third-party.example' } },
      callerOrigin: 'beta.example',
    })
    expect(result.ok).toBe(false)
    expect(result.code).toBe('peer-unknown')
    expect(globalThis.__providerResets).toBe(0)
  })
})
