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
    federation: {
      enabled: true,
      // content-bridge 2c (09 §5): the export block is test-driven —
      // undefined (default) keeps `sweepOnRevoke` ON.
      get export() {
        return globalThis.__exportSettings
      },
    },
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

// The adapter module: `revokeClientCodes` is the sweep spy (flag-ON
// tests); the default export (createAdapter) is kept real.
vi.mock('../../../oidc/RedisOidcProviderAdapter.mjs', async (importOriginal) => {
  const mod = await importOriginal()
  return {
    ...mod,
    revokeClientCodes: vi.fn(async (...args) => ({
      spyArgs: args,
      result: globalThis.__sweepResult ?? 0,
    })),
  }
})

vi.mock('../../../app/models/FederationPeer.mjs', () => ({
  FederationPeer: {
    updateOne: async (filter, update) => globalThis.__revokeUpdateOneResult ?? {
      matchedCount: 1,
      modifiedCount: 1,
    },
  },
}))

// ── content-bridge 2c (09 §3.3/§5): the export sweep (Sweep.mjs) runs in
//    this file (revoke.mjs imports it) — mock its three seams (no mongo in
//    the unit path). NOTE: vi.mock factories CANNOT reference module-scope
//    bindings; the thunk pattern (globalThis) is the sanctioned shape.

vi.mock('../../../../../app/src/infrastructure/mongodb.mjs', () => ({
  // Sweep.mjs imports { db, ObjectId } — mongodb-legacy style.
  ObjectId: class ObjectId {
    constructor(s) {
      this.s = String(s)
    }
  },
  connectionPromise: Promise.resolve(),
  db: {
    oauthAccessTokens: {
      deleteOne: async query => {
        ;(globalThis.__sweepPatDeletes ??= []).push(query)
        if (globalThis.__sweepDeleteOneFail) {
          throw new Error('mongo down')
        }
        return { deletedCount: 1 }
      },
    },
  },
}))

vi.mock('../../../app/models/FederationExportGrant.mjs', () => ({
  FederationExportGrant: {
    find: filter => ({
      select: () => ({
        lean: async () => {
          globalThis.__sweepFindFilter = filter
          return globalThis.__sweepLedgerRows ?? []
        },
      }),
    }),
    updateMany: async filter => {
      ;(globalThis.__sweepUpdateMany ??= []).push(filter)
      return { matchedCount: 0, modifiedCount: 0 }
    },
  },
  FederationExportGrantSchema: {},
}))

vi.mock('../../../util/Audit.mjs', () => ({
  audit: async args => {
    ;(globalThis.__sweepAudits ??= []).push(args)
  },
  AUDIT_TYPES: { exportSwept: 'federation_export_swept' },
}))

import {
  revokeClientCodes,
} from '../../../oidc/RedisOidcProviderAdapter.mjs'
import revoke from '../../../s2s/actions/revoke.mjs'

describe('S2S revoke action (03 §4.3, 04 §5)', () => {
  beforeEach(() => {
    globalThis.__providerResets = 0
    globalThis.__revokeUpdateOneResult = undefined
    globalThis.__sweepResult = 0
    // 2c export-sweep seams (Sweep.mjs is REAL here — the throttle is the
    // settings gate + the modifiedCount transition guard).
    globalThis.__exportSettings = undefined // undefined → sweepOnRevoke ON
    globalThis.__sweepLedgerRows = []
    globalThis.__sweepPatDeletes = []
    globalThis.__sweepUpdateMany = []
    globalThis.__sweepAudits = []
    globalThis.__sweepFindFilter = undefined
    globalThis.__sweepDeleteOneFail = false
    revokeClientCodes.mockReset()
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

  // 04 §5 / 06 §179: `killOutstandingCodes` (peer toggle, default off).

  it('flag OFF (explicit) → memo reset, NO sweep', async () => {
    const result = await revoke({
      body: { payload: { origin: 'this-connection' } },
      callerOrigin: 'beta.example',
      peer: { killOutstandingCodes: false },
    })
    expect(result.ok).toBe(true)
    expect(globalThis.__providerResets).toBe(1)
    expect(revokeClientCodes).not.toHaveBeenCalled()
  })

  it('flag absent (peer row without the field) → NO sweep (default off)', async () => {
    const result = await revoke({
      body: { payload: { origin: 'this-connection' } },
      callerOrigin: 'beta.example',
      peer: {},
    })
    expect(result.ok).toBe(true)
    expect(revokeClientCodes).not.toHaveBeenCalled()
  })

  it("flag ON + revoked transition → sweeps the caller's outstanding codes (memo still reset)", async () => {
    const peer = { killOutstandingCodes: true }
    const result = await revoke({
      body: { payload: { origin: 'this-connection' } },
      callerOrigin: 'beta.example',
      peer,
    })
    expect(result.ok).toBe(true)
    expect(globalThis.__providerResets).toBe(1)
    expect(revokeClientCodes).toHaveBeenCalledTimes(1)
    expect(revokeClientCodes.mock.calls[0][0]).toBe('urn:overleaf-federation:client:beta.example')
  })

  it('flag ON + double receipt (no write) → sweep skipped (idempotent no-op)', async () => {
    globalThis.__revokeUpdateOneResult = { matchedCount: 0, modifiedCount: 0 }
    const result = await revoke({
      body: { payload: { origin: 'this-connection' } },
      callerOrigin: 'beta.example',
      peer: { killOutstandingCodes: true },
    })
    expect(result.ok).toBe(true)
    expect(globalThis.__providerResets).toBe(0)
    expect(revokeClientCodes).not.toHaveBeenCalled()
  })

  it('flag ON + sweep failure → best-effort: revocation succeeds (error is warn-only)', async () => {
    revokeClientCodes.mockRejectedValueOnce(new Error('redis down'))
    const result = await revoke({
      body: { payload: { origin: 'this-connection' } },
      callerOrigin: 'beta.example',
      peer: { killOutstandingCodes: true },
    })
    expect(result.ok).toBe(true)
    expect(globalThis.__providerResets).toBe(1)
  })

  // ── 2c (09 §3.3/§5): the export sweep — settings-driven (default ON),
  //    INDEPENDENT of the `killOutstandingCodes` flag above (that one is
  //    the oidc-provider code sweep, 06 §179).

  it('revoke transition + default settings → export sweep (ledger + PATs + audit)', async () => {
    globalThis.__sweepLedgerRows = [{ patId: 'pat-1' }, { patId: 'pat-2' }]
    const result = await revoke({
      body: { payload: { origin: 'this-connection' } },
      callerOrigin: 'beta.example',
    })
    expect(result.ok).toBe(true)
    // The sweep runs even with the flag ABSENT (settings-driven, 09 §5).
    expect(globalThis.__sweepFindFilter).toEqual({ homeOrigin: 'beta.example' })
    // Both PAT docs deleted, scope-guarded (09 §3: a ledger row can only
    // name an export-scope token).
    expect(globalThis.__sweepPatDeletes).toHaveLength(2)
    expect(
      globalThis.__sweepPatDeletes[0].scope,
    ).toBe('federation:git_bridge')
    expect(globalThis.__sweepUpdateMany).toEqual([{ homeOrigin: 'beta.example' }])
    const swept = globalThis.__sweepAudits.filter(
      a => a.operation === 'federation_export_swept',
    )
    expect(swept).toHaveLength(1)
    // Redaction (09 §3): origin + constant scope — never a PAT value/hash.
    expect(swept[0].meta).toEqual({
      origin: 'beta.example',
      scope: 'federation:git_bridge',
    })
  })

  it('sweepOnRevoke: false → export sweep disabled (v1 NO-OP preserved)', async () => {
    globalThis.__exportSettings = { sweepOnRevoke: false }
    globalThis.__sweepLedgerRows = [{ patId: 'pat-1' }]
    const result = await revoke({
      body: { payload: { origin: 'this-connection' } },
      callerOrigin: 'beta.example',
    })
    expect(result.ok).toBe(true)
    expect(globalThis.__sweepFindFilter).toBeUndefined()
    expect(globalThis.__sweepPatDeletes).toEqual([])
    expect(globalThis.__sweepUpdateMany).toEqual([])
    expect(globalThis.__sweepAudits).toEqual([])
  })

  it('idempotent double receipt (no write) → export sweep skipped (no double sweep)', async () => {
    globalThis.__revokeUpdateOneResult = { matchedCount: 0, modifiedCount: 0 }
    const result = await revoke({
      body: { payload: { origin: 'this-connection' } },
      callerOrigin: 'beta.example',
    })
    expect(result.ok).toBe(true)
    expect(globalThis.__sweepFindFilter).toBeUndefined()
    expect(globalThis.__sweepPatDeletes).toEqual([])
  })

  it('export sweep best-effort: a PAT delete failure never fails the revocation', async () => {
    globalThis.__sweepLedgerRows = [{ patId: 'pat-1' }]
    globalThis.__sweepDeleteOneFail = true
    const result = await revoke({
      body: { payload: { origin: 'this-connection' } },
      callerOrigin: 'beta.example',
    })
    expect(result.ok).toBe(true)
    // ledger still transitioned + audit still written (per-row
    // best-effort, 03 §4.3: sweep never blocks the revocation).
    expect(globalThis.__sweepUpdateMany).toEqual([{ homeOrigin: 'beta.example' }])
    expect(
      globalThis.__sweepAudits.some(a => a.operation === 'federation_export_swept'),
    ).toBe(true)
  })
})
