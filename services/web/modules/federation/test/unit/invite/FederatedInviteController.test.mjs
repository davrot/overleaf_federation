import { vi, describe, it, expect, beforeEach } from 'vitest'
import PrivilegeLevels from '../../../../../app/src/Features/Authorization/PrivilegeLevels.mjs'

vi.mock('@overleaf/settings', () => ({
  default: {
    siteUrl: 'https://alpha.example',
    security: { sessionSecret: 'unit-test-secret' },
    federation: { enabled: true },
  },
}))

vi.mock('@overleaf/logger', () => ({
  default: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
}))

vi.mock('../../../app/models/FederationPeer.mjs', () => ({
  FederationPeer: {
    findOne: (filter) => {
      const doc = (globalThis.__PEERS ?? {})[filter.origin]
      const chain = {
        lean() {
          return Promise.resolve(doc === undefined ? undefined : { ...doc })
        },
        then(f) {
          return Promise.resolve(
            doc === undefined ? undefined : { ...doc },
          ).then((v) => f(v))
        },
      }
      return chain
    },
  },
}))

vi.mock('../../../../../app/src/models/User.mjs', () => ({
  User: {
    findOne: async () =>
      globalThis.__OWNER ?? { email: 'owner@alpha.example', first_name: 'Own', last_name: 'Er' },
  },
}))

vi.mock('../../../../../app/src/models/ProjectInvite.mjs', () => ({
  ProjectInvite: { findOneAndUpdate: vi.fn(async () => ({})) },
}))

vi.mock('../../../../../app/src/Features/Collaborators/CollaboratorsGetter.mjs', () => ({
  default: {
    promises: {
      getMemberIdPrivilegeLevel: vi.fn(async (userId) => {
        return globalThis.__LEVELS?.[userId] ?? PrivilegeLevels.READ_AND_WRITE
      }),
      getProjectOwnerId: vi.fn(async () => globalThis.__OWNER_ID ?? 'owner-id'),
    },
  },
}))

vi.mock('../../../oidf/ClientAssertionClient.mjs', () => ({
  buildS2sRequest: vi.fn(async (origin, action, payload) => ({
    headers: { client_assertion: `jwt-${action}` },
    body: { action, from: 'alpha.example', to: origin, ts: 0, payload },
  })),
  getClientId: () => 'urn:overleaf-federation:client:alpha.example',
}))

vi.mock('../../../oidf/leaf.mjs', () => ({
  getOrigin: () => 'alpha.example',
  leafJwksPayload: vi.fn(async () => ({ keys: [] })),
}))

vi.mock('../../../util/RateLimitStore.mjs', () => ({
  getCachedInvite: vi.fn(async () => globalThis.__INVITE_CACHE ?? null),
  setCachedInvite: vi.fn(async () => {
    globalThis.__INVITE_CACHE_WROTE = true
  }),
  checkRateLimit: vi.fn(async () => true),
}))

vi.mock('../../../rp/State.mjs', () => ({
  createPkceVerifier: vi.fn(() => ({
    verifier: 'verifier-1',
    challenge: 'challenge-1',
    nonce: 'nonce-1',
  })),
  signState: vi.fn(() => 'signed.state'),
  persistPkceState: vi.fn(async () => {}),
}))

import { ProjectInvite } from '../../../../../app/src/models/ProjectInvite.mjs' // eslint-disable-line no-duplicate-imports

function mkRes() {
  const res = { statuses: [], jsonCalls: [], redirectArgs: undefined }
  res.status = (code) => {
    res.statuses.push(code)
    return res
  }
  res.json = (d) => {
    res.jsonCalls.push(d)
    return res
  }
  res.redirect = (loc) => {
    res.redirectArgs = loc
    return res
  }
  return res
}

describe('FederatedInviteController (01 §5, 05 §4)', () => {
  describe('handlePreview (03 §4.2 soft preview)', () => {
    beforeEach(() => {
      globalThis.__PEERS = { 'betalpha.example': { origin: 'betalpha.example', status: 'approved', direction: 'both' } }
      globalThis.__LEVELS = { 'viewer-1': PrivilegeLevels.READ_AND_WRITE }
      globalThis.__INVITE_CACHE = null
      globalThis.__INVITE_CACHE_WROTE = false
      globalThis.fetch = vi.fn(async () => ({
        status: 200,
        ok: true,
        json: async () => ({
          ok: true,
          payload: { approved: true, displayName: 'Alice B.' },
        }),
      }))
    })

    it('wire approved → 200 { approved, displayName } + cache write', async () => {
      const mod = (await import('../../../invite/FederatedInviteController.mjs')).default
      const res = mkRes()
      await mod.handlePreview({ query: { anchor: 'alice:betalpha.example' } }, res)
      expect(globalThis.fetch).toHaveBeenCalledTimes(1)
      expect(res.jsonCalls).toEqual([{ approved: true, displayName: 'Alice B.' }])
      expect(globalThis.__INVITE_CACHE_WROTE).toBe(true)
    })

    it('cached preview short-circuits the wire (04 §6)', async () => {
      globalThis.__INVITE_CACHE = { approved: true, displayName: 'Cached' }
      const mod = (await import('../../../invite/FederatedInviteController.mjs')).default
      const res = mkRes()
      await mod.handlePreview({ query: { anchor: 'alice:betalpha.example' } }, res)
      expect(globalThis.fetch).not.toHaveBeenCalled()
      expect(res.jsonCalls).toEqual([{ approved: true, displayName: 'Cached' }])
    })

    it('wire failure degrades to approved:false (05 §4.1)', async () => {
      globalThis.fetch = vi.fn(async () => { throw new Error('dns') })
      const mod = (await import('../../../invite/FederatedInviteController.mjs')).default
      const res = mkRes()
      await mod.handlePreview({ query: { anchor: 'alice:betalpha.example' } }, res)
      expect(res.statuses).toEqual([])
      expect(res.jsonCalls).toEqual([{ approved: false, displayName: null, degraded: true }])
    })

    it('malformed anchor (no colon) → 400', async () => {
      const mod = (await import('../../../invite/FederatedInviteController.mjs')).default
      const res = mkRes()
      await mod.handlePreview({ query: { anchor: 'no-colon' } }, res)
      expect(res.statuses).toEqual([400])
    })

    it('pending peer → 404', async () => {
      globalThis.__PEERS = { 'betalpha.example': { origin: 'betalpha.example', status: 'pending', direction: 'both' } }
      const mod = (await import('../../../invite/FederatedInviteController.mjs')).default
      const res = mkRes()
      await mod.handlePreview({ query: { anchor: 'alice:betalpha.example' } }, res)
      expect(res.statuses).toEqual([404])
    })

    it('inbound-only → 403 (direction gate)', async () => {
      globalThis.__PEERS = { 'betalpha.example': { origin: 'betalpha.example', status: 'approved', direction: 'inbound' } }
      const mod = (await import('../../../invite/FederatedInviteController.mjs')).default
      const res = mkRes()
      await mod.handlePreview({ query: { anchor: 'alice:betalpha.example' } }, res)
      expect(res.statuses).toEqual([403])
    })
  })

  describe('handleAuthorize (01 §5 + PKCE)', () => {
    const DEFAULT = { projectId: 'project-1', anchor: 'alice:betalpha.example', privileges: 'readAndWrite' }

    beforeEach(() => {
      globalThis.__PEERS = { 'betalpha.example': { origin: 'betalpha.example', status: 'approved', direction: 'both' } }
      globalThis.__LEVELS = { 'viewer-1': PrivilegeLevels.READ_AND_WRITE }
      globalThis.fetch = vi.fn(async () => ({
        status: 200,
        ok: true,
        json: async () => ({
          ok: true,
          payload: { approved: true, displayName: 'Alice B.', institution: 'B' },
        }),
      }))
      ProjectInvite.findOneAndUpdate.mockClear?.()
    })

    function req(body) {
      return { body, query: {}, user: { _id: 'viewer-1' }, session: {} }
    }

    it('non-collaborator → 403 before S2S', async () => {
      globalThis.__LEVELS = { 'viewer-1': PrivilegeLevels.NONE }
      const mod = (await import('../../../invite/FederatedInviteController.mjs')).default
      const res = mkRes()
      await mod.handleAuthorize(req(DEFAULT), res)
      expect(res.statuses).toEqual([403])
      expect(globalThis.fetch).not.toHaveBeenCalled()
    })

    it('invalid privileges (owner) → 400', async () => {
      const mod = (await import('../../../invite/FederatedInviteController.mjs')).default
      const res = mkRes()
      await mod.handleAuthorize(req({ ...DEFAULT, privileges: 'owner' }), res)
      expect(res.statuses).toEqual([400])
    })

    it('B refusal invitee-unknown → 403 + business code', async () => {
      globalThis.fetch = vi.fn(async () => ({
        status: 200, ok: true, json: async () => ({ ok: false, code: 'invitee-unknown' }),
      }))
      const mod = (await import('../../../invite/FederatedInviteController.mjs')).default
      const res = mkRes()
      await mod.handleAuthorize(req(DEFAULT), res)
      expect(res.statuses).toEqual([403])
      expect(res.jsonCalls[0].code).toBe('invitee-unknown')
    })

    it('wire 429 → 502', async () => {
      globalThis.fetch = vi.fn(async () => ({ status: 429, ok: false, json: async () => ({}) }))
      const mod = (await import('../../../invite/FederatedInviteController.mjs')).default
      const res = mkRes()
      await mod.handleAuthorize(req(DEFAULT), res)
      expect(res.statuses).toEqual([502])
    })

    it('success → upsert + 302 to B auth URL (01 §5 step 3)', async () => {
      globalThis.fetch = vi.fn(async (url) => {
        return {
          status: 200, ok: true,
          json: async () => ({ ok: true, payload: { approved: true, displayName: 'Alice B.' } }),
        }
      })
      const mod = (await import('../../../invite/FederatedInviteController.mjs')).default
      const res = mkRes()
      await mod.handleAuthorize(req(DEFAULT), res)
      expect(ProjectInvite.findOneAndUpdate).toHaveBeenCalled()
      expect(globalThis.fetch).toHaveBeenCalled()
      expect(res.redirectArgs).toBeDefined()
      expect(res.redirectArgs.startsWith('https://betalpha.example/federation/oidc/auth?')).toBe(true)
      expect(res.redirectArgs).toContain('code_challenge_method=S256')
    })
  })

  it('FEDERATED_PRIVILEGES excludes owner (07 P1)', async () => {
    const mod = await import('../../../invite/FederatedInviteController.mjs')
    expect(mod.FEDERATED_PRIVILEGES).not.toContain(PrivilegeLevels.OWNER)
  })
})
