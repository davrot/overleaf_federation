// Site-admin federation surface unit tests (P1, 07 §P1).
//
// Real: @oidfed/core — fixture leaf ECs are built with the real
// `signEntityConfiguration` (signer + jwks) so `handlePin`'s decode +
// thumbprint path is exercised end to end.
// Mocks: FederationPeer/FederationKey (mongoose models), createProvider
// memo reset, ClientAssertionClient, keystore provider, Audit,
// ProjectAuditLogEntry. fetch: leaf well-known (pin) + S2S (revoke).

import { vi, describe, it, expect, beforeEach } from 'vitest'

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

vi.mock('../../../app/models/FederationPeer.mjs', () => {
  // findOne is thenable (hydrate) — `await findOne(...)` returns the
  // raw doc (so `.save()` and writes hit the shared __PEERS record) —
  // and chainable (`.lean()` returns a POJO copy).
  function findOneQuery(filter) {
    const q = { _lean: false }
    q.lean = () => {
      q._lean = true
      return q
    }
    q.then = (res, rej) =>
      Promise.resolve(
        q._lean
          ? (globalThis.__PEERS?.[filter.origin] ? { ...globalThis.__PEERS[filter.origin] } : undefined)
          : globalThis.__PEERS?.[filter.origin],
      ).then(res, rej)
    return q
  }
  return {
    FederationPeer: {
      findOne: findOneQuery,
      find: () => ({
        sort: () => ({
          select: () => ({
            lean: () => Promise.resolve(globalThis.__PEER_LIST ?? []),
          }),
        }),
      }),
      create: vi.fn(async (attrs) => {
        ;(globalThis.__CREATED ??= []).push(attrs)
        return { ...attrs }
      }),
      deleteOne: vi.fn(async (filter) => {
        delete globalThis.__PEERS[filter.origin]
        return { n: 1 }
      }),
    },
  }
})

vi.mock('../../../app/models/FederationKey.mjs', () => ({
  FederationKey: {
    find: () => ({
      sort: () => ({
        select: () => ({
          lean: () => Promise.resolve(globalThis.__KEY_LIST ?? []),
        }),
      }),
    }),
  },
}))

vi.mock('../../../oidc/createProvider.mjs', () => ({
  _resetForTest: vi.fn(),
}))

vi.mock('../../../oidf/ClientAssertionClient.mjs', () => ({
  buildS2sRequest: vi.fn(async (origin, action, payload) => ({
    headers: { client_assertion: 'jwt-assertion' },
    body: { action, from: 'alpha.example', to: origin, ts: 0, payload },
  })),
}))

vi.mock('../../../oidf/keystore.mjs', () => ({
  createKeyProvider: () => globalThis.__KEY_PROVIDER,
}))

vi.mock('../../../util/Audit.mjs', () => ({
  audit: vi.fn(async () => ({})),
  AUDIT_TYPES: {
    peerRegistered: 'federation_peer_registered',
    peerApproved: 'federation_peer_approved',
    peerRevoked: 'federation_peer_revoked',
    trustAnchorPinned: 'federation_trust_anchor_pinned',
    keyRotated: 'federation_key_rotated',
  },
}))

vi.mock('../../../../../app/src/models/ProjectAuditLogEntry.mjs', () => ({
  ProjectAuditLogEntry: {
    find: () => ({
      sort: () => ({
        limit: (n) => ({
          lean: () =>
            Promise.resolve(
              (globalThis.__AUDIT_ROWS ?? [])
                .slice(0, n)
                .map((m) => ({
                  _id: m._id,
                  projectId: m.projectId,
                  operation: m.operation,
                  initiatorId: m.initiatorId,
                  ipAddress: m.ipAddress,
                  timestamp: m.timestamp,
                  info: { meta: m.meta },
                })),
            ),
        }),
      }),
    }),
  },
}))

import { FederationPeer } from '../../../app/models/FederationPeer.mjs'
import { audit } from '../../../util/Audit.mjs'
import { _resetForTest } from '../../../oidc/createProvider.mjs'

import FederatedAdminController from '../../../admin/FederationAdminController.mjs'

describe('FederationAdminController (P1, 07 §P1)', () => {
  let Mod

  beforeEach(async () => {
    globalThis.__PEERS = {}
    globalThis.__PEER_LIST = []
    globalThis.__KEY_LIST = []
    globalThis.__AUDIT_ROWS = []
    globalThis.__CREATED = undefined
    globalThis.__KEY_PROVIDER = {
      publishKey: vi.fn(async () => ({})),
      switchActiveKey: vi.fn(async () => ({})),
      revokeKey: vi.fn(async () => ({})),
    }
    Mod = FederatedAdminController
    audit.mockClear?.()
  })

  function auditCalls() {
    return audit.mock.calls ?? []
  }

  async function freshSigner() {
    const { generateSigningKey, createFederationSigningKey } = await import('@oidfed/core')
    const generated = await generateSigningKey('ES256')
    const { signer, publicJwk } = createFederationSigningKey(generated.privateKey)
    return { signer, publicJwk }
  }

  async function leafEcFor(origin, signer, publicJwk) {
    const { signEntityConfiguration } = await import('@oidfed/core')
    return signEntityConfiguration({
      signer,
      entityId: `https://${origin}`,
      jwks: { keys: [publicJwk] },
    })
  }

  function mkRes() {
    const res = { statuses: [], jsonCalls: [], sent: [] }
    res.status = vi.fn((code) => {
      res.statuses.push(code)
      return res
    })
    res.json = vi.fn((d) => {
      res.jsonCalls.push(d)
      return res
    })
    res.send = vi.fn((body) => {
      res.sent.push(body)
      return res
    })
    res.redirect = vi.fn((loc) => {
      res.location = loc
      return res
    })
    return res
  }

  describe('handlePin (02 §3 pairwise TOFU)', () => {
    it('valid leaf EC → 201 pending row + dual audit (registered + pinned)', async () => {
      const { jwkThumbprint } = await import('@oidfed/core')
      const { signer, publicJwk } = await freshSigner()
      const ecJwt = await leafEcFor('beta.example', signer, publicJwk)
      globalThis.fetch = vi.fn(async () => ({
        ok: true,
        status: 200,
        text: async () => ecJwt,
      }))

      const res = mkRes()
      await Mod.handlePin({ body: { origin: 'beta.example' } }, res)

      expect(res.statuses).toEqual([201])
      const thumbprint = await jwkThumbprint(publicJwk)
      expect(res.jsonCalls[0]).toEqual({
        origin: 'beta.example',
        status: 'pending',
        kid: publicJwk.kid,
        thumbprint,
      })
      expect(globalThis.__CREATED[0]).toMatchObject({
        origin: 'beta.example',
        entityId: 'https://beta.example',
        mode: 'pairwise',
        kid: publicJwk.kid,
        thumbprint,
        status: 'pending',
      })
      const ops = auditCalls().map((call) => call[0].operation)
      expect(ops).toEqual([
        'federation_peer_registered',
        'federation_trust_anchor_pinned',
      ])
      expect(auditCalls().at(-1)[0].meta.anchorThumbprint).toBe(thumbprint)
    })

    it('leaf fetch failure → 502 peer-unreachable', async () => {
      globalThis.fetch = vi.fn(async () => {
        throw new Error('connect ECONNREFUSED')
      })
      const res = mkRes()
      await Mod.handlePin({ body: { origin: 'beta.example' } }, res)
      expect(res.statuses).toEqual([502])
      expect(res.jsonCalls[0].code).toBe('peer-unreachable')
    })

    it('iss/sub mismatch (EC for another origin) → 400 invalid-ec', async () => {
      const { signer, publicJwk } = await freshSigner()
      const ecJwt = await leafEcFor('gamma.example', signer, publicJwk)
      globalThis.fetch = vi.fn(async () => ({
        ok: true,
        status: 200,
        text: async () => ecJwt,
      }))
      const res = mkRes()
      await Mod.handlePin({ body: { origin: 'beta.example' } }, res)
      expect(res.statuses).toEqual([400])
      expect(res.jsonCalls[0].code).toBe('invalid-ec')
    })

    it('origin with scheme/port → 400 (never fetch user input)', async () => {
      globalThis.fetch = vi.fn()
      const res = mkRes()
      await Mod.handlePin({ body: { origin: 'https://beta.example' } }, res)
      expect(res.statuses).toEqual([400])
      expect(globalThis.fetch).not.toHaveBeenCalled()
    })

    it('existing peer → 409 peer-exists', async () => {
      globalThis.__PEERS = {
        'beta.example': { origin: 'beta.example', status: 'approved', save: vi.fn() },
      }
      const res = mkRes()
      await Mod.handlePin({ body: { origin: 'beta.example' } }, res)
      expect(res.statuses).toEqual([409])
      expect(res.jsonCalls[0].code).toBe('peer-exists')
    })

    it('invalid direction → 400', async () => {
      const res = mkRes()
      await Mod.handlePin(
        { body: { origin: 'beta.example', direction: 'sideways' } },
        res,
      )
      expect(res.statuses).toEqual([400])
    })
  })

  describe('peer lifecycle (04 §5)', () => {
    function pendingPeer(origin) {
      const d = { origin, status: 'pending', direction: 'both', save: vi.fn() }
      globalThis.__PEERS = { [origin]: d }
      return d
    }

    it('approve pending → approved + provider memo reset + audit', async () => {
      const d = pendingPeer('beta.example')
      const res = mkRes()
      await Mod.handleApprove({ params: { origin: 'beta.example' } }, res)
      expect(d.save).toHaveBeenCalled()
      expect(d.status).toBe('approved')
      expect(d.approvedAt).toBeInstanceOf(Date)
      expect(_resetForTest).toHaveBeenCalled()
      expect(res.jsonCalls[0].status).toBe('approved')
    })

    it('approve non-pending → 409 peer-not-pending', async () => {
      globalThis.__PEERS = {
        'beta.example': {
          origin: 'beta.example',
          status: 'approved',
          approvedAt: new Date(),
          save: vi.fn(),
        },
      }
      const res = mkRes()
      await Mod.handleApprove({ params: { origin: 'beta.example' } }, res)
      expect(res.statuses).toEqual([409])
      expect(res.jsonCalls[0].code).toBe('peer-not-pending')
    })

    it('approve unknown → 404', async () => {
      const res = mkRes()
      await Mod.handleApprove({ params: { origin: 'nobody.example' } }, res)
      expect(res.statuses).toEqual([404])
    })

    it('deny pending → delete row + 204', async () => {
      pendingPeer('beta.example')
      const res = mkRes()
      await Mod.handleDeny({ params: { origin: 'beta.example' } }, res)
      expect(FederationPeer.deleteOne).toHaveBeenCalledWith({ origin: 'beta.example' })
      expect(res.statuses).toEqual([204])
    })

    it('deny non-pending → 409', async () => {
      globalThis.__PEERS = {
        'beta.example': {
          origin: 'beta.example',
          status: 'approved',
          approvedAt: new Date(),
          save: vi.fn(),
        },
      }
      const res = mkRes()
      await Mod.handleDeny({ params: { origin: 'beta.example' } }, res)
      expect(res.statuses).toEqual([409])
    })

    it('revoke: local immediate + outbound S2S (best-effort) → peer-notified', async () => {
      const d = {
        origin: 'beta.example',
        status: 'approved',
        approvedAt: new Date(),
        save: vi.fn(),
      }
      globalThis.__PEERS = { 'beta.example': d }
      globalThis.fetch = vi.fn(async (url) => {
        expect(url).toBe('https://beta.example/federation/s2s')
        return { ok: true, status: 200 }
      })
      const res = mkRes()
      await Mod.handleRevoke({ params: { origin: 'beta.example' } }, res)
      expect(d.save).toHaveBeenCalled()
      expect(res.jsonCalls[0]).toMatchObject({
        origin: 'beta.example',
        status: 'revoked',
        revocation: 'peer-notified',
      })
      expect(globalThis.fetch).toHaveBeenCalledTimes(1)
      expect(
        auditCalls().filter((c) => c[0].operation === 'federation_peer_revoked'),
      ).toHaveLength(1)
    })

    it('revoke already-revoked → idempotent 200, no double audit, no second S2S', async () => {
      const d = {
        origin: 'beta.example',
        status: 'revoked',
        approvedAt: new Date(),
        save: vi.fn(),
      }
      globalThis.__PEERS = { 'beta.example': d }
      globalThis.fetch = vi.fn()
      const res = mkRes()
      await Mod.handleRevoke({ params: { origin: 'beta.example' } }, res)
      expect(res.statuses).toEqual([])
      expect(res.jsonCalls[0].revocation).toBe('peer-notified')
      expect(globalThis.fetch).not.toHaveBeenCalled()
      expect(
        auditCalls().filter((c) => c[0].operation === 'federation_peer_revoked'),
      ).toHaveLength(0)
    })

    it('revoke: outbound S2S failure → still local 200, revocation local-only', async () => {
      const d = {
        origin: 'beta.example',
        status: 'approved',
        approvedAt: new Date(),
        save: vi.fn(),
      }
      globalThis.__PEERS = { 'beta.example': d }
      globalThis.fetch = vi.fn(async () => {
        throw new Error('dns lookup failed')
      })
      const res = mkRes()
      await Mod.handleRevoke({ params: { origin: 'beta.example' } }, res)
      expect(res.statuses).toEqual([])
      // outbound S2S never blocks the admin action: local revoke is still
      // 200, revocation downgrades to 'local-only'.
      expect(res.jsonCalls[0].revocation).toBe('local-only')
    })
  })

  describe('keys (02 §5)', () => {
    it('rotate federation → publish + activate + audit', async () => {
      const res = mkRes()
      await Mod.handleRotate({ body: { purpose: 'federation' } }, res)
      expect(globalThis.__KEY_PROVIDER.publishKey).toHaveBeenCalledTimes(1)
      const { kid } = res.jsonCalls[0]
      expect(typeof kid).toBe('string')
      expect(kid.length).toBeGreaterThan(0)
      expect(globalThis.__KEY_PROVIDER.switchActiveKey.mock.calls[0][0]).toBe(kid)
      expect(
        auditCalls().filter((c) => c[0].operation === 'federation_key_rotated'),
      ).toHaveLength(1)
      expect(auditCalls().at(-1)[0].meta).toMatchObject({
        kid,
        reason: 'admin-rotate',
      })
    })

    it('rotate oidc → 501 (v9 cannot hot-swap jwks, 05 §8.6)', async () => {
      const res = mkRes()
      await Mod.handleRotate({ body: { purpose: 'oidc' } }, res)
      expect(res.statuses).toEqual([501])
    })

    it('invalid purpose → 400', async () => {
      const res = mkRes()
      await Mod.handleRotate({ body: { purpose: 'saml' } }, res)
      expect(res.statuses).toEqual([400])
    })

    it('listKeys → metadata only, no JWK bodies', async () => {
      globalThis.__KEY_LIST = [
        {
          purpose: 'federation',
          kid: 'kid-1',
          state: 'active',
          algorithm: 'ES256',
          publishedAt: new Date(),
          stateChangedAt: new Date(),
          expiresAt: null,
          anchorJwks: '{"secret":"must-not-leak"}',
        },
      ]
      const res = mkRes()
      await Mod.listKeys({}, res)
      expect(res.jsonCalls[0].keys[0]).toMatchObject({
        purpose: 'federation',
        kid: 'kid-1',
        state: 'active',
      })
      expect(JSON.stringify(res.jsonCalls[0])).not.toContain('anchorJwks')
    })
  })

  describe('audit list (04 §8)', () => {
    it('limit clamped + entries mapped', async () => {
      globalThis.__AUDIT_ROWS = [
        { _id: '1', operation: 'federation_invitee_denied', timestamp: new Date() },
        { _id: '2', operation: 'federation_peer_registered', timestamp: new Date() },
      ]
      const res = mkRes()
      await Mod.auditList({ query: { limit: '1' } }, res)
      expect(res.jsonCalls[0].entries).toHaveLength(1)
      expect(res.jsonCalls[0].entries[0]).toMatchObject({
        operation: 'federation_invitee_denied',
      })
    })
  })
})
