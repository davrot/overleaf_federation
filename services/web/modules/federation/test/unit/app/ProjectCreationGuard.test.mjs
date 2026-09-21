// Partner-side project-creation gate (01 §3.4, 05 §7
// `allowFederatedProjectCreate`, default OFF).
//
// Real: the guard function (pure middleware) + a fake express router
// (to prove the idempotent mount). Mocks: Settings (flag toggling).
//
// Matrix (05 §7 `allowFederatedProjectCreate: false` default):
//   flag OFF (default)
//     mirror user (federation subdoc present)   → 403 federated-project-create-disabled
//     local user                                → next()
//     no session                                → next()
//   flag ON
//     mirror user                               → next()
//   mount
//     apply x3 (router.mjs applyRouter call
//     sites) → exactly one `POST /project/new`
//     registration on the router.

import { vi, describe, it, expect, beforeEach } from 'vitest'

vi.mock('@overleaf/settings', () => ({
  default: {
    siteUrl: 'https://alpha.example',
    security: { sessionSecret: 'unit-test-secret' },
    get federation() {
      return (
        globalThis.__FED_SETTINGS ?? {
          enabled: true,
          allowFederatedProjectCreate: false,
        }
      )
    },
  },
}))

vi.mock('@overleaf/logger', () => ({
  default: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
}))

import mountGuard, {
  guardProjectCreation,
  _resetGuardForTest,
} from '../../../app/ProjectCreationGuard.mjs'

describe('ProjectCreationGuard (01 §3.4, 05 §7)', () => {
  beforeEach(() => {
    globalThis.__FED_SETTINGS = {
      enabled: true,
      allowFederatedProjectCreate: false,
    }
    _resetGuardForTest()
  })

  function mkRes() {
    return {
      statuses: [],
      jsonCalls: [],
      status: function (code) {
        this.statuses.push(code)
        return this
      },
      json: function (d) {
        this.jsonCalls.push(d)
        return this
      },
    }
  }

  describe('guardProjectCreation (the gate)', () => {
    it('flag OFF + mirror user → 403 federated-project-create-disabled', async () => {
      const res = mkRes()
      const next = vi.fn()
      const req = {
        session: {
          user: {
            _id: 'u1',
            email: '',
            hashedPassword: undefined,
            federation: {
              origin: 'home.example',
              localName: 'bla@example.com',
              federatedAt: new Date(),
            },
          },
        },
      }
      await guardProjectCreation(req, res, next)
      expect(res.statuses).toEqual([403])
      expect(res.jsonCalls[0]).toMatchObject({
        error: expect.any(String),
        code: 'federated-project-create-disabled',
      })
      // Not forwarded (the refusal short-circuits).
      expect(next).not.toHaveBeenCalled()
    })

    it('flag OFF + local user → next()', async () => {
      const res = mkRes()
      const next = vi.fn()
      const req = {
        session: {
          user: {
            _id: 'u2',
            first_name: 'Local',
            email: 'local@example.com',
          },
        },
      }
      await guardProjectCreation(req, res, next)
      expect(next).toHaveBeenCalled()
      expect(res.statuses).toEqual([])
      expect(res.jsonCalls).toHaveLength(0)
    })

    it('flag OFF + no session → next() (requireLogin is downstream)', async () => {
      const res = mkRes()
      const next = vi.fn()
      await guardProjectCreation({ session: {} }, res, next)
      expect(next).toHaveBeenCalled()
      expect(res.statuses).toEqual([])
    })

    it('flag OFF + req.session null (session middleware blew up) → next()', async () => {
      const res = mkRes()
      const next = vi.fn()
      // `req.session` undefined is what express shows before the session
      // middleware ran; getSessionUser(undefined) → null, isMirror(null)
      // → false → next().
      await guardProjectCreation(
        { session: undefined },
        res,
        next,
      )
      expect(next).toHaveBeenCalled()
      expect(res.statuses).toEqual([])
    })

    it('flag ON + mirror user → next() (no refusal, 05 §7 default-ON semantics)', async () => {
      globalThis.__FED_SETTINGS = {
        enabled: true,
        allowFederatedProjectCreate: true,
      }
      const res = mkRes()
      const next = vi.fn()
      const req = {
        session: {
          user: {
            federation: { origin: 'home.example', localName: 'bla@x' },
          },
        },
      }
      await guardProjectCreation(req, res, next)
      expect(next).toHaveBeenCalled()
      expect(res.statuses).toEqual([])
    })

    it('Settings.federation undefined entirely → treated as OFF (flag default 05 §7)', async () => {
      const res = mkRes()
      const next = vi.fn()
      const req = {
        session: {
          user: {
            federation: { origin: 'home.example' },
          },
        },
      }
      // No fallback: `Settings.federation` undefined → flag undefined
      // → false branch → mirror refusal.
      globalThis.__FED_SETTINGS = undefined
      await guardProjectCreation(req, res, next)
      expect(res.statuses).toEqual([403])
      expect(res.jsonCalls[0].code).toBe('federated-project-create-disabled')
    })

    it('federation subdoc without origin → NOT a mirror (defensive: no false refusal)', async () => {
      const res = mkRes()
      const next = vi.fn()
      const req = {
        session: {
          user: {
            // federation subdoc present but origin missing —
            // not a valid mirror mark in production (always set by
            // the grant path, 04 §1); the guard treats it as local.
            federation: {},
          },
        },
      }
      await guardProjectCreation(req, res, next)
      expect(next).toHaveBeenCalled()
      expect(res.statuses).toEqual([])
    })
  })

  describe('idempotent apply (Modules.applyRouter x3, router.mjs 239/286/312)', () => {
    function fakeRouter() {
      const mounted = []
      return {
        post: (path, handler) => mounted.push({ path, handler }),
        mounted,
      }
    }

    it('calling apply 3x → exactly one POST /project/new registration', () => {
      const r = fakeRouter()
      mountGuard(r)
      mountGuard(r)
      mountGuard(r)
      expect(r.mounted).toHaveLength(1)
      expect(r.mounted[0].path).toBe('/project/new')
    })

    it('_resetGuardForTest resets the mount flag', () => {
      const r1 = fakeRouter()
      mountGuard(r1)
      _resetGuardForTest()
      const r2 = fakeRouter()
      mountGuard(r2)
      expect(r1.mounted).toHaveLength(1)
      expect(r2.mounted).toHaveLength(1)
    })
  })
})
