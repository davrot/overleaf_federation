// git-bridge auth middleware — content-bridge 2c read-only guard (plan 09:
// "one scope-prefix check in the receive-pack auth path").
//
// Both git directions authenticate with the raw PAT into web's REST
// endpoints: fetch (upload-pack) hits the `read` mounts; push
// (receive-pack → snapshot postback) hits
// POST /api/v0/docs/:project_id/snapshots under `write`. 2c: a token
// minted with scope `federation:git_bridge` (a 2a export PAT) is REFUSED
// on the write path (403, before any permission oracle) and still ALLOWED
// on the read path (fetch = the content path). Normal `git_bridge`-scoped
// PATs are unaffected.
//
// Mocked (thunk + call-log pattern — test/unit/bootstrap.mjs runs
// `vi.resetAllMocks()` after every test, so plain `globalThis`-backed
// functions are used here, NOT vi.fn; see federation test conventions):
//   - git-bridge PAT manager: raw token → { userId, scope } | null
//   - AuthorizationManager: permission oracle → records calls to a log
import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../../app/src/GitBridgePATManager.mjs', () => ({
  default: {
    getUserIdAndScope: async (token) => {
      const entry = (globalThis.__TOKENS ?? {})[token]
      return entry ? { userId: entry.userId, scope: entry.scope } : null
    },
    getUserId: async (token) => {
      const entry = (globalThis.__TOKENS ?? {})[token]
      return entry ? entry.userId : null
    },
  },
}))

vi.mock(
  '../../../../app/src/Features/Authorization/AuthorizationManager.mjs',
  () => ({
    default: {
      promises: {
        canUserReadProject: async (...args) => {
          ;(globalThis.__READ_CALLS ??= []).push(args)
          return globalThis.__READ_ALLOWED
        },
        canUserWriteProjectContent: async (...args) => {
          ;(globalThis.__WRITE_CALLS ??= []).push(args)
          return globalThis.__WRITE_ALLOWED
        },
      },
    },
  }),
)

import ensureTokenProjectAccess from '../../app/src/GitBridgeAuthMiddleware.mjs'

function makeRes() {
  return {
    statuses: [],
    sendStatus(code) {
      this.statuses.push(code)
      return this
    },
  }
}

describe('GitBridgeAuthMiddleware 2c read-only guard', () => {
  beforeEach(() => {
    globalThis.__TOKENS = {
      olp_normal: { userId: 'u-normal', scope: 'git_bridge' },
      olp_export: { userId: 'u-owned', scope: 'federation:git_bridge' },
    }
    globalThis.__READ_CALLS = []
    globalThis.__WRITE_CALLS = []
    globalThis.__READ_ALLOWED = true
    globalThis.__WRITE_ALLOWED = true
  })

  it('write + federation:-scoped token → 403, permission oracle NOT consulted', async () => {
    const mw = ensureTokenProjectAccess('write')
    const res = makeRes()
    const req = {
      params: { project_id: 'P1' },
      headers: { authorization: 'Bearer olp_export' },
    }
    let nextCalled = false
    await mw(req, res, () => { nextCalled = true })
    expect(res.statuses).toEqual([403])
    expect(nextCalled).toBe(false)
    // The guard fires at the scope marker: a project write-allow would NOT
    // save an export PAT (the write oracle is never consulted).
    expect(globalThis.__WRITE_CALLS).toHaveLength(0)
    expect(globalThis.__READ_CALLS).toHaveLength(0)
  })

  it('read + federation:-scoped token → ALLOWED (fetch = the content path)', async () => {
    const mw = ensureTokenProjectAccess('read')
    const res = makeRes()
    const req = {
      params: { project_id: 'P1' },
      headers: { authorization: 'Bearer olp_export' },
    }
    await mw(req, res, () => {})
    expect(res.statuses).toEqual([])
    expect(globalThis.__WRITE_CALLS).toHaveLength(0)
    // The read oracle is consulted (fetch is the content path for a
    // federation-EXPORT token — it can still fetch).
    expect(globalThis.__READ_CALLS).toEqual([['u-owned', 'P1', null]])
  })

  it('write + normal-scope token → permission oracle applied (unchanged)', async () => {
    const mw = ensureTokenProjectAccess('write')
    const res = makeRes()
    const req = {
      params: { project_id: 'P1' },
      headers: { authorization: 'Bearer olp_normal' },
    }
    let nextUserId = null
    await mw(req, res, () => { nextUserId = req.user_id })
    expect(res.statuses).toEqual([])
    expect(nextUserId).toBe('u-normal')
    expect(globalThis.__WRITE_CALLS).toEqual([['u-normal', 'P1', null]])
    expect(globalThis.__READ_CALLS).toHaveLength(0)
  })

  it('write + normal-scope token + no access → 403 via the oracle', async () => {
    globalThis.__WRITE_ALLOWED = false
    const mw = ensureTokenProjectAccess('write')
    const res = makeRes()
    const req = {
      params: { project_id: 'P1' },
      headers: { authorization: 'Bearer olp_normal' },
    }
    let nextCalled = false
    await mw(req, res, () => { nextCalled = true })
    expect(res.statuses).toEqual([403])
    expect(nextCalled).toBe(false)
    expect(globalThis.__WRITE_CALLS).toHaveLength(1)
  })

  it('write + unknown token → 401 (invalid/expired)', async () => {
    const mw = ensureTokenProjectAccess('write')
    const res = makeRes()
    const req = {
      params: { project_id: 'P1' },
      headers: { authorization: 'Bearer olp_unknown' },
    }
    await mw(req, res, () => {})
    expect(res.statuses).toEqual([401])
    expect(globalThis.__WRITE_CALLS).toHaveLength(0)
    expect(globalThis.__READ_CALLS).toHaveLength(0)
  })

  it('read + unknown token → 401', async () => {
    const mw = ensureTokenProjectAccess('read')
    const res = makeRes()
    const req = {
      params: { project_id: 'P1' },
      headers: { authorization: 'Bearer olp_unknown' },
    }
    await mw(req, res, () => {})
    expect(res.statuses).toEqual([401])
    expect(globalThis.__READ_CALLS).toHaveLength(0)
  })
})
