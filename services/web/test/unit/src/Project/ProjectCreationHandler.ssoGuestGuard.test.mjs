import path from 'node:path'
import { describe, it, expect, beforeEach, vi } from 'vitest'

// P1c (plan 10 §0.8) — the "guest cannot create own project" choke.
//
// ProjectCreationHandler._createBlankProject is the single convergence point for
// every "make a project of your own" path (UI newProject, Duplicate, Upload, TPDS).
// When the user's SSO role (attrFilter-evaluated at login, persisted on
// user.ssoRoles[id] keying on ssoLoginProviderId) is `guest`/`blocked`, the choke
// refuses with ForbiddenError (HTTP 403) BEFORE any project/history/metric side
// effect.
//
// The decision core (evaluateAttrFilter / sanitizeAttrFilter /
// persistedRoleForProvider) is covered 100% by ssoRoleEvaluator.test.mjs. This
// test runs the REAL handler guard (real Errors, real persistedRoleForProvider)
// with the handler's heavy model/manager imports mocked, so the wiring is proven,
// not just asserted.
//
// `infrastructure/mongodb` (which connect()s at module scope) is avoided by
// mocking every model/manager import the handler pulls in at load time.
//
// Assertion note: `Errors.js` is CJS — a class-identity check across the CJS/ESM
// boundary is unreliable, so refusals are asserted structurally
// (name === 'ForbiddenError', message === 'project-creation-denied',
// info.ssoGuestCreateDenied && info.ssoRole). That is the exact wire shape the
// ErrorController maps to 403 (Errors.ForbiddenError → res.sendStatus(403)).

const HANDLER_PATH = path.join(
  import.meta.dirname,
  '../../../../app/src/Features/Project/ProjectCreationHandler.mjs'
)

describe('ProjectCreationHandler SSO guest-creation guard (P1c)', () => {
  let ProjectCreationHandler

  beforeEach(async function () {
    vi.doMock('../../../../app/src/infrastructure/Features.mjs', () => ({
      default: { hasFeature: () => false },
    }))
    vi.doMock('@overleaf/settings', () => ({ default: {} }))
    vi.doMock('@overleaf/metrics', () => ({
      default: { inc() {}, observe() {} },
    }))
    vi.doMock('@overleaf/logger', () => ({
      default: { info() {}, warn() {}, error() {}, debug() {} },
    }))
    vi.doMock('../../../../app/src/models/User.mjs', () => ({
      User: {
        findById: () => ({ exec: async () => globalThis.__ssoUserDoc ?? null }),
      },
    }))
    vi.doMock('../../../../app/src/models/Project.mjs', () => ({ Project: {} }))
    vi.doMock('../../../../app/src/models/Folder.mjs', () => ({ Folder: {} }))
    vi.doMock('../../../../app/src/models/UserAuditLogEntry.mjs', () => ({
      UserAuditLogEntry: { create: async () => {} },
    }))
    vi.doMock('../../../../app/src/Features/User/UserAuditLogHandler.mjs', () => ({
      default: {
        addEntryInBackground: () => null,
        promises: { addEntry: async () => {} },
      },
    }))
    vi.doMock(
      '../../../../app/src/Features/Project/ProjectEntityUpdateHandler.mjs',
      () => ({ default: {} })
    )
    vi.doMock(
      '../../../../app/src/Features/Project/ProjectDetailsHandler.mjs',
      () => ({ default: {} })
    )
    vi.doMock(
      '../../../../app/src/Features/History/HistoryManager.mjs',
      () => ({ default: {} })
    )
    vi.doMock(
      '../../../../app/src/Features/Analytics/AnalyticsManager.mjs',
      () => ({ default: { recordEventForUserInBackground: () => {} } })
    )
    vi.doMock(
      '../../../../app/src/Features/ThirdPartyDataStore/TpdsUpdateSender.mjs',
      () => ({ default: {} })
    )
    vi.doMock(
      '../../../../app/src/Features/SplitTests/SplitTestHandler.mjs',
      () => ({ default: {} })
    )
    vi.doMock(
      '../../../../app/src/Features/SplitTests/SplitTestUserGetter.mjs',
      () => ({ default: {} })
    )
    vi.doMock(
      '../../../../app/src/Features/Compile/ClsiCacheManager.mjs',
      () => ({ default: {} })
    )

    const mod = await import(HANDLER_PATH)
    ProjectCreationHandler = mod.default
  })

  it('refuses a guest-SSO owner: ForbiddenError, ssoRole=guest, before creation', async () => {
    globalThis.__ssoUserDoc = {
      _id: '111111111111111111111111',
      ssoRoles: { p1: { role: 'guest' } },
      ssoLoginProviderId: 'p1',
    }
    let err
    try {
      await ProjectCreationHandler.promises.createBlankProject(
        '111111111111111111111111',
        'New Project',
        {}
      )
    } catch (e) {
      err = e
    }
    expect(err).toBeDefined()
    expect(err.name).toBe('ForbiddenError')
    expect(err.message).toBe('project-creation-denied')
    expect(err.info?.ssoGuestCreateDenied).toBe(true)
    expect(err.info?.ssoRole).toBe('guest')
  })

  it('refuses a blocked-SSO owner: ForbiddenError, ssoRole=blocked', async () => {
    globalThis.__ssoUserDoc = {
      _id: '222222222222222222222222',
      ssoRoles: { p1: { role: 'blocked' } },
      ssoLoginProviderId: 'p1',
    }
    let err
    try {
      await ProjectCreationHandler.promises.createBlankProject(
        '222222222222222222222222',
        'New Project',
        {}
      )
    } catch (e) {
      err = e
    }
    expect(err?.name).toBe('ForbiddenError')
    expect(err?.info?.ssoRole).toBe('blocked')
  })

  it('treats a password-login user (cleared ssoLoginProviderId) as local', async () => {
    globalThis.__ssoUserDoc = {
      _id: '333333333333333333333333',
      ssoRoles: { p1: { role: 'guest' } },
      ssoLoginProviderId: undefined, // password-login clears the marker
    }
    let err
    try {
      await ProjectCreationHandler.promises.createBlankProject(
        '333333333333333333333333',
        'New Project',
        {}
      )
    } catch (e) {
      // Past the guard the mocked-out creation throws (empty Project mock);
      // any error here must NOT be the ForbiddenError guest refusal.
      err = e
    }
    expect(err?.name).not.toBe('ForbiddenError')
  })

  it('treats a no-SSO (local) user as local: guard does not refuse', async () => {
    globalThis.__ssoUserDoc = {
      _id: '444444444444444444444444',
    }
    let err
    try {
      await ProjectCreationHandler.promises.createBlankProject(
        '444444444444444444444444',
        'New Project',
        {}
      )
    } catch (e) {
      err = e
    }
    // Same as above: must get past the guard (no ForbiddenError).
    expect(err?.name).not.toBe('ForbiddenError')
  })

  it('a guest row for a DIFFERENT provider does not refuse (keyed on ssoLoginProviderId)', async () => {
    globalThis.__ssoUserDoc = {
      _id: '555555555555555555555555',
      ssoRoles: { p1: { role: 'guest' }, p2: { role: 'local' } },
      ssoLoginProviderId: 'p2',
    }
    let err
    try {
      await ProjectCreationHandler.promises.createBlankProject(
        '555555555555555555555555',
        'New Project',
        {}
      )
    } catch (e) {
      err = e
    }
    expect(err?.name).not.toBe('ForbiddenError')
  })
})
