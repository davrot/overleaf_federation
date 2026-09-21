// Federation admin dashboard + wizard controller unit tests (0fa0f9f3).
//
// Real: nothing (pure view + probe layer).
// Mocks: Settings, logger, FederationPeer/FederationKey models,
// ProjectAuditLogEntry model, globalThis.fetch (the leaf loopback probe).

import { vi, describe, it, expect, beforeEach } from 'vitest'

vi.mock('@overleaf/settings', () => ({
  default: {
    siteName: 'alpha.example',
    siteUrl: 'https://alpha.example',
    get federation() {
      return (
        globalThis.__FED_SETTINGS ??
        { enabled: true, requireAdminApproval: true, allowFederatedProjectCreate: true }
      )
    },
  },
}))

vi.mock('@overleaf/logger', () => ({
  default: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
}))

vi.mock('../../../app/models/FederationPeer.mjs', () => ({
  FederationPeer: {
    find: () => ({
      sort: () => ({
        limit: () => ({
          lean: () => Promise.resolve(globalThis.__PEERS ?? []),
        }),
      }),
    }),
  },
}))

vi.mock('../../../app/models/FederationKey.mjs', () => ({
  FederationKey: {
    find: () => ({
      sort: () => ({
        limit: () => ({
          lean: () => Promise.resolve(globalThis.__KEYS ?? []),
        }),
      }),
    }),
  },
}))

vi.mock('../../../../../app/src/models/ProjectAuditLogEntry.mjs', () => ({
  ProjectAuditLogEntry: {
    find: () => ({
      sort: () => ({
        limit: () => ({
          lean: () => Promise.resolve(globalThis.__AUDIT_ROWS ?? []),
        }),
      }),
    }),
  },
}))

import FederationWizardController, {
  getFederationWizardStatus,
} from '../../../admin/FederationWizardController.mjs'

describe('FederationWizardController', () => {
  beforeEach(() => {
    globalThis.__FED_SETTINGS = {
      enabled: true,
      requireAdminApproval: true,
      allowFederatedProjectCreate: true,
    }
    globalThis.__PEERS = []
    globalThis.__KEYS = []
    globalThis.__AUDIT_ROWS = []
    globalThis.fetch = vi.fn(async () => {
      throw new Error('leaf fetch blocked')
    })
  })

  it('step 1: module disabled → first step not done', async () => {
    globalThis.__FED_SETTINGS = { enabled: false }
    const status = await getFederationWizardStatus()
    expect(status.steps[0].name).toBe('module-enabled')
    expect(status.steps[0].done).toBe(false)
    expect(status.ok).toBe(false)
  })

  it('step 2: no active federation key → identity-key not done', async () => {
    globalThis.__KEYS = []
    const status = await getFederationWizardStatus()
    const step = status.steps.find(s => s.name === 'identity-key')
    expect(step.done).toBe(false)
  })

  it('step 2: active key present → identity-key done', async () => {
    globalThis.__KEYS = [{ kid: 'active-kid' }]
    const status = await getFederationWizardStatus()
    const step = status.steps.find(s => s.name === 'identity-key')
    expect(step.done).toBe(true)
    expect(step.detail).toContain('active-kid')
  })

  it('step 3: no approved peer → first-peer-approved not done', async () => {
    globalThis.__PEERS = []
    const status = await getFederationWizardStatus()
    const step = status.steps.find(s => s.name === 'first-peer-approved')
    expect(step.done).toBe(false)
  })

  it('step 3: approved peer → first-peer-approved done (detail names origin)', async () => {
    globalThis.__PEERS = [{ origin: 'https://beta.example' }]
    const status = await getFederationWizardStatus()
    const step = status.steps.find(s => s.name === 'first-peer-approved')
    expect(step.done).toBe(true)
    expect(step.detail).toContain('beta.example')
  })

  it('step 4: leaf probe HTTP 500 → leaf-published not done', async () => {
    globalThis.fetch = vi.fn(async () => ({ status: 500 }))
    const status = await getFederationWizardStatus()
    const step = status.steps.find(s => s.name === 'leaf-published')
    expect(step.done).toBe(false)
  })

  it('step 4: leaf probe 200 + three-part EC → leaf-published done', async () => {
    globalThis.fetch = vi.fn(async () => ({
      status: 200,
      text: async () => 'eyJhbGciOiJFUzI1NiJ9.eyJleGNoYW5naSI6MS59.c2ln',
    }))
    const status = await getFederationWizardStatus()
    const step = status.steps.find(s => s.name === 'leaf-published')
    expect(step.done).toBe(true)
  })

  it('step 4: fetch throws (DNS / port closed) → leaf-published not done, detail names cause', async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new Error('fetch failed')
    })
    const status = await getFederationWizardStatus()
    const step = status.steps.find(s => s.name === 'leaf-published')
    expect(step.done).toBe(false)
    expect(step.detail).not.toBe('')
  })

  it('step 5: no audit rows → s2s-proven not done', async () => {
    globalThis.__AUDIT_ROWS = []
    const status = await getFederationWizardStatus()
    const step = status.steps.find(s => s.name === 's2s-proven')
    expect(step.done).toBe(false)
  })

  it('step 5: recent federation audit row → s2s-proven done', async () => {
    globalThis.__AUDIT_ROWS = [{
      operation: 'federation_peer_approved',
      timestamp: new Date(),
    }]
    const status = await getFederationWizardStatus()
    const step = status.steps.find(s => s.name === 's2s-proven')
    expect(step.done).toBe(true)
  })

  it('all green (enabled + key + peer + leaf + audit) → ok true', async () => {
    globalThis.__KEYS = [{ kid: 'k1' }]
    globalThis.__PEERS = [{ origin: 'beta.example' }]
    globalThis.__AUDIT_ROWS = [{
      operation: 'federation_peer_approved',
      timestamp: new Date(),
    }]
    globalThis.fetch = vi.fn(async () => ({
      status: 200,
      text: async () => 'a.b.c',
    }))
    const status = await getFederationWizardStatus()
    expect(status.ok).toBe(true)
    expect(status.steps).toHaveLength(5)
  })

  it('returns effective-settings view (defaults) with s2s fetch timeout', async () => {
    globalThis.fetch = vi.fn(async () => ({
      status: 200,
      text: async () => 'a.b.c',
    }))
    const status = await getFederationWizardStatus()
    expect(status.settings).toEqual({
      enabled: true,
      requireAdminApproval: true,
      allowFederatedProjectCreate: true,
      keyRotationGraceDays: 14,
      s2sFetchTimeoutMs: 10_000,
    })
  })
})

describe('federationAdminPage (GET /admin/federation)', () => {
  it('renders the federation view with title + settings', async () => {
    const render = vi.fn()
    const res = { render, locals: { csrfToken: 'tok-123' } }
    FederationWizardController.federationAdminPage({}, res)
    expect(render).toHaveBeenCalled()
    const args = render.mock.calls[0]
    expect(String(args[0])).toContain('/app/views/federation')
    expect(args[1].title).toBe('Federation')
    expect(args[1].csrfToken).toBe('tok-123')
    expect(args[1].settings.enabled).toBe(true)
  })
})

describe('federationWizard (GET /admin/federation/wizard)', () => {
  it('res.json: 5 steps, ok flag, settings', async () => {
    globalThis.fetch = vi.fn(async () => ({
      status: 200,
      text: async () => 'a.b.c',
    }))
    globalThis.__KEYS = [{ kid: 'k1' }]
    globalThis.__PEERS = [{ origin: 'beta.example' }]
    globalThis.__AUDIT_ROWS = [{
      operation: 'federation_peer_approved',
      timestamp: new Date(),
    }]
    const res = { json: vi.fn() }
    const next = vi.fn()
    await new Promise(resolve =>
      setTimeout(async () => {
        await FederationWizardController.federationWizard({}, res, next)
        resolve()
      }, 0)
    )
    expect(res.json).toHaveBeenCalled()
    expect(next).not.toHaveBeenCalled()
    const payload = res.json.mock.calls[0][0]
    expect(payload.ok).toBe(true)
    expect(payload.steps).toHaveLength(5)
    expect(payload.settings).toEqual(expect.objectContaining({
      s2sFetchTimeoutMs: 10_000,
    }))
  })
})
