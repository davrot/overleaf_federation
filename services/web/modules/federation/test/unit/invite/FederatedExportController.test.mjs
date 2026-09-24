// 2b: A-side federated export wizard controller (plan 09 §4.1).
//
// Thunk-backed unit: FederationPeer.find, callPeer, audit. The
// wizard is a thin proxy (B is authority) with the PAT rendered into
// the result view only (LOCKED Q2): this test pins (a) wire shape
// (callPeer 'export-project' { projectId, expiresAt }), (b) audit
// rows (requested/denied, meta allow-list, NEVER the PAT value,
// 04 §8), (c) TTL clamp (form seconds → wire unix-seconds), (d)
// refusal paths (peer gate 403 / local 400 / wire 502 / business
// 403).

import { vi, describe, it, expect, beforeEach } from 'vitest'

vi.mock('@overleaf/settings', () => ({
  default: {
    siteName: 'Home A',
    federation: {
      enabled: true,
      export: {
        enabled: false, // A-side does not need B's gate (2a decision §1)
        maxExportTtlSeconds: 86400,
      },
    },
  },
}))

vi.mock('@overleaf/logger', () => ({
  default: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
}))

vi.mock('../../../app/models/FederationPeer.mjs', () => ({
  FederationPeer: {
    find: (filter) => {
      globalThis.__FED_PEER_FILTER = filter
      return {
        sort: () =>
          Promise.resolve(
            (globalThis.__EXPORT_PEERS ?? []).map(p => ({
              origin: p.origin,
              displayName: p.displayName,
            })),
          ),
      }
    },
  },
}))

vi.mock('../../../invite/FederatedInviteController.mjs', () => ({
  callPeer: (origin, action, payload) => {
    globalThis.__CALL_PEER_CALLS.push({ origin, action, payload })
    const r = globalThis.__CALL_PEER_RESULT
    if (r instanceof Error) return Promise.reject(r)
    return Promise.resolve(r)
  },
}))

vi.mock('../../../util/Audit.mjs', () => ({
  audit: (args) => {
    globalThis.__AUDIT_CALLS.push(args)
    return Promise.resolve({ ok: true })
  },
  AUDIT_TYPES: {
    exportRequested: 'federation_export_requested',
    exportDenied: 'federation_export_denied',
  },
}))

import {
  handleExportFormGet,
  handleExport,
} from '../../../invite/FederatedExportController.mjs'

const PEER = { origin: 'b.example', displayName: 'B' }
const PAT = 'olp_SECRET12345'
const GIT_URL = 'https://b.example.git/gw/git/pid123'

function makeRes() {
  const res = {
    statusCode: 200,
    rendered: [],
    locals: { csrfToken: 'CT-42' },
    status(code) {
      res.statusCode = code
      return res
    },
    async render(view, locals) {
      res.rendered.push({ view, locals })
      return 'HTML'
    },
  }
  return res
}

beforeEach(() => {
  delete globalThis.__EXPORT_PEERS
  delete globalThis.__FED_PEER_FILTER
  globalThis.__CALL_PEER_CALLS = []
  globalThis.__CALL_PEER_RESULT = {
    ok: true,
    payload: { git_url: GIT_URL, pat: PAT, expires_at: Math.floor(Date.now() / 1000) + 3600 },
  }
  globalThis.__AUDIT_CALLS = []
})

describe('handleExportFormGet', () => {
  it('renders the wizard form with approved outbound peers (thunk)', async () => {
    globalThis.__EXPORT_PEERS = [PEER]
    const res = makeRes()
    const req = { body: {}, query: {} }
    await handleExportFormGet(req, res)
    expect(res.rendered).toHaveLength(1)
    const { view, locals } = res.rendered[0]
    expect(view).toMatch(/federation-export\.pug$/)
    expect(locals.peers).toEqual([
      { origin: 'b.example', displayName: 'B' },
    ])
    expect(locals.csrfToken).toBe('CT-42')
    expect(locals.error).toBeUndefined()
    // Approved+outbound|both filter (the dropdown gate, Q1).
    expect(globalThis.__FED_PEER_FILTER).toEqual({
      status: 'approved',
      direction: { $in: ['outbound', 'both'] },
    })
  })

  it('renders an empty peer state (no approved outbound peers)', async () => {
    const res = makeRes()
    await handleExportFormGet({ body: {}, query: {} }, res)
    expect(res.rendered[0].locals.peers).toEqual([])
  })
})

describe('handleExport', () => {
  it('happy path: S2S wire + result view with PAT + audit without secret', async () => {
    globalThis.__EXPORT_PEERS = [PEER]
    const res = makeRes()
    const req = { body: { origin: 'b.example', projectId: 'pid123' }, query: {} }
    await handleExport(req, res)
    expect(res.statusCode).toBe(200)
    expect(res.rendered).toHaveLength(1)
    const { view, locals } = res.rendered[0]
    expect(view).toMatch(/federation-export-result\.pug$/)
    // Wire (03 §2): action + payload (B re-clamps expiresAt server-side).
    expect(globalThis.__CALL_PEER_CALLS).toHaveLength(1)
    const call = globalThis.__CALL_PEER_CALLS[0]
    expect(call.origin).toBe('b.example')
    expect(call.action).toBe('export-project')
    expect(call.payload.projectId).toBe('pid123')
    expect(typeof call.payload.expiresAt).toBe('number')
    const nowSec = Math.floor(Date.now() / 1000)
    expect(call.payload.expiresAt - nowSec).toBeLessThan(3610)
    expect(call.payload.expiresAt - nowSec).toBeGreaterThan(3590)
    // PAT rendered into the view (Q2: NOT a JSON body field).
    expect(locals.project.pat).toBe(PAT)
    expect(
      locals.project.cloneCommand,
    ).toBe(`git clone https://git:${PAT}@b.example.git/gw/git/pid123`)
    // Success audit (plan 09 §3.2: { gitUrl, expiry } — the PAT is not
    // a secret field).
    expect(globalThis.__AUDIT_CALLS).toHaveLength(1)
    const a = globalThis.__AUDIT_CALLS[0]
    expect(a.operation).toBe('federation_export_requested')
    expect(a.meta.origin).toBe('b.example')
    expect(a.meta.scope).toBe('federation:git_bridge')
    expect(a.meta.gitUrl).toBe(GIT_URL)
    expect(typeof a.meta.expiresAt).toBe('number')
    // (b) redaction regression: the PAT never enters the audit.
    expect(JSON.stringify(globalThis.__AUDIT_CALLS)).not.toContain(PAT)
  })

  it('clamps TTL: out-of-range form value → max cap (86400 s)', async () => {
    globalThis.__EXPORT_PEERS = [PEER]
    const res = makeRes()
    await handleExport(
      { body: { origin: 'b.example', projectId: 'pid123', expiresAt: '999999999' }, query: {} },
      res,
    )
    const call = globalThis.__CALL_PEER_CALLS[0]
    const nowSec = Math.floor(Date.now() / 1000)
    expect(call.payload.expiresAt - nowSec).toBeLessThan(86405)
    expect(call.payload.expiresAt - nowSec).toBeGreaterThan(86395)
  })

  it('falls back to the 3600 s default on a malformed TTL', async () => {
    globalThis.__EXPORT_PEERS = [PEER]
    const res = makeRes()
    await handleExport(
      { body: { origin: 'b.example', projectId: 'pid123', expiresAt: 'junk' }, query: {} },
      res,
    )
    expect(globalThis.__CALL_PEER_CALLS[0].payload.expiresAt - Math.floor(Date.now() / 1000)).toBe(
      3600,
    )
  })

  it('peer not in the approved outbound list → 403 form re-render, no wire', async () => {
    globalThis.__EXPORT_PEERS = [PEER]
    const res = makeRes()
    await handleExport(
      { body: { origin: 'evil.example', projectId: 'pid123' }, query: {} },
      res,
    )
    expect(res.statusCode).toBe(403)
    expect(globalThis.__CALL_PEER_CALLS).toHaveLength(0)
    expect(globalThis.__AUDIT_CALLS).toHaveLength(0)
    expect(res.rendered[0].locals.error).toMatch(/not approved/)
    expect(res.rendered[0].view).not.toMatch(/export-result/)
  })

  it('missing projectId → 400, no wire (local validation)', async () => {
    globalThis.__EXPORT_PEERS = [PEER]
    const res = makeRes()
    await handleExport(
      { body: { origin: 'b.example' }, query: {} },
      res,
    )
    expect(res.statusCode).toBe(400)
    expect(globalThis.__CALL_PEER_CALLS).toHaveLength(0)
    expect(globalThis.__AUDIT_CALLS).toHaveLength(0)
    expect(res.rendered[0].locals.error).toMatch(/project id/)
  })

  it('wire-level refusal (PeerRefusal) → 502 + denied audit (redacted)', async () => {
    globalThis.__EXPORT_PEERS = [PEER]
    const refusal = Object.assign(new Error('peer S2S returned 301 redirect'), {
      code: 'redirect-refused',
    })
    globalThis.__CALL_PEER_RESULT = refusal
    const res = makeRes()
    await handleExport(
      { body: { origin: 'b.example', projectId: 'pid123' }, query: {} },
      res,
    )
    expect(res.statusCode).toBe(502)
    expect(res.rendered[0].view).not.toMatch(/export-result/)
    expect(res.rendered[0].locals.error).toMatch(/redirect-refused/)
    expect(globalThis.__AUDIT_CALLS).toHaveLength(1)
    expect(globalThis.__AUDIT_CALLS[0].operation).toBe('federation_export_denied')
    expect(globalThis.__AUDIT_CALLS[0].meta.reason).toBe('redirect-refused')
    expect(JSON.stringify(globalThis.__AUDIT_CALLS)).not.toContain(PAT)
  })

  it('business refusal (ok:false export-no-consent) → 403 + denied audit', async () => {
    globalThis.__EXPORT_PEERS = [PEER]
    globalThis.__CALL_PEER_RESULT = {
      ok: false,
      code: 'export-no-consent',
      detail: 'no live consent grant',
    }
    const res = makeRes()
    await handleExport(
      { body: { origin: 'b.example', projectId: 'pid123' }, query: {} },
      res,
    )
    expect(res.statusCode).toBe(403)
    expect(globalThis.__AUDIT_CALLS).toHaveLength(1)
    expect(globalThis.__AUDIT_CALLS[0].operation).toBe('federation_export_denied')
    expect(globalThis.__AUDIT_CALLS[0].meta.reason).toBe('export-no-consent')
    // The business `detail` is B's own string (not a secret); we
    // audit the `code` — never the detail (it can vary freely).
    expect(JSON.stringify(globalThis.__AUDIT_CALLS)).not.toContain('no live consent grant')
  })
})
