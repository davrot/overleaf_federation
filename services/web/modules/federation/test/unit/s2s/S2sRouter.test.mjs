// Inbound S2S router unit tests (03 §2, 03 §6) — exercising the LOCKED
// handler ordering (HANDOFF §2) against a fake req/res:
//   ① settings gate → 200 { ok:false, code:'federation-off' }
//   ② envelope sanity (from/to/action shape) → 401 peer-unknown
//   ③ peer pre-lookup → 401 peer-unknown / peer-not-approved
//     (ordering: ③ is BEFORE ④ crypto — unknown peer refuses even with
//      a bad assertion; missing client_assertion → 401 bad-signature)
//   ④ verifyS2sClientAssertion → 401 code passthrough (bad-signature,
//     replay-jti)
//   ⑤ rate limit → 429 + Allow-Retry-After
//   ⑥ dispatch → 200 { ok:true, payload } | { ok:false, code } | 500
//   ⑦ audit → authorize-invite/revoke rows; `invited` preview → NO row
//
// Mocked (everything beyond the router's own ordering & status codes):
//   - verify.mjs crypto (we keep the REAL S2S_ERRORS via importActual so
//     assertions assert the production code constants, not literals).
//   - FederationPeer model (DB), RateLimitStore (Redis; absent in unit
//     tests), the three action modules, util/Audit (ProjectAuditLogEntry
//     DB write).
// The vi.mock factory delegates to plain globalThis-thunk mocks (NOT
// vi.fn) because test/unit/bootstrap.mjs runs `vi.resetAllMocks()` in
// afterEach and that would erase vi.fn implementations/mock values
// between tests.
import { vi, describe, it, expect, beforeEach } from 'vitest'
import Settings from '@overleaf/settings'

vi.mock('@overleaf/settings', () => ({
  default: {
    siteUrl: 'https://alpha.example',
    security: { sessionSecret: 'unit-test-secret' },
    federation: { enabled: true },
    redis: { web: { host: 'localhost', port: 6379 } },
    mongo: { url: 'mongodb://localhost/test-federation', options: {} },
  },
}))

vi.mock('@overleaf/logger', () => ({
  default: {
    info: () => {},
    error: (obj, msg) => {
      globalThis.__lastError = obj?.error ?? msg
      return {}
    },
    warn: () => {},
    debug: () => {},
  },
}))

vi.mock('../../../oidf/verify.mjs', async () => {
  const actual = await vi.importActual('../../../oidf/verify.mjs')
  return {
    ...actual,
    verifyS2sClientAssertion: (assertion, from) => globalThis.__s2sVerify(assertion, from),
  }
})

// Pure-identity modules (no DB/Redis): stop the import graph before
// keystore → FederationKey → Mongoose.connect (no mongo in unit tests).
vi.mock('../../../oidf/leaf.mjs', () => ({
  getOrigin: () => 'alpha.example',
  getEntityId: () => 'https://alpha.example',
  oidcEndpoints: () => ({
    issuer: 'https://alpha.example/federation/oidc',
    authorization: 'https://alpha.example/federation/oidc/auth',
    token: 'https://alpha.example/federation/oidc/token',
    jwks: 'https://alpha.example/federation/oidc/jwks',
    callback: 'https://alpha.example/federation/oidc/rp/callback',
    endSession: 'https://alpha.example/federation/oidc/session/end',
  }),
  buildLeafMetadata: () => ({}),
  buildLeafEntityConfiguration: async () => 'leaf-ec-jwt',
  leafHandler: () => {},
}))

vi.mock('../../../oidf/ClientAssertionClient.mjs', () => ({
  getS2sEndpoint: () => 'https://alpha.example/federation/s2s',
  buildS2sRequest: async () => ({ headers: {}, body: {} }),
}))

vi.mock('../../../app/models/FederationPeer.mjs', () => ({
  FederationPeer: {
    findOne: (filter) => {
      const doc = (globalThis.__peers ?? {})[filter.origin] ?? null
      return {
        lean: async () => doc,
      }
    },
  },
}))

vi.mock('../../../util/RateLimitStore.mjs', () => ({
  checkRateLimit: (...args) =>
    globalThis.__rateLimit
      ? globalThis.__rateLimit(...args)
      : Promise.resolve({ allowed: true, retryAfterSeconds: 0 }),
}))

vi.mock('../../../s2s/actions/invited.mjs', () => ({
  default: async (ctx) => {
    globalThis.__actions.push(ctx)
    return globalThis.__actionResult ?? { ok: true, payload: { preview: 'ok' } }
  },
}))
vi.mock('../../../s2s/actions/authorizeInvite.mjs', () => ({
  default: async (ctx) => {
    globalThis.__actions.push(ctx)
    return globalThis.__actionResult ?? { ok: true, payload: { approved: true } }
  },
}))
vi.mock('../../../s2s/actions/revoke.mjs', () => ({
  default: async (ctx) => {
    globalThis.__actions.push(ctx)
    return globalThis.__actionResult ?? { ok: true, payload: {} }
  },
}))

vi.mock('../../../s2s/actions/exportProject.mjs', () => ({
  // content-bridge v2 (plan 09 §2): the real action's import graph
  // reaches app/src Project/mongodb (Mongoose) — stubbed at the router
  // boundary (the unit scope is router ordering, not the action body;
  // `exportProject.test.mjs` + the two-instance file cover it).
  default: async (ctx) => {
    globalThis.__actions.push(ctx)
    return globalThis.__actionResult ?? { ok: true, payload: { git_url: 'g' } }
  },
}))

vi.mock('../../../util/Audit.mjs', () => ({
  audit: async (args) => {
    globalThis.__auditCalls.push(args)
  },
  AUDIT_TYPES: {
    inviteApproved: 'federation_invite_approved',
    inviteDenied: 'federation_invite_denied',
    trustRevoked: 'federation_trust_revoked',
    exportGranted: 'federation_export_granted',
    exportDenied: 'federation_export_denied',
  },
}))

import S2sRouter from '../../../s2s/S2sRouter.mjs'
import { S2S_ERRORS } from '../../../oidf/verify.mjs'

function makeRes() {
  return {
    statusCode: 0,
    headers: {},
    jsonBody: undefined,
    status(code) {
      this.statusCode = code
      return this
    },
    set(k, v) {
      this.headers[k] = v
      return this
    },
    json(body) {
      this.jsonBody = body
      return this
    },
  }
}

function makeReq({ body, headers = {} } = {}) {
  return {
    body,
    get: (name) => headers[name.toLowerCase()] ?? headers[name] ?? null,
    ip: '127.0.0.1',
  }
}

// Body shape (03 §2): `{ action, from, to, ts, payload }`.
// `to` MUST equal our origin: getOrigin() = host of Settings.siteUrl
// (https://alpha.example → alpha.example).
const VALID_BODY = (over = {}) => ({
  action: 'invited',
  from: 'beta.example',
  to: 'alpha.example',
  ts: 1750000000,
  payload: {},
  ...over,
})

function approvedPeer() {
  globalThis.__peers = { 'beta.example': { origin: 'beta.example', status: 'approved' } }
}

beforeEach(() => {
  // Isolation + per-test toggles for the mock delegates, and the
  // vi.mocked Settings object (shared across this file).
  Object.assign(Settings, {
    siteUrl: 'https://alpha.example',
    security: { sessionSecret: 'unit-test-secret' },
    federation: { enabled: true },
    redis: { web: { host: 'localhost', port: 6379 } },
    mongo: { url: 'mongodb://localhost/test-federation', options: {} },
  })
  globalThis.__peers = {}
  globalThis.__auditCalls = []
  globalThis.__actions = []
  globalThis.__actionResult = undefined
  globalThis.__rateLimit = undefined
  // Default: verification succeeds; individual cases override per branch.
  globalThis.__s2sVerify = async (_assertion, from) => ({
    ok: true,
    verified: {
      clientId: `urn:overleaf-federation:client:${from}`,
      jti: 'jti-1',
    },
  })
})

describe('S2sRouter (unit, fake req/res)', () => {
  it('① federation off → 200 { ok:false, code:federation-off } (route always mounted)', async () => {
    Settings.federation.enabled = false
    const res = makeRes()
    const req = makeReq({ body: VALID_BODY(), headers: { client_assertion: 'any' } })
    await S2sRouter._handleS2sRequest(req, res)
    expect(res.statusCode).toBe(200)
    expect(res.jsonBody).toEqual({
      ok: false,
      code: S2S_ERRORS.FEDERATION_OFF,
      detail: 'federation disabled',
    })
  })

  it('② malformed envelope (missing `to`, wrong `to`, unknown action) → 401 peer-unknown', async () => {
    const bodies = [
      // missing `to`
      { action: 'invited', from: 'beta.example', ts: 1, payload: {} },
      // `to` mismatch (must be our own origin)
      VALID_BODY({ to: 'other.example' }),
      // unknown action
      VALID_BODY({ action: 'not-an-action' }),
    ]
    for (const body of bodies) {
      const res = makeRes()
      const req = makeReq({ body, headers: { client_assertion: 'any' } })
      await S2sRouter._handleS2sRequest(req, res)
      expect(res.statusCode, `body ${JSON.stringify(body)}`).toBe(401)
      expect(res.jsonBody.code, `body ${JSON.stringify(body)}`).toBe(S2S_ERRORS.PEER_UNKNOWN)
    }
  })

  it('③ unknown peer (FQDN not pinned) → 401 peer-unknown', async () => {
    // __peers empty → findOne returns null.
    const res = makeRes()
    const req = makeReq({ body: VALID_BODY(), headers: { client_assertion: 'any' } })
    await S2sRouter._handleS2sRequest(req, res)
    expect(res.statusCode).toBe(401)
    expect(res.jsonBody.code).toBe(S2S_ERRORS.PEER_UNKNOWN)
  })

  it('③ before ④: unknown peer + bad assertion still reports peer-lookup (no crypto)', async () => {
    globalThis.__s2sVerify = async () => ({
      ok: false,
      code: S2S_ERRORS.BAD_SIGNATURE,
      detail: 'signature verify failed',
      verified: undefined,
    })
    const res = makeRes()
    const req = makeReq({
      body: VALID_BODY(),
      headers: { client_assertion: 'forged' },
    })
    await S2sRouter._handleS2sRequest(req, res)
    expect(res.statusCode).toBe(401)
    expect(res.jsonBody.code).toBe(S2S_ERRORS.PEER_UNKNOWN)
  })

  it('③ peer exists but not approved → 401 peer-not-approved', async () => {
    globalThis.__peers = { 'beta.example': { origin: 'beta.example', status: 'pending' } }
    const res = makeRes()
    const req = makeReq({ body: VALID_BODY(), headers: { client_assertion: 'any' } })
    await S2sRouter._handleS2sRequest(req, res)
    expect(res.statusCode).toBe(401)
    expect(res.jsonBody.code).toBe(S2S_ERRORS.PEER_NOT_APPROVED)
  })

  it('header contract: approved peer + missing client_assertion → 401 bad-signature', async () => {
    approvedPeer()
    const res = makeRes()
    const req = makeReq({ body: VALID_BODY() }) // no client_assertion header
    await S2sRouter._handleS2sRequest(req, res)
    expect(res.statusCode).toBe(401)
    expect(res.jsonBody.code).toBe(S2S_ERRORS.BAD_SIGNATURE)
  })

  it('④ verify failure → 401 with verify.mjs code passthrough (bad-signature)', async () => {
    approvedPeer()
    globalThis.__s2sVerify = async () => ({
      ok: false,
      code: S2S_ERRORS.BAD_SIGNATURE,
      detail: 'signature verify failed',
      verified: undefined,
    })
    const res = makeRes()
    const req = makeReq({
      body: VALID_BODY(),
      headers: { client_assertion: 'sig-1.2.3' },
    })
    await S2sRouter._handleS2sRequest(req, res)
    expect(res.statusCode).toBe(401)
    expect(res.jsonBody.code).toBe(S2S_ERRORS.BAD_SIGNATURE)
  })

  it('④ replay (jti seen before) → 401 replay-jti passthrough', async () => {
    approvedPeer()
    globalThis.__s2sVerify = async () => ({
      ok: false,
      code: S2S_ERRORS.REPLAY_JTI,
      detail: 'replay jti',
      verified: undefined,
    })
    const res = makeRes()
    const req = makeReq({
      body: VALID_BODY(),
      headers: { client_assertion: 'sig-1.2.3' },
    })
    await S2sRouter._handleS2sRequest(req, res)
    expect(res.statusCode).toBe(401)
    expect(res.jsonBody.code).toBe(S2S_ERRORS.REPLAY_JTI)
  })

  it('⑤ rate limit trip → 429 + Allow-Retry-After header (no dispatch/audit)', async () => {
    approvedPeer()
    globalThis.__rateLimit = async () => ({ allowed: false, retryAfterSeconds: 7 })
    const res = makeRes()
    const req = makeReq({
      body: VALID_BODY(),
      headers: { client_assertion: 'sig-1.2.3' },
    })
    await S2sRouter._handleS2sRequest(req, res)
    expect(res.statusCode).toBe(429)
    expect(res.jsonBody.code).toBe(S2S_ERRORS.RATE_LIMITED)
    expect(res.headers['Allow-Retry-After']).toBe('7')
    expect(globalThis.__actions).toHaveLength(0) // no dispatch past ⑤
    expect(globalThis.__auditCalls).toHaveLength(0) // no audit past ⑤
  })

  it('⑥ dispatch `invited` → 200 { ok:true, payload }; preview → NO audit row', async () => {
    approvedPeer()
    globalThis.__actionResult = { ok: true, payload: { localName: 'alice', origin: 'beta.example' } }
    const res = makeRes()
    const req = makeReq({
      body: VALID_BODY({ action: 'invited' }),
      headers: { client_assertion: 'sig-1.2.3' },
    })
    await S2sRouter._handleS2sRequest(req, res)
    expect(res.statusCode).toBe(200)
    expect(res.jsonBody).toEqual({
      ok: true,
      payload: { localName: 'alice', origin: 'beta.example' },
    })
    expect(globalThis.__actions).toHaveLength(1)
    expect(globalThis.__actions[0].callerOrigin).toBe('beta.example')
    // 04 §8 / HANDOFF: `invited` previews → NO audit row.
    expect(globalThis.__auditCalls).toHaveLength(0)
  })

  it('⑥ dispatch `authorize-invite` ok → 200 { ok:true } + audit inviteApproved', async () => {
    approvedPeer()
    globalThis.__actionResult = { ok: true, payload: { displayName: 'Alice' } }
    const res = makeRes()
    const req = makeReq({
      body: VALID_BODY({
        action: 'authorize-invite',
        payload: { invitee: { localName: 'alice', origin: 'beta.example' } },
      }),
      headers: { client_assertion: 'sig-1.2.3' },
    })
    await S2sRouter._handleS2sRequest(req, res)
    expect(res.statusCode).toBe(200)
    expect(res.jsonBody.ok).toBe(true)
    // ⑦ audit fired with the approve op (hashed assertion meta, 03 §6).
    expect(globalThis.__auditCalls).toHaveLength(1)
    expect(globalThis.__auditCalls[0].operation).toBe('federation_invite_approved')
  })

  it('⑥ dispatch `authorize-invite` business refusal → 200 { ok:false, code } + audit inviteDenied', async () => {
    approvedPeer()
    globalThis.__actionResult = { ok: false, code: 'invitee-unknown' }
    const res = makeRes()
    const req = makeReq({
      body: VALID_BODY({
        action: 'authorize-invite',
        payload: { invitee: { localName: 'alice', origin: 'beta.example' } },
      }),
      headers: { client_assertion: 'sig-1.2.3' },
    })
    await S2sRouter._handleS2sRequest(req, res)
    expect(res.statusCode).toBe(200)
    expect(res.jsonBody).toEqual({ ok: false, code: 'invitee-unknown' })
    expect(globalThis.__auditCalls).toHaveLength(1)
    expect(globalThis.__auditCalls[0].operation).toBe('federation_invite_denied')
  })

  it('⑥ dispatch `revoke` → 200 + audit trustRevoked (inbound)', async () => {
    approvedPeer()
    globalThis.__actionResult = { ok: true, payload: {} }
    const res = makeRes()
    const req = makeReq({
      body: VALID_BODY({ action: 'revoke' }),
      headers: { client_assertion: 'sig-1.2.3' },
    })
    await S2sRouter._handleS2sRequest(req, res)
    expect(res.statusCode).toBe(200)
    expect(res.jsonBody.ok).toBe(true)
    expect(globalThis.__auditCalls).toHaveLength(1)
    expect(globalThis.__auditCalls[0].operation).toBe('federation_trust_revoked')
    expect(globalThis.__auditCalls[0].meta.direction).toBe('inbound')
  })

  it('⑥ action throws inside trusted path → 500 internal-error (no stack echo)', async () => {
    approvedPeer()
    const origInvited = S2sRouter._actions['invited']
    S2sRouter._actions['invited'] = async () => {
      throw new Error('boom')
    }
    try {
      const res = makeRes()
      const req = makeReq({
        body: VALID_BODY({ action: 'invited' }),
        headers: { client_assertion: 'sig-1.2.3' },
      })
      await S2sRouter._handleS2sRequest(req, res)
      expect(res.statusCode).toBe(500)
      expect(res.jsonBody).toMatchObject({ ok: false, code: 'internal-error' })
    } finally {
      S2sRouter._actions['invited'] = origInvited
    }
  })
})
