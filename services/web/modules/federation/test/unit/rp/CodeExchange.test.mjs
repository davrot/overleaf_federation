import { describe, it, expect, vi, beforeAll } from 'vitest'
import { SignJWT, importJWK } from 'jose'
import Settings from '@overleaf/settings'
import { generateSigningKey } from '@oidfed/core'
import { exchange } from '../../../rp/CodeExchange.mjs'

// Real jose v6 + real EC P-256 keys — the exact stack B signs with
// (FINDINGS §oidc-provider), so header/kid/alg round-tripping is
// exercised honestly, not faked.

let B_KEY
let SIGNER

beforeAll(async () => {
  B_KEY = await generateSigningKey('ES256')
  SIGNER = await importJWK({ ...B_KEY.privateKey })
})

const INTENT = {
  projectId: 'proj-1',
  privileges: 'read-and-write',
  nonce: 'nonce-abc',
  origin: 'beta.example',
  localName: 'alice',
}
// Must match the expression in rp/CodeExchange.mjs (Settings singleton).
const CLIENT_ID = `urn:overleaf-federation:client:${new URL(Settings.siteUrl).hostname}`
const ISSUER = 'https://beta.example/federation/oidc'

async function jwksForKey(key = B_KEY) {
  return {
    keys: [{
      kid: key.publicKey.kid,
      kty: key.publicKey.kty,
      crv: key.publicKey.crv,
      x: key.publicKey.x,
      y: key.publicKey.y,
      alg: 'ES256',
      use: 'sig',
    }],
  }
}

async function idToken(claimOverrides = {}, kid, key, signingKey) {
  const now = Math.floor(Date.now() / 1000)
  const token = await new SignJWT({
    sub: 'account-id-1',
    iss: ISSUER,
    aud: CLIENT_ID,
    origin: INTENT.origin,
    localName: INTENT.localName,
    nonce: INTENT.nonce,
    iat: now,
    exp: now + 600,
    ...claimOverrides,
  })
    .setProtectedHeader({ kid: kid || B_KEY.publicKey.kid, alg: 'ES256' })
    .sign(signingKey || SIGNER)
  return token
}

function fakeRedis() {
  const store = new Map()
  return {
    __store: store,
    get: vi.fn(async (k) => (store.has(k) ? store.get(k) : null)),
    set: vi.fn(async (k, v) => {
      store.set(k, v)
      return 'OK'
    }),
    del: vi.fn(async () => 0),
  }
}

/**
 * fetch mock: distinguishes `/federation/oidc/jwks` (jwksResponses,
 * consumed in order) from `/federation/oidc/token` (tokenResponses).
 */

// chai-as-promised is active (repo vitest setup) and breaks
// `expect(promise).rejects...` — assert rejections manually.
async function expectRejectedToContain(fn, substring) {
  try {
    await fn()
  } catch (err) {
    if (err.message?.includes(substring)) return
    throw new Error(
      `expected error containing "${substring}", got: ${err.message}`,
    )
  }
  throw new Error(`expected rejection with "${substring}" but the promise resolved`)
}
function setupFetch(jwksResponses, {
  tokenBody,
  tokenStatus = 200,
  tokenOk = true,
} = {}) {
  let jwksCalls = 0
  const fetchMock = vi.fn(async (url, opts) => {
    const path = String(url)
    if (path.endsWith('/federation/oidc/jwks')) {
      const idx = jwksCalls++
      return {
        ok: true,
        json: async () => jwksResponses[Math.min(idx, jwksResponses.length - 1)],
      }
    }
    return {
      ok: tokenOk,
      status: tokenStatus,
      json: async () => (tokenOk ? tokenBody : { error: 'invalid_grant' }),
    }
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

describe('exchange (rp/CodeExchange 05 §3.2)', () => {
  it('happy path: code swapped for a verified id_token, PKCE sent', async () => {
    const redis = fakeRedis()
    const token = await idToken()
    const fetchMock = setupFetch([await jwksForKey()], {
      tokenBody: { id_token: token },
    })
    const claims = await exchange('beta.example', {
      code: 'code-1',
      codeVerifier: 'verifier-xyz',
      intent: INTENT,
    }, redis)
    vi.unstubAllGlobals()

    expect(claims.origin).toBe('beta.example')
    expect(claims.localName).toBe('alice')
    expect(claims.nonce).toBe('nonce-abc')

    // JWKS fetched once, token endpoint hit once, with PKCE body.
    expect(fetchMock).toHaveBeenCalledTimes(2)
    const tokenCall = fetchMock.mock.calls.find(
      (c) => String(c[0]).includes('/federation/oidc/token'),
    )
    const body = new URLSearchParams(tokenCall[1].body)
    expect(body.get('grant_type')).toBe('authorization_code')
    expect(body.get('code')).toBe('code-1')
    expect(body.get('code_verifier')).toBe('verifier-xyz')
    expect(body.get('client_id')).toBe(CLIENT_ID)
  })

  it('cached JWKS: no refetch, still verifies', async () => {
    const redis = fakeRedis()
    await redis.set(
      'federation:jwks:beta.example',
      JSON.stringify(await jwksForKey()),
      'EX',
      3600,
    )
    const fetchMock = setupFetch([await jwksForKey()], {
      tokenBody: { id_token: await idToken() },
    })
    const claims = await exchange('beta.example', {
      code: 'code-1',
      codeVerifier: 'verifier-xyz',
      intent: INTENT,
    }, redis)
    vi.unstubAllGlobals()
    expect(claims.localName).toBe('alice')
    // JWKS served from Redis cache: fetch called only for the token.
    const jwksFetches = fetchMock.mock.calls.filter(
      (c) => String(c[0]).endsWith('/federation/oidc/jwks'),
    )
    expect(jwksFetches).toHaveLength(0)
  })

  it('kid mismatch: refetches JWKS once, verifies with fresh key', async () => {
    const redis = fakeRedis()
    // The token is signed with a key whose kid is NOT in the first
    // (stale) JWKS response the controller would use — mirroring a
    // post-rotation kid mismatch (04 §6).
    const FRESH = await generateSigningKey('ES256')
    const FRESH_SIGNER = await importJWK({ ...FRESH.privateKey })
    const token = await idToken({ nonce: INTENT.nonce }, FRESH.publicKey.kid, FRESH, FRESH_SIGNER)
    const first = { keys: [] }
    const second = await jwksForKey(FRESH)
    setupFetch([first, second], {
      tokenBody: { id_token: token },
    })
    const claims = await exchange('beta.example', {
      code: 'code-1',
      codeVerifier: 'verifier-xyz',
      intent: INTENT,
    }, redis)
    vi.unstubAllGlobals()
    expect(claims.localName).toBe('alice')
    // Stale JWKS was refetched (cache-bypass), and the cache was repopulated
    // with the fresh key.
    const cache = await redis.get('federation:jwks:beta.example')
    expect(JSON.parse(cache)).toEqual(second)
  })

  it('identity-mismatch: id_token localName disagrees with intent', async () => {
    const redis = fakeRedis()
    const token = await idToken({ localName: 'mallory' })
    setupFetch([await jwksForKey()], { tokenBody: { id_token: token } })
    await expectRejectedToContain(
      () => exchange('beta.example', {
        code: 'code-1',
        codeVerifier: 'verifier-xyz',
        intent: INTENT,
      }, redis),
      'identity-mismatch',
    )
    vi.unstubAllGlobals()
  })

  it('state-mismatch: id_token nonce disagrees with intent', async () => {
    const redis = fakeRedis()
    const token = await idToken({ nonce: 'other-nonce' })
    setupFetch([await jwksForKey()], { tokenBody: { id_token: token } })
    await expectRejectedToContain(
      () => exchange('beta.example', {
        code: 'code-1',
        codeVerifier: 'verifier-xyz',
        intent: INTENT,
      }, redis),
      'state-mismatch',
    )
    vi.unstubAllGlobals()
  })

  it('exchange-failed: token endpoint error (no id_token)', async () => {
    const redis = fakeRedis()
    setupFetch([await jwksForKey()], {
      tokenStatus: 400,
      tokenOk: false,
    })
    await expectRejectedToContain(
      () => exchange('beta.example', {
        code: 'bogus',
        codeVerifier: 'verifier-xyz',
        intent: INTENT,
      }, redis),
      'exchange-failed',
    )
    vi.unstubAllGlobals()
  })

  it('kid truly not in JWKS (stale + fresh): exchange-failed', async () => {
    const redis = fakeRedis()
    const token = await idToken() // signed with B_KEY
    const OTHER = await generateSigningKey('ES256')
    const otherJwks = await jwksForKey(OTHER)
    setupFetch([otherJwks, otherJwks], { tokenBody: { id_token: token } })
    await expectRejectedToContain(
      () => exchange('beta.example', {
        code: 'code-1',
        codeVerifier: 'verifier-xyz',
        intent: INTENT,
      }, redis),
      'kid-not-in-jwks',
    )
    vi.unstubAllGlobals()
  })
})
