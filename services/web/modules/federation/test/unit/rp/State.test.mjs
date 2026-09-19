import { describe, it, expect, vi } from 'vitest'
import {
  createPkceVerifier,
  signState,
  verifySignedState,
  persistPkceState,
  consumePkceState,
  PKCE_STATE_TTL_SECONDS,
} from '../../../rp/State.mjs'

vi.mock('@overleaf/settings', () => ({
  default: {
    siteUrl: 'https://alpha.example',
    security: { sessionSecret: 'unit-test-secret' },
  },
}))

// Mirrors the module-private STATE_KEY_PREFIX in State.mjs (04 §7 key space).
const STATE_PREFIX = 'federation:rp-state:'

function fakeRedis() {
  const store = new Map()
  return {
    __store: store,
    get: vi.fn(async (k) => (store.has(k) ? store.get(k) : null)),
    set: vi.fn(async (k, v, ...args) => {
      store.set(k, v)
      store.lastSet = { key: k, value: v, args }
      return 'OK'
    }),
    del: vi.fn(async (k) => (store.delete(k) ? 1 : 0)),
  }
}

describe('createPkceVerifier', () => {
  it('verifier + challenge + nonce (RFC 7636, S256)', () => {
    const { verifier, challenge, nonce } = createPkceVerifier()
    expect(typeof verifier).toBe('string')
    // RFC 7636 §4.2: 43-128 chars, case-sensitive.
    expect(verifier.length).toBeGreaterThanOrEqual(43)
    expect(verifier.length).toBeLessThanOrEqual(128)
    expect(typeof challenge).toBe('string')
    expect(typeof nonce).toBe('string')
    // S256: challenge is a deterministic transform of verifier, never equal.
    expect(verifier).not.toBe(challenge)

    // Uniqueness: two distinct verifiers.
    const again = createPkceVerifier()
    expect(again.verifier).not.toBe(verifier)
  })
})

describe('signState / verifySignedState', () => {
  const INTENT = {
    projectId: 'proj-1',
    privileges: 'read-and-write',
    nonce: 'abc',
    origin: 'beta.example',
    localName: 'alice',
    url: 'https://alphadeployment.com',
  }

  it('round-trip: verify returns the signed intent', () => {
    const state = signState(INTENT)
    expect(verifySignedState(state)).toEqual(INTENT)
  })

  it('tampered body → null', () => {
    const state = signState(INTENT)
    const flipped = state[2] === 'a' ? 'b' + state.slice(1)
      : state.slice(0, 2) + 'b' + state.slice(3)
    expect(verifySignedState(flipped)).toBeNull()
  })

  it('forged signature (same length) → null via constant-time compare', () => {
    const state = signState(INTENT)
    const dot = state.indexOf('.')
    const sig = state.slice(dot + 1)
    const flipped = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1)
    expect(verifySignedState(state.slice(0, dot + 1) + flipped)).toBeNull()
  })

  it('state signed for another intent yields THAT intent (caller cross-checks)', () => {
    const other = { ...INTENT, localName: 'bob' }
    const stateForOther = signState(other)
    const got = verifySignedState(stateForOther)
    expect(got.localName).toBe('bob')
    expect(got).not.toEqual(INTENT)
  })

  it('garbage input → null (no exception)', () => {
    expect(verifySignedState('')).toBeNull()
    expect(verifySignedState('nodot')).toBeNull()
    expect(verifySignedState(undefined)).toBeNull()
    expect(verifySignedState(12345)).toBeNull()
  })
})

describe('persistPkceState / consumePkceState (05 §3.1)', () => {
  it('persist: redis SET with 120 s TTL + session slot', async () => {
    const redis = fakeRedis()
    const session = {}
    const record = {
      state: 'state-x',
      verifier: 'vrf',
      origin: 'beta.example',
      intent: { projectId: 'p1' },
    }
    await persistPkceState(session, record, redis)
    expect(redis.__store.get(`${STATE_PREFIX}state-x`)).toBe(JSON.stringify({
      verifier: 'vrf',
      origin: 'beta.example',
      intent: { projectId: 'p1' },
    }))
    // EX + TTL 120 s (04 §6). ioredis: set(key, value, 'EX', ttl).
    const callArgs = redis.set.mock.calls[0]
    expect(callArgs[0]).toBe(STATE_PREFIX + 'state-x')
    expect(callArgs[1]).toBe(JSON.stringify({
      verifier: 'vrf',
      origin: 'beta.example',
      intent: { projectId: 'p1' },
    }))
    expect(callArgs[2]).toBe('EX')
    expect(callArgs[3]).toBe(PKCE_STATE_TTL_SECONDS)
    expect(PKCE_STATE_TTL_SECONDS).toBe(120)
    // Session slot written for the owner.
    expect(session.federationRp).toEqual({
      state: 'state-x',
      verifier: 'vrf',
    })
  })

  it('consume: single-use — second read returns null', async () => {
    const redis = fakeRedis()
    const session = { federationRp: { state: 's', verifier: 'v' } }
    await persistPkceState(session, {
      state: 's',
      verifier: 'v0',
      origin: 'beta.example',
      intent: { projectId: 'p1' },
    }, redis)

    const first = await consumePkceState(session, 's', redis)
    expect(first).toEqual({
      verifier: 'v0',
      origin: 'beta.example',
      intent: { projectId: 'p1' },
    })
    // Session slot cleared after consume.
    expect(session.federationRp).toBeUndefined()

    const second = await consumePkceState(session, 's', redis)
    expect(second).toBeNull()
  })

  it('consume: null-session (visitor without express session) still works', async () => {
    const redis = fakeRedis()
    await persistPkceState(null, {
      state: 's2',
      verifier: 'v1',
      origin: 'beta.example',
      intent: { projectId: 'p1' },
    }, redis)
    const got = await consumePkceState(null, 's2', redis)
    expect(got.verifier).toBe('v1')
    expect(await consumePkceState(null, 's2', redis)).toBeNull()
  })

  it('consume: unknown state → null', async () => {
    const redis = fakeRedis()
    const res = await consumePkceState({}, 'never-persisted', redis)
    expect(res).toBeNull()
  })
})
