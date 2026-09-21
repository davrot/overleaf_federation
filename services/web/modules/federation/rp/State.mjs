// A-side PKCE + state store (05 §3.1, 01 §5 steps 3–7).
//
// Grant initiation is one redirect (05 §4.2 "pure identity redirect").
// This module does the two halves around that 302:
//
//   initiation:  generate verifier + challenge S256, nonce;
//                persist the HMAC-signed intent in Redis as the single
//                read source (TTL 120 s — survives cookie expiry across
//                tabs, 05 §3.1), and mirror it into the owner's express
//                session as a CLEANUP MIRROR only (deleted on callback);
//                build B's authorization URL.
//
//   callback:    read + DELETE the single-use verifier from Redis
//                (the session slot is NOT a read source — callback may
//                land on another replica where the session rows differs);
//                verify the HMAC-signed
//                `state` (the intent, never a raw secret).
//
// Security (06 §3): no client secret anywhere (public client + PKCE);
// `state` is the HMAC-signed intent — a forged `state` cannot mint a
// mirror session because the callback re-derives every grant-relevant
// value from it.

import crypto from 'node:crypto'
import Settings from '@overleaf/settings'
import RedisWrapper from '../../../app/src/infrastructure/RedisWrapper.mjs'

// 04 §6: 120 s backup. The AuthorizationCode TTL on B is the same
// (createProvider.mjs), so the CODE is always the expiry bottleneck.
export const PKCE_STATE_TTL_SECONDS = 120
const STATE_KEY_PREFIX = 'federation:rp-state:'

function getRedis(redis) {
  return redis ?? RedisWrapper.client('federation')
}

export function createPkceVerifier() {
  const verifier = crypto.randomBytes(32).toString('base64url')
  const challenge = crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url')
  const nonce = crypto.randomBytes(32).toString('base64url')
  return { verifier, challenge, nonce }
}

/**
 * Sign the grant intent (01 §5 step 3: state = HMAC-signed JSON nonce).
 *
 * @param {object} intent
 *   { origin, localName, projectId, privileges, url, nonce }
 * @returns {string} `<base64url(JSON)>.<base64url(HMAC-SHA256)>`
 */
export function signState(intent) {
  const body = Buffer.from(JSON.stringify(intent)).toString('base64url')
  const sig = crypto
    .createHmac('sha256', Settings.security.sessionSecret)
    .update(body)
    .digest('base64url')
  return `${body}.${sig}`
}

/**
 * Verify the HMAC and return the intent, or null. Constant-time compare
 * (06 §2). A malformed / forged state is a hard refusal, not a parse.
 *
 * @param {string} state
 * @returns {object|null}
 */
export function verifySignedState(state) {
  if (typeof state !== 'string') return null
  const dot = state.indexOf('.')
  if (dot <= 0) return null
  const body = state.slice(0, dot)
  const sig = state.slice(dot + 1)
  const expected = crypto
    .createHmac('sha256', Settings.security.sessionSecret)
    .update(body)
    .digest('base64url')
  if (
    body.length === 0 ||
    sig.length !== expected.length ||
    !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))
  ) {
    return null
  }
  try {
    return JSON.parse(Buffer.from(body, 'base64url').toString())
  } catch {
    return null
  }
}

/**
 * Persist the single-use PKCE record (initiation, 05 §3.1):
 *   Redis `federation:rp-state:<state>`  TTL 120 s
 *   value: { verifier, origin, intent }
 * and mirror it into the owner's express session (`req.session.federationRp`).
 *
 * @param {object} session  the owner's express session (or null in tests)
 * @param {object} record  { state, verifier, origin, intent }
 * @param {ioredis|null} [redis]  client override
 */
export async function persistPkceState(session, record, redis) {
  const client = getRedis(redis)
  await client.set(
    `${STATE_KEY_PREFIX}${record.state}`,
    JSON.stringify({
      verifier: record.verifier,
      origin: record.origin,
      intent: record.intent,
    }),
    'EX',
    PKCE_STATE_TTL_SECONDS,
  )
  if (session) {
    session.federationRp = {
      state: record.state,
      verifier: record.verifier,
    }
  }
}

/**
 * Read + DELETE the single-use PKCE record (callback, 05 §3.3 step 1).
 * Session slot first, Redis backup fallback.
 *
 * @param {object|null} session  the visitor's express session
 * @param {string} state
 * @param {ioredis|null} [redis]
 * @returns {Promise<object|null>} { verifier, origin, intent } or null
 */
export async function consumePkceState(session, state, redis) {
  const client = getRedis(redis)
  const raw = await client.get(`${STATE_KEY_PREFIX}${state}`)
  if (session) {
    delete session.federationRp
  }
  if (raw === null) return null
  const parsed = JSON.parse(raw)
  await client.del(`${STATE_KEY_PREFIX}${state}`)
  return parsed
}
