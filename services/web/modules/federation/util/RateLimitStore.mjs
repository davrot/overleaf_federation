// S2S rate limiting (03 §5, 04 §6), enforced on the RECEIVING instance.
//
// Mirror of NC v36 `lib/private/Security/RateLimiting/Limiter.php`: one
// Redis `INCR` per receipt + `EXPIRE` on the window opener (INCR returns
// 1 → set the TTL); on exceed: 429 + `Allow-Retry-After` = remaining
// window TTL (03 §5). Budgets and keys (04 §6 exact forms):
//
//   federation:ratelimit:authorize:<callerOrigin>:<localNameHash>  30 / 120 s
//   federation:ratelimit:invited:<callerOrigin>:<localNameHash>    30 / 120 s
//   federation:ratelimit:revoke:<callerOrigin>                     5  / 1200 s
//
// `<localNameHash>` = saltedLocalNameHash (util/Anchor.mjs) over the
// INVITEE's wire values (`invitee.localName`, `invitee.origin`) — the spec
// keys by `(caller, invitee.localName)`; the raw claim never lands in a
// Redis key (06 §6). `federation:ratelimit:registration:<origin>` (04 §6)
// is the P3 institutional budget — NOT built in P0–P2.
//
// The same hash form serves the A-side `invited` preview cache (03 §4.2,
// 04 §6 `federation:invite-cache:<peerOrigin>:<localNameHash>`), exported
// as helpers below.

import RedisWrapper from '../../../app/src/infrastructure/RedisWrapper.mjs'

// 03 §5 budget table. `revoke` is keyed by caller origin only (admin
// action, no invitee); the two invite actions are keyed by
// (caller origin, invitee localNameHash).
export const RATE_LIMITS = {
  'authorize-invite': { budget: 30, windowSeconds: 120 },
  invited: { budget: 30, windowSeconds: 120 },
  revoke: { budget: 5, windowSeconds: 1200 },
}

// ioredis (via @overleaf/redis-wrapper). Feature key 'federation' falls
// back to `Settings.redis.web` (05 §10); tests inject a fake client.
let _redisClient = null
export function _setRateLimitRedisClientForTest(client) {
  _redisClient = client
}
export function getRateLimitRedis(redis) {
  return redis ?? _redisClient ?? RedisWrapper.client('federation')
}

/**
 * Check (and consume) one budget unit for an inbound S2S action (03 §5).
 * Called by the S2S router AFTER assertion verification (step ⑤) and
 * BEFORE dispatch (step ⑥).
 *
 * @param {ioredis|null} redis  client override (tests); fallback: the
 *   module client / test fake
 * @param {object} opts
 * @param {string} opts.action 'authorize-invite' | 'invited' | 'revoke'
 * @param {string} opts.callerOrigin the S2S wire's `from` (caller origin)
 * @param {string} [opts.localNameHash] saltedLocalNameHash of the INVITEE
 *   wire values (invite action key component; omitted for `revoke`)
 * @returns {Promise<{ allowed: boolean, retryAfterSeconds?: number }>}
 *   `retryAfterSeconds` = remaining window TTL (the 429 header).
 */
export async function checkRateLimit(
  redis,
  { action, callerOrigin, localNameHash },
) {
  const limit = RATE_LIMITS[action]
  if (!limit) {
    // Unknown action: the envelope pre-check already refused it; do not
    // rate-limit (no budget row for it).
    return { allowed: true }
  }
  const key =
    action === 'revoke'
      ? `federation:ratelimit:revoke:${callerOrigin}`
      : `federation:ratelimit:${action}:${callerOrigin}:${localNameHash}`

  const client = getRateLimitRedis(redis)
  const count = await client.incr(key)
  if (count === 1) {
    // We opened this window — start its TTL.
    await client.expire(key, limit.windowSeconds)
  }
  if (count > limit.budget) {
    const ttl = await client.ttl(key)
    return {
      allowed: false,
      retryAfterSeconds: Math.max(ttl > 0 ? ttl : 1, 1),
    }
  }
  return { allowed: true }
}

/**
 * A-side `invited` preview cache (03 §4.2 "60 s cached on caller",
 * 04 §6): 60 s TTL, keyed `federation:invite-cache:<peerOrigin>:
 * <localNameHash>`. The receiving side never caches (it rate-limits).
 */
export async function getCachedInvite(redis, peerOrigin, localNameHash) {
  const client = getRateLimitRedis(redis)
  const cached = await client.get(
    `federation:invite-cache:${peerOrigin}:${localNameHash}`,
  )
  return cached ? JSON.parse(cached) : null
}

export async function setCachedInvite(redis, peerOrigin, localNameHash, response) {
  const client = getRateLimitRedis(redis)
  await client.set(
    `federation:invite-cache:${peerOrigin}:${localNameHash}`,
    JSON.stringify(response),
    'EX',
    60,
  )
}
