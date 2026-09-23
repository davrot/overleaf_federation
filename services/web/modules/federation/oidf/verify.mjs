// Inbound S2S verification (03 §2 steps 1–3, §3, §6).
//
// Ordering (03 §6: "verify → dedup → apply, or refuse"):
//
//   1. peer lookup — approved peer by `from` (body, 03 §2 step 2). The
//      pinned key (peer.anchorJwks + peer.kid, TOFU admin pin, 02 §3) is
//      the authority; we do NOT re-fetch the caller's leaf at runtime
//      (03 §2 "no per-call JWKS negotiation" — kid-mismatch refetch is
//      the admin flow, 06 §2);
//   2. `kid` check — the assertion header kid must be a key we pinned
//      (`unknown-kid`, 03 §6);
//   3. signature + `iss`/`aud`/`exp` via npm `verifyClientAssertion`
//      (iss must equal sub, aud must be OUR S2S endpoint — a
//      cross-destination assertion is refused); `iss` must be the
//      caller's client id `urn:overleaf-federation:client:<from>` (03 §2
//      step 2);
//   4. replay — Redis `federation:replay:<jti>` SETNX (TTL = `exp` +
//      clock tolerance, 03 §3). A second delivery of the same `jti` is
//      401 `replay-jti`, no state change.
//
// Machine codes (03 §6).
export const S2S_ERRORS = {
  BAD_SIGNATURE: 'bad-signature',
  UNKNOWN_KID: 'unknown-kid',
  PEER_UNKNOWN: 'peer-unknown',
  PEER_NOT_APPROVED: 'peer-not-approved',
  REPLAY_JTI: 'replay-jti',
  TIMESTAMP_SKEW: 'timestamp-skew',
  FEDERATION_OFF: 'federation-off',
  INVITEE_UNKNOWN: 'invitee-unknown',
  INVITEE_DISABLED: 'invitee-disabled',
  RATE_LIMITED: 'rate-limited',
  // Content bridge v2 (plan 09 §2). Business refusions (200 + in-band
  // envelope, LOCKED §1 — NOT 401; "401" in plan 09 is code-taxonomy
  // shorthand). Peer-level refusions above (peer-not-approved / peer-
  // unknown) are pre-existing router-layer (S2sRouter ③).
  EXPORT_DISABLED: 'export-disabled',
  EXPORT_NO_CONSENT: 'export-no-consent',
  PROJECT_NOT_OWNED: 'project-not-owned',
}
import { decodeProtectedHeader } from 'jose'
import { verifyClientAssertion } from '@oidfed/core'
import logger from '@overleaf/logger'

import RedisWrapper from '../../../app/src/infrastructure/RedisWrapper.mjs'
import { FederationPeer } from '../app/models/FederationPeer.mjs'

import { getS2sEndpoint } from './ClientAssertionClient.mjs'

// 03 §3: clock tolerance (60 s, `FederationOptions.clockSkewSeconds`).
const CLOCK_SKEW_SECONDS = 60

const REPLAY_PREFIX = 'federation:replay:'

// ioredis (via @overleaf/redis-wrapper). Feature key 'federation' falls
// back to `Settings.redis.web` (05 §10); tests inject a fake client.
let _redisClient = null
export function _setReplayRedisClientForTest(client) {
  _redisClient = client
}
function redis() {
  return _redisClient ?? RedisWrapper.client('federation')
}

/**
 * Approved peer by ORIGIN (FQDN without port, the S2S wire's `from`,
 * 03 §2). Entity id is derived from origin (02 §5).
 * */
export async function lookupApprovedPeer(origin) {
  const peer = await FederationPeer.findOne({ origin }).lean()
  if (!peer || peer.status !== 'approved') {
    return null
  }
  return peer
}

/**
 * Redis-backed `jti` dedup (03 §3, 04 §6).
 *
 * npm @oidfed/core v1.0.0 defines the `ReplayStore` TYPE (`useJti(claim)
 * -> Promise<boolean>`, `claim = { issuer, audience, jti, expiresAt }`)
 * and ships the in-memory `MemoryReplayStore`; the Redis impl is ours
 * (04 §6 "we wrap Redis with the same interface"). Atomic one roundtrip:
 * `SET key 1 EX ttl NX` (nil on replay), same as the `MemoryReplayStore`
 * contract (`true` = claimed, `false` = replayed).
 *
 * @returns {Promise<boolean>} true first time; false on replay.
 * */
export async function claimJti(jti, expiresAt) {
  const ttlSeconds = Math.max(
    expiresAt + CLOCK_SKEW_SECONDS - Math.floor(Date.now() / 1000),
    1,
  )
  const res = await redis().set(REPLAY_PREFIX + jti, '1', 'EX', ttlSeconds, 'NX')
  return res === 'OK'
}

/**
 * Verify a received S2S client assertion (03 §2).
 *
 * @returns {Promise<
 *  { ok: true, peer, verified: { clientId, issuedAt, expiresAt, jti? } } |
 *  { ok: false, code, detail }
 * >}
 */
export async function verifyS2sClientAssertion(assertion, from) {
  // (1) peer lookup (03 §2 step 1) by the wire's `from` (caller origin
  //     FQDN).
  const peer = await lookupApprovedPeer(from)
  if (!peer) {
    return {
      ok: false,
      code: 'peer-unknown',
      detail: `no approved peer for ${from}`,
    }
  }

  let header
  try {
    header = decodeProtectedHeader(assertion)
  } catch {
    return { ok: false, code: 'bad-signature', detail: 'undecodable assertion' }
  }

  // (2) kid must be a pinned key (03 §6 machine code `unknown-kid`).
  if (header.kid && peer.kid && header.kid !== peer.kid) {
    return {
      ok: false,
      code: 'unknown-kid',
      detail: `kid ${header.kid} not pinned for ${from}`,
    }
  }

  // (3) signature + iss + aud + exp (npm v1.0.0
  // `verifyClientAssertion(assertion, jwks, expectedAudience, opts)`).
  // aud = our S2S endpoint (03 §2 step 2, fixed per instance, 03 §8).
  const anchorJwks =
    typeof peer.anchorJwks === 'string' ? JSON.parse(peer.anchorJwks) : peer.anchorJwks
  const result = await verifyClientAssertion(
    assertion,
    anchorJwks,
    getS2sEndpoint(),
    { clockSkewSeconds: CLOCK_SKEW_SECONDS },
  )
  if (!result.ok) {
    return {
      ok: false,
      code: 'bad-signature',
      detail:
        result.error?.description || 'client assertion verification failed',
    }
  }
  const verified = result.value

  // (3b) iss == the caller's client id (03 §2 step 2). The S2S wire's `from`
  //     is the caller's ORIGIN (FQDN without port/scheme, 03 §2 body
  //     example); `iss` encodes that same origin. We derive the expected
  //     client id from the *approved peer's* pinned origin — never from a
  //     body field — so a spoofed `from` can neither pass peer lookup nor
  //     the iss check (06 §2: "verify → dedup → apply, or refuse").
  const expectedClientId = `urn:overleaf-federation:client:${peer.origin}`
  if (verified.clientId !== expectedClientId) {
    return { ok: false, code: 'bad-signature', detail: 'iss mismatch' }
  }

  // (4) replay (03 §3).
  if (!verified.jti) {
    return { ok: false, code: 'bad-signature', detail: 'missing jti' }
  }
  const claimed = await claimJti(verified.jti, verified.expiresAt)
  if (!claimed) {
    // 06 §3: a replayed jti is a security event (replayed client
    // assertion from `from`); log before the wire-level refusal.
    logger.warn(
      `federation S2S: replayed jti ${verified.jti} from origin ${peer.origin}`,
    )
    return { ok: false, code: 'replay-jti', detail: 'jti replay' }
  }

  return { ok: true, peer, verified }
}

