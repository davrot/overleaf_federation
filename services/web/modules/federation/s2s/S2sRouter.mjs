// Inbound S2S endpoint (03 §2, §6): POST /federation/s2s.
//
// ALWAYS mounted (decision, HANDOFF): even when `Settings.federation.enabled`
// is false the route exists and returns 200 `{ ok: false, code:
// 'federation-off' }` so peers get a machine-readable refusal instead of a
// 404 from a dead mount.
//
// Handler ordering (LOCKED, HANDOFF §2) — everything is verified before any
// DB write ("verify → dedup → apply, or refuse", 03 §6, 06 §2):
//   ① settings gate        → 200 { ok:false, code:'federation-off' }
//   ② envelope sanity      → 401 { code:'peer-unknown' }  (no `from` / bad
//                            `to` / unknown `action`; no separate
//                            invalid-envelope code exists, 03 §6)
//   ③ peer pre-lookup      → 401 peer-unknown / peer-not-approved
//                            (cheap; precedes crypto)
//   ④ verifyS2sClientAssertion (signature + iss/aud/exp + jti dedup,
//                            03 §2-§3; codes pass through from verify.mjs)
//   ⑤ rate limit INCR      → 429 + Allow-Retry-After (03 §5)
//   ⑥ action dispatch      → 200 { ok:true, payload } | { ok:false, code }
//   ⑦ audit                → 04 §8 rows (hashed assertion meta, 03 §6)
//   ⑧ respond
//
// Wire (03 §2, authority): JSON body `{ action, from, to, ts, payload }`,
// signed client assertion in the `client_assertion` header (the signature
// itself is the wire integrity; NO RFC 9421 / body signature, 03 §1).
import logger from '@overleaf/logger'
import Settings from '@overleaf/settings'

import { FederationPeer } from '../app/models/FederationPeer.mjs'
import { getS2sEndpoint } from '../oidf/ClientAssertionClient.mjs'
import { getOrigin } from '../oidf/leaf.mjs'
import { S2S_ERRORS, verifyS2sClientAssertion } from '../oidf/verify.mjs'
import { saltedLocalNameHash } from '../util/Anchor.mjs'
import { audit, AUDIT_TYPES } from '../util/Audit.mjs'
import { assertionMeta } from '../util/Redact.mjs'
import { checkRateLimit } from '../util/RateLimitStore.mjs'

import authorizeInvite from './actions/authorizeInvite.mjs'
import invited from './actions/invited.mjs'
import revoke from './actions/revoke.mjs'

// 03 §4: the three actions. (No `federate` action — trust is admin pin,
// 03 §7; no key-rotation S2S.)
const ACTIONS = {
  'authorize-invite': authorizeInvite,
  invited,
  revoke,
}

async function handleS2sRequest(req, res) {
  // ① federation-off (router always mounted; machine-readable refusal).
  if (!Settings.federation?.enabled) {
    return res
      .status(200)
      .json({ ok: false, code: S2S_ERRORS.FEDERATION_OFF, detail: 'federation disabled' })
  }

  // ② envelope sanity (03 §2 body): `from` (string), `to` (must be our
  //     origin), `action` (one of the three). Any shape error is
  //     reported as `peer-unknown` (no invalid-envelope code, HANDOFF).
  const body = req.body
  if (
    !body ||
    typeof body !== 'object' ||
    typeof body.from !== 'string' ||
    body.from.length === 0 ||
    typeof body.to !== 'string' ||
    body.to !== getOrigin()
  ) {
    return res
      .status(401)
      .json({
        ok: false,
        code: S2S_ERRORS.PEER_UNKNOWN,
        detail: 'malformed S2S envelope (from/to)',
      })
  }
  const action = body.action
  if (typeof action !== 'string' || !(action in ACTIONS)) {
    return res
      .status(401)
      .json({
        ok: false,
        code: S2S_ERRORS.PEER_UNKNOWN,
        detail: 'unknown action',
      })
  }

  const from = body.from
  // Header contract (03 §2): the client assertion is mandatory.
  const assertion = req.get('client_assertion') || ''
  if (!assertion) {
    return res
      .status(401)
      .json({
        ok: false,
        code: S2S_ERRORS.BAD_SIGNATURE,
        detail: 'missing client_assertion header',
      })
  }

  try {
    // ③ peer pre-lookup by the wire's `from` (decision: distinguish
    //    peer-unknown vs peer-not-approved BEFORE crypto; verify.mjs
    //    alone conflates the two into one refusal).
    const peer = await FederationPeer.findOne({ origin: from }).lean()
    if (!peer) {
      return res
        .status(401)
        .json({ ok: false, code: S2S_ERRORS.PEER_UNKNOWN, detail: `no peer for ${from}` })
    }
    if (peer.status !== 'approved') {
      return res
        .status(401)
        .json({
          ok: false,
          code: S2S_ERRORS.PEER_NOT_APPROVED,
          detail: `peer ${from} is not approved`,
        })
    }

    // ④ verify the client assertion (signature, iss/aud, exp, jti dedup)
    //    against the caller's PINNED key (03 §2; TOFU admin pin, 02 §3).
    const verification = await verifyS2sClientAssertion(assertion, from)
    if (!verification.ok) {
      return res
        .status(401)
        .json({ ok: false, code: verification.code, detail: verification.detail })
    }
    const { verified } = verification

    // ⑤ rate limit (03 §5): keyed (caller origin[, invitee localNameHash])
    //    — the hash is salted (util/Anchor); raw claims never hit Redis.
    const invitee = body.payload?.invitee
    let localNameHash
    if (
      invitee &&
      typeof invitee.localName === 'string' &&
      typeof invitee.origin === 'string'
    ) {
      localNameHash = saltedLocalNameHash(invitee.localName, invitee.origin)
    }
    const limited = await checkRateLimit(null, {
      action,
      callerOrigin: from,
      localNameHash,
    })
    if (!limited.allowed) {
      return res
        .status(429)
        .set('Allow-Retry-After', String(limited.retryAfterSeconds))
        .json({
          ok: false,
          code: S2S_ERRORS.RATE_LIMITED,
          detail: 'rate limit exceeded',
        })
    }

    // ⑥ dispatch (the action may write state — invite row on A only
    //    happens on A's side; here B writes the audit row and, for
    //    `revoke`, the peer status).
    const result = await ACTIONS[action]({ body, callerOrigin: from, peer })

    // ⑦ audit (04 §8, LOCKED): `invited` is a read-only preview — NO
    //    audit row.
    const assertionMetaObj = assertionMeta({
      iss: verified.clientId,
      aud: getS2sEndpoint(),
      jti: verified.jti,
    })
    if (action === 'authorize-invite') {
      await audit({
        operation: result.ok
          ? AUDIT_TYPES.inviteApproved
          : AUDIT_TYPES.inviteDenied,
        projectId: null,
        meta: {
          origin: from,
          localName: invitee?.localName ?? null,
          displayName: result.ok ? result.payload?.displayName ?? null : null,
          assertion: assertionMetaObj,
        },
        req,
      })
    } else if (action === 'revoke') {
      await audit({
        operation: AUDIT_TYPES.trustRevoked,
        projectId: null,
        meta: {
          origin: from,
          direction: 'inbound',
          assertion: assertionMetaObj,
        },
        req,
      })
    }

    // ⑧ respond. Business outcomes are 200 + in-band envelope (decision
    //    §1): the wire-level integrity already passed (steps ③④).
    return res.status(200).json(result)
  } catch (error) {
    // Inside the trusted path only: assertion verified + peer approved.
    // Never echo a stack to a peer (06 §6); log structured.
    logger.error({ error, action, from }, 'federation S2S: internal error')
    return res.status(500).json({ ok: false, code: 'internal-error', detail: 'internal error' })
  }
}

export default {
  apply(webRouter) {
    logger.debug({}, 'Init federation nonCsrfRouter (S2S)')
    // Always mounted (decision): peers get `federation-off` (200) even
    // while the feature flag is off, never a bare 404.
    webRouter.post('/federation/s2s', (req, res, next) => {
      handleS2sRequest(req, res).catch(error => {
        logger.error({ error }, 'federation S2S: unhandled')
        next(error)
      })
    })
  },
  // Exported for tests.
  _handleS2sRequest: handleS2sRequest,
  _actions: ACTIONS,
}
