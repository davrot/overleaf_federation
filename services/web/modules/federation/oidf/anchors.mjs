// Trust anchors (02 §3, 07 §4).
//
// Pairwise (P0–P2): the ONLY anchors are APPROVED peers, each keyed by
// the peer's OWN entity id (02 §3: "trustAnchors = { https://peer-a.example:
// {jwks} }" — peer is its own trust anchor, depth-1). Admin pin = the
// `anchorJwks` we stored on approval (TOFU, 02 §3), fetched from the
// peer's leaf ONCE (02 §2). Institutional (P3) adds the institutional
// anchor (05 §9) — out of scope for the anchor-set builder in P0–P2, but
// `explicitAnchors` is the slot for it.
import { createTrustAnchorSet } from '@oidfed/core'

import logger from '@overleaf/logger'

import { FederationPeer } from '../app/models/FederationPeer.mjs'

/**
 * Build the trust-anchor set from APPROVED peers (02 §3 depth-1 case:
 * a leaf EC with no `authority_hints` whose entityId is a configured
 * anchor yields chain `[leafEC]`, `trustAnchorId = entityId`).
 *
 * @param {Array<{ entityId: string, jwks: { keys: Array } }>} [explicitAnchors]
 *   institutional / non-peer anchors (P3 slot, 05 §9); additive, 04 §2.
 * @returns a `Map<EntityId, { jwks: Jwks }>`.
 * */
export async function createTrustAnchorSetFromPeers(explicitAnchors = []) {
  const approved = await FederationPeer.find({ status: 'approved' }).sort({ federatedAt: 1 }).exec()
  const rows = []

  for (const peer of approved) {
    // anchorJwks is a JSON-serialized JWKS doc (04 §2: "anchorJwks +
    // status: approved are the fields... " the anchor we verify against).
    if (!peer.anchorJwks) {
      // Approved peer with no pinned JWK is an operator error — log,
      // skip (never fall back to an unapproved/fetched key: TOFU, 02 §3).
      logger.warn({ origin: peer.origin }, 'federation: approved peer has no anchorJwks')
      continue
    }
    let jwks
    try {
      jwks = JSON.parse(peer.anchorJwks)
    } catch (error) {
      logger.error({ error, origin: peer.origin }, 'federation: bad anchorJwks JSON')
      continue
    }
    // Normalize to `{ keys: [...] }` (02 §3 anchor shape).
    if (!jwks || !Array.isArray(jwks.keys)) {
      jwks = { keys: [jwks && jwks.keys ? jwks.keys[0] : jwks] }
    }
    rows.push({ entityId: peer.entityId, jwks })
  }

  for (const anchor of explicitAnchors) {
    rows.push({ entityId: anchor.entityId, jwks: anchor.jwks })
  }

  return createTrustAnchorSet(rows)
}
