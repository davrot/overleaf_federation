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
import { FederationTrustAnchor } from '../app/models/FederationTrustAnchor.mjs'

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

/**
 * Institutional anchor set (02 §3, 07 §P3): every configured TA row
 * (`FederationTrustAnchor`), keyed by the TA's entity id. These are
 * additive to the peer-pin anchors — the runtime S2S path (depth-1, the
 * peer's own pinned key) does NOT consult this set; it feeds the
 * PIN-TIME institutional chain resolve and any future IA hierarchy
 * (02 §3: "scale-out is data, not code").
 *
 * @returns {Promise<Array<{ entityId: string, jwks: { keys: Array } }>>}
 */
export async function institutionalAnchorsFromDb() {
  const tAs = await FederationTrustAnchor.find({})
  return tAs.map((ta) => ({
    entityId: ta.entityId,
    jwks: ta.jwks,
  }))
}

/**
 * The instance's FULL trust-anchor set: approved peer pins + every
 * configured institutional TA. This is the map a (future) P3 explicit
 * `OidcProviderRole.initialize` consumes, and what the admin-pin chain
 * resolve (institutional path) verifies against.
 *
 * @returns a `Map<EntityId, { jwks: Jwks }>`.
 * */
export async function createTrustAnchorSetForInstance() {
  const explicit = await institutionalAnchorsFromDb()
  return await createTrustAnchorSetFromPeers(explicit)
}
