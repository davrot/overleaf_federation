// A-side federated invite (01 §5 steps 1–3, plan 05 §4.1/§4.2).
//
// Two endpoints, both on the CSR-applied `router` (session + CSRF —
// they are the standard collaborator-invite form, NOT cross-origin
// machine calls):
//
//   GET  /api/federation/invite/preview?anchor=<localName>:<origin>
//        Owner blur-verification (03 §4.2): soft preview via the S2S
//        `invited` assertion — ALWAYS a business-200 result (not-found
//        is a valid preview, HANDOFF decision 5), 60 s caller-side Redis
//        cache (04 §6).
//
//   POST /api/federation/invite/authorize
//        Body { projectId, anchor, privileges }: local collaborator
//        check, S2S `authorize-invite` (03 §4.1 — B is the oracle),
//        upsert `ProjectInvite.federated` (04 §3), then PKCE initiation
//        (05 §3.1) + 302 to B's authorization endpoint.
//
// Peer direction gate (LOCKED): the peer row must be `status:
// 'approved'` AND `direction` one of `outbound|both` — we initiate
// toward them.
//
// The 302 to B's authorization endpoint cannot be followed by a
// `fetch()`-ing browser; the frontend renders a `<form method="POST">`
// or reads the Location and navigates (LOCKED: "302 redirect to B's
// OIDC auth URL").

import logger from '@overleaf/logger'

import { expressify } from '@overleaf/promise-utils'
import PrivilegeLevels from '../../../app/src/Features/Authorization/PrivilegeLevels.mjs'
import CollaboratorsGetter from '../../../app/src/Features/Collaborators/CollaboratorsGetter.mjs'
import { User } from '../../../app/src/models/User.mjs'
import { ProjectInvite } from '../../../app/src/models/ProjectInvite.mjs'

import { buildS2sRequest, getClientId } from '../oidf/ClientAssertionClient.mjs'
import { getOrigin } from '../oidf/leaf.mjs'
import { FederationPeer } from '../app/models/FederationPeer.mjs'
import { parseAnchor, validateAnchor, saltedLocalNameHash } from '../util/Anchor.mjs'
import { getCachedInvite, setCachedInvite } from '../util/RateLimitStore.mjs'
import {
  createPkceVerifier,
  signState,
  persistPkceState,
} from '../rp/State.mjs'

export const FEDERATED_PRIVILEGES = [
  PrivilegeLevels.READ_ONLY,
  PrivilegeLevels.READ_AND_WRITE,
  PrivilegeLevels.REVIEW,
]

// S2S budget: assert-level 401 / rate-limit 429 / business 200. An
// outbound S2S call must never hang the invite form — 10 s cap (06 §7).
const S2S_FETCH_TIMEOUT_MS = 10000

class PeerRefusal extends Error {
  constructor(code, detail) {
    super(detail || code)
    this.code = code
    this.detail = detail
  }
}

/**
 * One outbound S2S call (A → B, 03 §2). The wire contract (HANDOFF
 * decision 1): assertion-level refusals are 401; business refusals are
 * 200 + `{ ok: false, code }`; rate limit is 429.
 *
 * @returns {Promise<object>} the `{ ok, payload?|code? }` envelope
 */
export async function callPeer(peerOrigin, action, payload) {
  const { headers, body } = await buildS2sRequest(peerOrigin, action, payload)
  const resp = await fetch(`https://${peerOrigin}/federation/s2s`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(S2S_FETCH_TIMEOUT_MS),
  })
  if (resp.status === 429) {
    throw new PeerRefusal('rate-limited', 'peer rate limit exceeded')
  }
  const data = await resp.json().catch(() => ({}))
  if (!resp.ok) {
    if (!data.code) data.code = `wire-${resp.status}`
    throw new PeerRefusal(data.code, data.detail || `wire ${resp.status}`)
  }
  return data
}

// Shared: anchor parse + approved-peer + outbound-direction gate.
async function gateAnchor(anchorStr) {
  const anchor = parseAnchor(anchorStr)
  if (!anchor) {
    return { error: 400, message: 'invalid anchor: expected "<localName>:<origin>"' }
  }
  try {
    validateAnchor(anchor)
  } catch (error) {
    return { error: 400, message: error.message }
  }
  const peer = await FederationPeer.findOne({ origin: anchor.origin }).lean()
  if (!peer || peer.status !== 'approved') {
    return { error: 404, message: 'peer not approved for this origin' }
  }
  if (peer.direction !== 'outbound' && peer.direction !== 'both') {
    return { error: 403, message: `peer ${peer.origin} is not approved for outbound invites` }
  }
  return { peer, anchor }
}

/**
 * GET /api/federation/invite/preview?anchor=<localName>:<origin>
 * Soft preview: `{ approved, displayName }`. `approved: false` when the
 * invitee has no account on B (a valid preview result — the owner may
 * still save with "defer verification", 05 §4.1).
 */
async function _handlePreview(req, res) {
  const anchorStr = req.query?.anchor
  if (typeof anchorStr !== 'string' || anchorStr.length === 0) {
    return res.status(400).json({ message: 'anchor required' })
  }
  const gate = await gateAnchor(anchorStr)
  if (gate.error) {
    return res.status(gate.error).json({ message: gate.message })
  }
  const { peer, anchor } = gate

  const localNameHash = saltedLocalNameHash(anchor.localName, anchor.origin)
  const cached = await getCachedInvite(null, peer.origin, localNameHash)
  if (cached) {
    return res.json(cached)
  }

  try {
    const result = await callPeer(peer.origin, 'invited', {
      invitee: { origin: peer.origin, localName: anchor.localName, display: anchorStr },
    })
    const payload = result.ok
      ? {
          approved: result.payload?.approved ?? false,
          displayName: result.payload?.displayName ?? null,
        }
      : { approved: false, displayName: null }
    await setCachedInvite(null, peer.origin, localNameHash, payload)
    return res.json(payload)
  } catch (error) {
    // A preview failure is NOT a refusal (05 §4.1) — the invite is
    // savable without it; degrade to `approved: false`.
    logger.warn({ error, peerOrigin: peer.origin }, 'federation: invited preview failed')
    return res.json({ approved: false, displayName: null, degraded: true })
  }
}

/**
 * POST /api/federation/invite/authorize
 * Body { projectId, anchor, privileges }.
 * ① local collaborator check (01 §5 step 1a), ② S2S `authorize-invite`,
 * ③ upsert `ProjectInvite.federated` (04 §3), ④ PKCE initiation + 302
 * to B's authorization URL (01 §5 step 3).
 *
 * `req.user` is set by `AuthenticationController.requireLogin()` in the
 * router guard.
 */
async function _handleAuthorize(req, res) {
  const body = req.body || {}
  const projectId = body.projectId
  const anchorStr = body.anchor
  const privileges = body.privileges
  if (
    typeof projectId !== 'string' ||
    projectId.length === 0 ||
    typeof anchorStr !== 'string' ||
    anchorStr.length === 0 ||
    typeof privileges !== 'string' ||
    !FEDERATED_PRIVILEGES.includes(privileges)
  ) {
    return res
      .status(400)
      .json({ message: 'projectId, anchor and privileges (readOnly|readAndWrite|review) required' })
  }

  // ① local collaborator check (01 §5 step 1a). The owner resolves
  //    through ProjectAccess as privilege `owner`, so this alone covers
  //    owner + collaborator; a non-collaborator is 403.
  const viewerId = req.user?._id
  let level
  try {
    level = await CollaboratorsGetter.promises.getMemberIdPrivilegeLevel(viewerId, projectId)
  } catch {
    level = PrivilegeLevels.NONE
  }
  if (level === PrivilegeLevels.NONE) {
    return res.status(403).json({ message: 'viewer does not have collaborator permission' })
  }
  const ownerRow = await User.findOne({
    _id: await CollaboratorsGetter.promises.getProjectOwnerId(projectId),
  })
  const ownerLocalName = ownerRow?.email || 'owner'
  const ownerDisplay =
    (ownerRow?.first_name ? ownerRow.first_name + ' ' : '') + (ownerRow?.last_name || '')

  const gate = await gateAnchor(anchorStr)
  if (gate.error) {
    return res.status(gate.error).json({ message: gate.message })
  }
  const { peer, anchor } = gate

  // ② S2S authorize-invite (03 §4.1). B (oracle) answers:
  //    200 { ok:true,  payload: { approved: true, displayName, institution } }
  //    200 { ok:false, code: 'invitee-unknown'|'invitee-disabled'|... , detail }
  //    401 { code: ... } (wire level) · 429 (rate limit)
  let result
  try {
    result = await callPeer(peer.origin, 'authorize-invite', {
      invitee: { origin: peer.origin, localName: anchor.localName, display: anchorStr },
      project: {
        ref: projectId,
        ownerLocalName,
        ownerDisplay: ownerDisplay || ownerLocalName,
        privileges: [privileges],
      },
    })
  } catch (error) {
    logger.error(
      { peerError: error, peerOrigin: peer.origin, projectId },
      'federation: authorize-invite S2S refused',
    )
    return res.status(502).json({ message: 'peer refused or unreachable' })
  }
  if (result.ok !== true || result.payload?.approved !== true) {
    return res.status(403).json({
      message: 'invitee refused or not found on home instance',
      code: result?.code || 'invitee-unknown',
    })
  }
  const invitee = result.payload

  // ③ upsert the federated invite (04 §3). Per (projectId, anchor) the
  //    row is refreshable: a re-invite re-authorizes.
  const localNameHash = saltedLocalNameHash(anchor.localName, anchor.origin)
  await ProjectInvite.findOneAndUpdate(
    { projectId, 'federated.origin': anchor.origin, 'federated.localName': anchor.localName },
    {
      projectId,
      'federated.origin': anchor.origin,
      'federated.localName': anchor.localName,
      'federated.localNameHash': localNameHash,
      'federated.invitedBy': viewerId,
      'federated.homeDisplayName': invitee.displayName || null,
      'federated.authorized': true,
      'federated.authorizedAt': new Date(),
      'federated.status': 'active',
    },
    { upsert: true, new: true, setDefaultsOnInsert: false },
  )

  // ④ PKCE initiation (05 §3.1): public client + S256 challenge; `state`
  //    is the HMAC-signed intent (never a raw secret, 05 §3.1). Redis-first
  //    (TTL 120 s) + session backup survive cookie expiry across tabs.
  const { verifier, challenge, nonce } = createPkceVerifier()
  const intent = {
    origin: peer.origin,
    localName: anchor.localName,
    projectId,
    privileges,
    nonce,
    url: `/project/${projectId}`,
  }
  const state = signState(intent)
  await persistPkceState(
    req.session,
    { state, verifier, origin: peer.origin, intent },
    null,
  )

  // 302 to B's authorization endpoint (LOCKED). Public client, no secret.
  const redirectUri = `https://${getOrigin()}/federation/oidc/rp/callback`
  const authUrl =
    `https://${peer.origin}/federation/oidc/auth` +
    `?response_type=code` +
    `&client_id=${encodeURIComponent(getClientId())}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&scope=openid` +
    `&state=${encodeURIComponent(state)}` +
    `&nonce=${encodeURIComponent(nonce)}` +
    `&code_challenge=${encodeURIComponent(challenge)}` +
    `&code_challenge_method=S256`

  return res.redirect(authUrl)
}

export const FederatedInviteController = {
  handlePreview: expressify(_handlePreview),
  handleAuthorize: expressify(_handleAuthorize),
}

export default FederatedInviteController
