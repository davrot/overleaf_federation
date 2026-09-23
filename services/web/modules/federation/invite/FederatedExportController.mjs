// A-side federated export wizard (content-bridge 2b, plan 09 §4.1).
//
// The wizard is the A-side thin authenticated proxy (SESSION 11 LOCKED
// decision Q1): the user picks the peer B (approved outbound origin)
// and enters the B-side project id + an optional TTL; A re-signs a
// client assertion for B. B is the authority (plan 09 §2.1): owner
// must be a B-native account holding a LIVE consent grant to home
// A's client; B mints the short-lived PAT against B's own
// `oauthAccessTokens` (2a, dependency rule). A persists NOTHING
// (re-run = fresh S2S; B's export-grant ledger upsert is idempotent,
// 09 §1).
//
// PAT handling (plan 09 §2 risk note + SESSION 11 LOCKED decision Q2):
// the minted token is rendered INTO the single result view only (Pug
// auto-escapes; a `requireLogin()`-guarded render, NOT a JSON body
// field). It is NEVER written to the audit log (04 §8 allow-list:
// `{ origin, scope, gitUrl, reason }` only — `gitUrl` is audited per
// plan 09 §3.2's "audit { gitUrl and expiry if successful }", the
// git URL is not a secret; the PAT value is) and only appears in
// A-side logs redacted.
//
// Routes (plan 09 §4.1, mirror invite/FederatedInviteRouter.mjs):
//   GET  /federation/export  — wizard form (approved outbound peers,
//                              B project id, optional TTL)
//   POST /federation/export  — S2S to B, then the result view
//                              (instructions + the PAT, copy-able) or
//                              the form re-rendered with the refusal.
// Both ride `router` (the CSRF-applied web router, HANDOFF decision
// 10) under `requireLogin()` (plan 09 §4: "authenticated user").
//
// Wire (03 §2, LOCKED): `callPeer(peerOrigin, 'export-project',
// { projectId, expiresAt })` → B answers 200 + `{ ok, code?, payload? }`
// (business envelope); peer-level refusals (wire 401, rate-limit 429,
// redirect) surface as 502 here (matching the invite flow, HANDOFF
// SESSION 11 "S2S envelope" item).

import Path from 'node:path'
import logger from '@overleaf/logger'
import Settings from '@overleaf/settings'

import { FederationPeer } from '../app/models/FederationPeer.mjs'
import { callPeer } from './FederatedInviteController.mjs'
import { audit, AUDIT_TYPES } from '../util/Audit.mjs'

// 09 §3 scope constant (mirrors 2a's EXPORT_SCOPE — the git-bridge
// PAT scope `federation:git_bridge`; the 2c receive-pack 403 guard
// keys off the `federation:` prefix). Audit meta carries this string
// only, never a secret.
const SCOPE = 'federation:git_bridge'

// Default wizard TTL: 1 h (one transfer session). The user may
// shorten it (form, seconds); B clamps server-side: request ∩ grant
// remaining ∩ Settings maxExportTtlSeconds (09 §3.1/§5).
const DEFAULT_TTL_SECONDS = 3600
const MAX_TTL_SECONDS = Settings.federation?.export?.maxExportTtlSeconds || 86400

const EXPORT_VIEW = Path.resolve(__dirname, '../app/views/federation-export')
const EXPORT_RESULT_VIEW = Path.resolve(
  __dirname,
  '../app/views/federation-export-result',
)

function _ttlSeconds(raw) {
  const value = Number(raw)
  if (!Number.isFinite(value) || value <= 0) {
    return DEFAULT_TTL_SECONDS
  }
  return Math.max(1, Math.min(Math.floor(value), MAX_TTL_SECONDS))
}

// Approved outbound/both peers — the wizard dropdown (Q1: the user
// picks B by origin; direction outbound|both so A may call B, mirrors
// invite's `gateAnchor`). No `.lean()` — plain objects suffice; the
// test mock returns thenable arrays.
async function _approvedOutboundPeers() {
  try {
    const peers = await FederationPeer.find({
      status: 'approved',
      direction: { $in: ['outbound', 'both'] },
    }).sort({ origin: 1 })
    return peers.map(peer => ({
      origin: peer.origin,
      displayName: peer.displayName || peer.origin,
    }))
  } catch {
    return []
  }
}

// 04 §8 A-side audit (redacted). `reason` is the B-side code string
// (allow-list field), never a secret.
async function _audit(operation, origin, extra, req) {
  return await audit({
    operation,
    projectId: null,
    meta: { origin, scope: SCOPE, ...(extra || {}) },
    req,
  }).catch(error => {
    logger.warn({ error, operation }, 'federation: export audit failed (swallowed)')
  })
}

function _formLocals(req, res, opts) {
  const body = req.body || {}
  const query = req.query || {}
  return {
    title: 'Federation export',
    siteName: Settings.siteName,
    csrfToken: res.locals?.csrfToken,
    defaultTtlSeconds: DEFAULT_TTL_SECONDS,
    maxTtlSeconds: MAX_TTL_SECONDS,
    form: {
      origin: typeof body.origin === 'string' ? body.origin : query.origin || '',
      projectId:
        typeof body.projectId === 'string' ? body.projectId : query.projectId || '',
      expiresAt: body.expiresAt || query.expiresAt || '',
    },
    ...(opts || {}),
  }
}

/**
 * GET /federation/export
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 */
export async function handleExportFormGet(req, res) {
  const peers = await _approvedOutboundPeers()
  return res.render(EXPORT_VIEW, {
    ..._formLocals(req, res),
    peers,
    form: {},
  })
}

/**
 * POST /federation/export
 * Body: origin (peer origin FQDN), projectId (B-side project id),
 * expiresAt (optional seconds).
 *
 * ① local validation (400/403 form re-render, no wire)
 * ② S2S `export-project` (PeerRefusal → 502 + denied audit; business
 *    ok:false → 403 + denied audit)
 * ③ success → `federation_export_requested` audit (meta { origin,
 *    scope, gitUrl, expiresAt } — the PAT is NEVER in the audit,
 *    04 §8) + result view (PAT rendered once into the HTML)
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 */
export async function handleExport(req, res) {
  const peers = await _approvedOutboundPeers()
  const origin =
    typeof (req.body || {}).origin === 'string' ? req.body.origin : ''
  const peer = peers.find((p) => p.origin === origin)
  if (!peer) {
    // Peer row vanished / direction changed since the form rendered —
    // local refusal, no wire (mirrors invite gateAnchor 403).
    return res.status(403).render(EXPORT_VIEW, {
      ..._formLocals(req, res),
      peers,
      error: 'peer not approved for outbound calls',
    })
  }

  const projectId = (req.body || {}).projectId
  if (
    typeof projectId !== 'string' ||
    projectId.length === 0 ||
    projectId.length > 128
  ) {
    return res.status(400).render(EXPORT_VIEW, {
      ..._formLocals(req, res),
      peers,
      error: 'B-side project id is required',
    })
  }

  const ttl = _ttlSeconds(req.body.expiresAt)
  const expiresAt = Math.floor(Date.now() / 1000) + ttl

  // ② S2S wire (03 §2). `callPeer` (imported from the invite
  //    controller) throws on non-2xx (401 wire, 429 rate limit, 3xx
  //    redirect-refused); the business envelope is a 200 with
  //    { ok, code?, payload? }.
  let result
  try {
    result = await callPeer(peer.origin, 'export-project', {
      projectId,
      expiresAt,
    })
  } catch (error) {
    const reason = error?.code || 'peer-unreachable'
    logger.error(
      { peerOrigin: peer.origin, projectId, reason },
      'federation: export S2S refused',
    )
    await _audit(AUDIT_TYPES.exportDenied, peer.origin, { reason }, req)
    return res.status(502).render(EXPORT_VIEW, {
      ..._formLocals(req, res),
      peers,
      error: `export refused by home instance (${reason})`,
    })
  }

  if (result?.ok !== true || !result.payload) {
    const reason = result?.code || 'export-denied'
    logger.error(
      { peerOrigin: peer.origin, projectId, reason },
      'federation: export refused (business envelope)',
    )
    await _audit(AUDIT_TYPES.exportDenied, peer.origin, { reason }, req)
    return res.status(403).render(EXPORT_VIEW, {
      ..._formLocals(req, res),
      peers,
      error: `export refused: ${reason}`,
    })
  }

  // ③ success. `git_url` + expiry are NOT secrets (09 §3.2: audit
  //    them on success); the PAT value is (Q2).
  const gitUrl = result.payload.git_url
  const expiresAtUnix = result.payload.expires_at || expiresAt
  await _audit(AUDIT_TYPES.exportRequested, peer.origin, {
    gitUrl,
    expiresAt: expiresAtUnix,
  }, req)

  // The copyable clone command. git-bridge's PAT flow (git-modal.tsx
  // + GitBridgeAuthMiddleware `Bearer <PAT>` + B /oauth/token/info):
  // the PAT is a full git-bridge-scoped token. Embed it as Basic-auth
  // userinfo (git-CLI's native path, matching gitmodal's
  // `<protocol>//git@<host>/git/<projectId>` + "use your token" note)
  // and document the `Authorization: Bearer <PAT>` curl form for
  // smart-HTTP debugging.
  let cloneCommand = `git clone ${gitUrl}`
  try {
    const parsed = new URL(gitUrl)
    cloneCommand = `git clone https://git:${result.payload.pat}@${parsed.host}${parsed.pathname}`
  } catch {
    // Malformed peer git_url: keep the bare URL; the PAT field below
    // is still copy-able.
  }

  return res.render(EXPORT_RESULT_VIEW, {
    title: 'Federation export',
    siteName: Settings.siteName,
    csrfToken: res.locals?.csrfToken,
    project: {
      origin: peer.origin,
      projectId,
      gitUrl,
      pat: result.payload.pat,
      cloneCommand,
      expiresAt: new Date(expiresAtUnix * 1000).toISOString(),
      scope: SCOPE,
    },
  })
}

// House pattern (mirror invite/FederatedInviteController.mjs): a named
// const + default so `import FederatedExportController from './...'.mjs'`
// (FederatedExportRouter, index.mjs) resolves to the handler object, not
// `undefined` (named exports above stay for tests). The router is
// default-imported; a named-only module here is `undefined` at
// `router.apply` → app boot (Modules.applyRouter) would throw.
export const FederatedExportController = {
  handleExportFormGet,
  handleExport,
}

export default FederatedExportController
