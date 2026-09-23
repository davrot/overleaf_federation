// Audit wrappers for the federation module (04 §8, 03 §6).
//
// overleaf-cep's existing `ProjectAuditLogEntry` model is reused
// UNCHANGED as the storage vehicle (04 §8); `operation` (a free-form
// String) carries the `federated_*` / `federation_*` machine type and the
// free-form `info` object carries the allow-listed `meta` (04 §8:
// `{ origin, localName?, displayName?, kid?, anchorThumbprint?,
//    registrationJtiHash?, direction }`).
//
// NEVER in `info` (04 §8, 06 §6): JWS raw, key material, password hashes,
// project bytes, any claim beyond `displayName`. The S2S assertion rides
// as `{ iss, aud, jtiHash }` (hashed, 03 §6) — built by
// `Redact.assertionMeta`, never the raw JWS.
//
// Machine types (04 §8, v2 list — the v1 `openid_session_issued` etc. are
// OIDC-layer and dropped):
//   project-scoped (require projectId):
//     federated_invite_approved / federated_invite_denied
//       (B-side, at `authorize-invite` receipt — one row per action)
//     federation_session_issued
//       (A-side, per successful grant → mirror resolution; projectId =
//        the project being opened)
//     federation_peer_trust_revoked
//       (either side, on `revoke`; old anchor thumbprint in meta)
//   peer-level (projectId: null):
//     federation_peer_registered
//       (per-direction pin; pairwise = admin pin wrote the row)
//     federation_peer_approved / federation_peer_revoked
//     federation_trust_anchor_pinned
//       (pairwise TOFU admin action; meta holds anchor thumbprint +
//        entity id, 02 §3)
//     federation_key_rotated
//       (per key-set; kid + old/new state, 02 §5)
//     federation_peer_denied
//       (pairwise TOFU: admin denied a pending registration)

import logger from '@overleaf/logger'
import { ProjectAuditLogEntry } from '../../../app/src/models/ProjectAuditLogEntry.mjs'

// 04 §8 meta allow-list (06 §8). `assertion` is the special S2S slot
// (hashed, 03 §6); everything else is one of the listed meta fields.
const META_FIELDS = [
  'origin',
  'localName',
  'displayName',
  'kid',
  'anchorThumbprint',
  'registrationJtiHash',
  'direction',
  'assertion',
  'reason',
  // content-bridge v2 (plan 09 §3): the scope marker on export audits
  // (the string 'federation:git_bridge' — a constant, never a secret).
  'scope',
]

function filterMeta(meta) {
  const out = {}
  if (meta && typeof meta === 'object') {
    for (const key of META_FIELDS) {
      if (meta[key] !== undefined) out[key] = meta[key]
    }
  }
  return out
}

/**
 * Write one federation audit row (04 §8). Fire-and-forget for the caller:
 * an audit write failure is logged, never thrown (06 §7: an audit bug must
 * not brick an S2S receipt or an admin action).
 *
 * @param {object} args
 * @param {string} args.operation  the `federated_*` / `federation_*` type
 * @param {string|null} [args.projectId]  project id or null (peer-level, 04 §8)
 * @param {object} [args.meta]  allow-listed meta (04 §8); unknown keys dropped
 * @param {object} [args.req]  incoming request (client ip, admin id)
 * @returns {Promise<object|null>}
 */
export async function audit({ operation, projectId = null, meta = {}, req = {} }) {
  const info = filterMeta(meta)
  const initiatorId =
    req && req.session && req.session.user
      ? req.session.user.userId
      : undefined
  const ipAddress = req && req.ip
  try {
    return await ProjectAuditLogEntry.create({
      projectId,
      operation,
      ...((initiatorId || ipAddress)
        ? {
            ...(initiatorId ? { initiatorId } : {}),
            ...(ipAddress ? { ipAddress } : {}),
          }
        : {}),
      info,
    }).then(row => row._id).catch(error => {
      logger.error({ error, operation }, 'federation: audit write failed')
      return null
    })
  } catch (error) {
    logger.error({ error, operation }, 'federation: audit write failed')
    return null
  }
}

export const AUDIT_TYPES = {
  // peer-level
  peerRegistered: 'federation_peer_registered',
  peerApproved: 'federation_peer_approved',
  peerRevoked: 'federation_peer_revoked',
  trustAnchorPinned: 'federation_trust_anchor_pinned',
  trustRevoked: 'federation_peer_trust_revoked',
  keyRotated: 'federation_key_rotated',
  peerDenied: 'federation_peer_denied',
  // project-scoped
  inviteApproved: 'federated_invite_approved',
  inviteDenied: 'federated_invite_denied',
  sessionIssued: 'federation_session_issued',
  // content-bridge v2 (plan 09 §3)
  exportGranted: 'federation_export_granted',
  exportDenied: 'federation_export_denied',
}
