// 2c: export sweep (plan 09 §3.3) — the FIRST real consumer of
// `killOutstandingCodes`' export side (04 §5).
//
// Called from BOTH revoke points (this instance is always B here — the
// home origin is B-origin, 04 §5):
//   - S2S `revoke` receipt (s2s/actions/revoke.mjs) — the peer admin
//     revoked the connection on THEIR side;
//   - admin `handleRevoke` (admin/FederationAdminController.mjs) —
//     the local admin revoked the peer row.
//
// Effect (best-effort — a failure warns + logs, NEVER fails/rolls
// back the revocation; the row transition + `revokeClientCodes` code
// sweep are independent on top of it, 03 §4.3):
//   1. every `federationExportGrants` row for that home origin →
//      `status: 'revoked'`
//   2. the `oauthAccessTokens` PATs those grants name (`patId`, the
//      `db.oauthAccessTokens` doc _id) → deleteMany
//
// Settings gate: `Settings.federation.export.sweepOnRevoke` (default
// true; off = v1 NO-OP preserved for migration safety, plan 09 §5).
// Independent of the peer `killOutstandingCodes` flag (that one gates
// the oidc-provider code sweep, 06 §178/§179).
//
// Audit (`federation_export_swept`, 04 §8 allow-list): meta
// { origin, scope } — redacted; the PAT value is never a field.
import logger from '@overleaf/logger'
import Settings from '@overleaf/settings'

import {
  db,
  ObjectId,
} from '../../../app/src/infrastructure/mongodb.mjs'
import { FederationExportGrant } from '../app/models/FederationExportGrant.mjs'
import { audit, AUDIT_TYPES } from '../util/Audit.mjs'

// 09 §3 scope marker (the token scope these grants minted). The delete
// is `scope`-guarded so a ledger row could never sweep a non-export
// PAT (dependency rule: the token is instance-local, 04 §4 deny-list).
export const EXPORT_SCOPE = 'federation:git_bridge'

/**
 * Sweep the export grant rows + their PATs for one home origin.
 *
 * @param {string} origin the home (B) origin string
 * @returns {Promise<number|null>} rows swept (or null on error)
 */
export async function sweepExportGrants(origin) {
  // Settings gate (default true): off = v1 behavior, the sweep is a
  // NO-OP (the PATs still expire on their own, 2a TTL clamp).
  if (
    Settings.federation?.export?.sweepOnRevoke === false
  ) {
    return null
  }
  if (typeof origin !== 'string' || origin.length === 0) {
    return null
  }
  try {
    // 1. ledger rows for the origin (lean, minimal projection).
    const rows = await FederationExportGrant.find({ homeOrigin: origin })
      .select('owner projectId patId')
      .lean()
    if (!rows || rows.length === 0) {
      return 0
    }
    // 2. PAT delete (scope-guarded: a ledger row can only name an
    //    export-scope token). Each delete is best-effort per-row.
    for (const row of rows) {
      try {
        await db.oauthAccessTokens.deleteOne({
          _id: new ObjectId(row.patId),
          scope: EXPORT_SCOPE,
        })
      } catch (error) {
        logger.error(
          { error, origin, patId: row.patId },
          'federation: export sweep: PAT delete failed',
        )
      }
    }
    // 3. ledger rows → revoked.
    await FederationExportGrant.updateMany(
      { homeOrigin: origin },
      { $set: { status: 'revoked' } },
    )
    // 4. audit (redacted: origin + constant scope).
    await audit({
      operation: AUDIT_TYPES.exportSwept,
      projectId: null,
      meta: { origin, scope: EXPORT_SCOPE },
      req: {},
    })
    return rows.length
  } catch (error) {
    logger.error({ error, origin }, 'federation: export sweep failed')
    return null
  }
}
