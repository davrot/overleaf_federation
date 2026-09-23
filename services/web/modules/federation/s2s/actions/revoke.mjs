// B-side trust revocation: revoke (03 §4.3).
//
// The wire's `revoke` means: "no longer accept inbound S2S from origin
// <A>" — i.e. B marks the peer ROW FOR THE SENDER (the row whose `origin`
// equals the wire's `from`) as `revoked`. `payload.origin` defaults to
// `'this-connection'` (the connection between us and you = the sender);
// an explicit origin equal to the caller is accepted (same row).
// Anything else is a contract error (peer-unknown).
//
// Receiver effects, v1 (03 §4.3, 04 §5):
//   - stops accepting S2S from that origin (subsequent requests 401
//     peer-not-approved after the pre-lookup, HANDOFF)
//   - blocks grant minting: the oidc-provider `clients[]` is
//     reconstructed from approved peers on provider (re)construction
//     (clients.mjs), so a revoked peer stops minting grants on the next
//     provider rebuild
//   - does NOT delete mirror rows
//   - does NOT kill existing receiver sessions (04 §5 v1 — 06 §178
//     "not over-cross": A's admin does not log out B's users on A;
//     the sweep only touches token docs minted for the revoked
//     client, never Session/Grant docs)
//   - `killOutstandingCodes` (peer toggle, default off — 04 §5, 06
//     §179 "optional, default off"): when true, a revoked transition
//     sweeps the peer's outstanding codes (adapter
//     `revokeClientCodes`, 04 §5 client index) — best-effort (a
//     Redis failure warns, the revocation itself is already local).
//
// Idempotent: a second `revoke` receipt (already-`revoked` row) still
// returns ok with no double side-effect (the updateOne match filters
// `status != 'revoked'`).
import { FederationPeer } from '../../app/models/FederationPeer.mjs'
import { _resetProviderMemo } from '../../oidc/createProvider.mjs'
import { federationClientId } from '../../oidc/clients.mjs'
import { revokeClientCodes } from '../../oidc/RedisOidcProviderAdapter.mjs'
import { sweepExportGrants } from '../../export/Sweep.mjs'
import logger from '@overleaf/logger'

import { S2S_ERRORS } from '../../oidf/verify.mjs'

export default async function revoke({ body, callerOrigin, peer }) {
  const origin = body?.payload?.origin ?? 'this-connection'

  // The revocation target is always the sender row; an explicit
  // `payload.origin` may only name the caller (otherwise we are being
  // asked to revoke a third party we cannot verify).
  if (origin !== 'this-connection' && origin !== callerOrigin) {
    return {
      ok: false,
      code: S2S_ERRORS.PEER_UNKNOWN,
      detail: `revoke target ${origin} does not match the caller`,
    }
  }

  // Mark the sender's row revoked. `status != 'revoked'` in the match
  // makes a double receipt a no-op write (still returns ok below).
  const res = await FederationPeer.updateOne(
    { origin: callerOrigin, status: { $ne: 'revoked' } },
    { status: 'revoked' },
  )

  // 05 §8.3 / 04 §5: a revoked peer must stop minting grants. The
  // oidc-provider `clients[]` is a memoized snapshot (clients.mjs), so
  // invalidate it on the transition — a real write (matchedCount / modified
  // Count) only, NOT on the idempotent double-receipt no-op path.
  if (res.modifiedCount) {
    _resetProviderMemo()
    // 06 §178/§179: the optional hostile-residual sweep, keyed on the
    // peer's own `killOutstandingCodes` toggle (default off). Best-effort
    // (never fails/rolls back the revocation — 03 §4.3 "optional";
    // the memo reset above already stops NEW minting, and single-use
    // 120 s codes are the bounded residual otherwise).
    if (peer && peer.killOutstandingCodes === true) {
      try {
        await revokeClientCodes(federationClientId(callerOrigin))
      } catch (error) {
        logger.warn({ error, origin: callerOrigin }, 'federation: code sweep after revoke failed')
      }
    }
    // content-bridge 2c (09 §3.3): the export side of `killOutstandingCodes` —
    // sweep the grant ledger + minted PATs for that home origin. Gated by
    // `Settings.federation.export.sweepOnRevoke` (default on; off = v1
    // NO-OP), INDEPENDENT of the `killOutstandingCodes` flag above (that
    // one gates the oidc-provider code sweep, 06 §179). Best-effort —
    // never fails/rolls back the revocation (03 §4.3 effects list).
    try {
      await sweepExportGrants(callerOrigin)
    } catch (error) {
      logger.warn(
        { error, origin: callerOrigin },
        'federation: export sweep after revoke failed'
      )
    }
  }

  return { ok: true, payload: {} }
}
