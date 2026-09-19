// Admin router (P1, plan 07 §P1).
//
// Mounted under `/admin/federation` on the CSR webRouter via index.mjs
// `router.apply` — session middleware is active (session guard), CSRF is
// handled per-route (POSTs from the admin SPA carry the standard CSRF
// token).
//
// Guard (LOCKED, HANDOFF decision):
//   AuthorizationMiddleware.ensureUserIsSiteAdmin — this fork's site-admin
//   check (site_admin flag / project-level admin). CE has no
//   PermissionsService, so there is no "project admin" path here.
//
// Routes:
//   GET    /admin/federation/peers                          listPeers
//   POST   /admin/federation/peers                          pin (TOFU, 02 §3)
//   POST   /admin/federation/peers/:origin/approve          approvePeer
//   DELETE /admin/federation/peers/:origin                  denyPeer
//   POST   /admin/federation/peers/:origin/revoke           revokePeer
//   GET    /admin/federation/keys                           listKeys
//   POST   /admin/federation/keys/rotate                    rotateKey
//   GET    /admin/federation/audit                          auditList

import logger from '@overleaf/logger'
import AuthorizationMiddleware from '../../../app/src/Features/Authorization/AuthorizationMiddleware.mjs'

import FederatedAdminController from './FederationAdminController.mjs'

export default {
  /**
   * @param {import('express').Router} webRouter
   * @param {import('express').Router} _privateApiRouter
   * @param {import('express').Router} _publicApiRouter
   */
  apply(webRouter, _privateApiRouter, _publicApiRouter) {
    const adminGuard = (req, res, next) =>
      AuthorizationMiddleware.ensureUserIsSiteAdmin(req, res, next)

    // Peer listing (admin settings screen, 07 §P1).
    webRouter.get(
      '/admin/federation/peers',
      adminGuard,
      FederatedAdminController.listPeers,
    )

    // pin (TOFU, 02 §3): fetch leaf EC + pin active key → `pending` row.
    webRouter.post(
      '/admin/federation/peers',
      adminGuard,
      FederatedAdminController.handlePin,
    )

    // approve (04 §5 `pending → approved`).
    webRouter.post(
      '/admin/federation/peers/:origin/approve',
      adminGuard,
      FederatedAdminController.handleApprove,
    )

    // deny (delete the `pending` row — no trust anchor was established).
    webRouter.delete(
      '/admin/federation/peers/:origin',
      adminGuard,
      FederatedAdminController.handleDeny,
    )

    // revoke (03 §4.3, 04 §5: local immediate + best-effort S2S).
    webRouter.post(
      '/admin/federation/peers/:origin/revoke',
      adminGuard,
      FederatedAdminController.handleRevoke,
    )

    // Keys: metadata-only listing (02 §5 "public halves only").
    webRouter.get(
      '/admin/federation/keys',
      adminGuard,
      FederatedAdminController.listKeys,
    )

    // Key rotation (federation purpose; oidc = 501 in v1).
    webRouter.post(
      '/admin/federation/keys/rotate',
      adminGuard,
      FederatedAdminController.handleRotate,
    )

    // Audit readout (04 §8: `federated_*` / `federation_*` rows).
    webRouter.get(
      '/admin/federation/audit',
      adminGuard,
      FederatedAdminController.auditList,
    )

    logger.debug({}, 'federation: admin router mounted (8 routes)')
  },
}
