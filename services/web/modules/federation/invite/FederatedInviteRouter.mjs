// A-side invite router (plan 07 §P1: "invite/FederatedInviteRouter
// minimal: GET preview (invited-only, read) + POST authorize").
//
// Mounted on the CSR-applied `router` (webRouter, via index.mjs
// `router.apply` — session middleware precedes applyRouter, HANDOFF
// decision 10). Guard: `AuthenticationController.requireLogin()` (the
// owner must be logged in to invite).
//
// Path prefix `/api/federation/invite` (plan 05 §4.1).

import AuthenticationController from '../../../app/src/Features/Authentication/AuthenticationController.mjs'

import FederatedInviteController from './FederatedInviteController.mjs'

// `requireLogin()` returns a standard express middleware (checks
// `req.session` + sets `req.user`); applied per-route below. The router
// is applied at 3 mount points (L239/L286/L312 of app/src/router.mjs) —
// registration is idempotent and cheap.
export default {
  /**
   * @param {import('express').Router} webRouter
   * @param {import('express').Router} privateApiRouter
   * @param {import('express').Router} publicApiRouter
   */
  apply(webRouter) {
    const requireLogin = AuthenticationController.requireLogin()

    // ① soft preview (blur-verification, 03 §4.2).
    webRouter.get(
      '/api/federation/invite/preview',
      requireLogin,
      FederatedInviteController.handlePreview,
    )

    // ② invite authorize + OIDC grant initiation (01 §5 step 1–3).
    webRouter.post(
      '/api/federation/invite/authorize',
      requireLogin,
      FederatedInviteController.handleAuthorize,
    )
  },
}
