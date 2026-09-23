// A-side federated export router (content-bridge 2b, plan 09 §4.1).
//
// Mounted on the CSR-applied `router` (webRouter, via index.mjs
// `router.apply` — session middleware precedes applyRouter, HANDOFF
// decision 10). Guard: `AuthenticationController.requireLogin()`
// (plan 09 §4: "authenticated user on A who is a collaborator of the
// B-side mirror project" — the mirror check is the wizard form; the
// collaborator gate is enforced by B via the live consent grant, 09
// §2.1).
//
// Path prefix `/federation/export` (plan 09 §4.1). The wizard is a
// plain HTML form flow (no fetch/JS, so `csrfToken` rides a hidden
// `_csrf` field, 05 §2).

import AuthenticationController from '../../../app/src/Features/Authentication/AuthenticationController.mjs'
import FederatedExportController from './FederatedExportController.mjs'

export default {
  /**
   * @param {import('express').Router} webRouter
   * @param {import('express').Router} _privateApiRouter
   * @param {import('express').Router} _publicApiRouter
   */
  apply(webRouter) {
    const requireLogin = AuthenticationController.requireLogin()

    // ① wizard form (approved outbound peers + B project id + TTL).
    webRouter.get(
      '/federation/export',
      requireLogin,
      FederatedExportController.handleExportFormGet,
    )

    // ② export (S2S to B; result view renders the PAT, 2b Q2).
    webRouter.post(
      '/federation/export',
      requireLogin,
      FederatedExportController.handleExport,
    )
  },
}
