// Partner-side project-creation gate (01 §3.4, 05 §7
// `federation.allowFederatedProjectCreate`, default OFF).
//
// "Not over-cross": a mirror user on a partner machine may create a
// project ONLY when the PARTNER admin enabled the flag — the partner
// admin decides what happens on THEIR machine. Edit rights are
// unrelated: project `Permissions` authorize editing once a grant
// has been minted (01 §3.4); creation is the gate here.
//
// Mount: WebModule `router` hook (this module's `index.mjs`
// `router.apply`). `Router.initialize` invokes `Modules.applyRouter`
// three times against the same `webRouter` (router.mjs: 239, 286, 312)
// with `POST /project/new` (ProjectController.newProject) registered
// later in the same pass — so the guard precedes the core handler.
//
// Session: `webRouter.use(express().session)` (Server.mjs) mounts
// BEFORE `Router.initialize` (Server.mjs:374), so `req.session` is
// populated in the guard and `SessionManager.getSessionUser(req.session)`
// sees `session.user` (the federated mirror doc, 04 §1: `federation`
// subdoc presence is the mirror mark — no `kind` field exists). The
// guard must call `next()` for every request it does not refuse (the
// core `newProject` is the downstream consumer).

import Settings from '@overleaf/settings'

import SessionManager from '../../../app/src/Features/Authentication/SessionManager.mjs'

function isMirror(sessionUser) {
  // Mirror mark (04 §1): PRESENCE of the `federation` subdocument
  // (origin = home FQDN, localName = home login name).
  return !!(
    sessionUser &&
    sessionUser.federation &&
    sessionUser.federation.origin
  )
}

// The gate itself. Exported for direct unit testing (no router
// mount required).
export function guardProjectCreation(req, res, next) {
  // Flag ON: mirrors create freely — hand off, express no opinion.
  if (Settings.federation?.allowFederatedProjectCreate) {
    return next()
  }
  let sessionUser
  try {
    sessionUser = SessionManager.getSessionUser(req.session)
  } catch {
    // The guard is NOT a session check: if the session middleware
    // blew up, `AuthenticationController.requireLogin()` (downstream)
    // will refuse; pass this request through for it to own.
    return next()
  }
  if (!isMirror(sessionUser)) {
    return next()
  }
  // Refuse: mirror + flag OFF (01 §3.4 default). `error` is
  // human-readable (surfaces in overleaf-cep error JSON); `code`
  // machine-identifies the refusal (admin UI / audit).
  return res.status(403).json({
    error:
      'This federated identity is not allowed to create projects on this instance',
    code: 'federated-project-create-disabled',
  })
}

// Module-scope mount flag — `Modules.applyRouter` is invoked three
// times per boot (the three apply call-sites above); the guard
// mounts exactly once. Exported for tests (unit files re-mount with
// fresh fake routers).
let mounted = false

export default function applyGuard(webRouter) {
  if (mounted) return
  mounted = true
  webRouter.post('/project/new', guardProjectCreation)
}

// Test-only.
export function _resetGuardForTest() {
  mounted = false
}
