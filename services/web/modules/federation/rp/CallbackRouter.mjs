// A-side grant callback (05 §3.3, 01 §5 steps 6–9).
//
// B 302s the visitor back to `GET /federation/oidc/rp/callback?code&state`
// (the `redirect_uri` registered at initiation).
//
// Refusal path (LOCKED): every pre-302 failure answers 401
// `invalid grant request` (or its OIDC-spec analog) — no mirror
// resolution, no grant, no session written, no 302 (05 §3.3 step 4:
// "if `code` cannot be exchanged → abort, no session, no 302"). A forged
// or replayed `state` fails the HMAC, and the OIDC `nonce` binds the
// id_token to the intent (05 §3.1).
//
// Success path: mirror row resolved-or-created (04 §1), grant via
// `CollaboratorsHandler.addUserIdToProject` (this fork's grant
// mechanism — the plan's `PermissionsService` does not exist here),
// mirror session minted by setting `req.session.user` directly (LOCKED
// decision 11 — no passport; mirror rows have `email: ''` and cannot go
// through `serializeUser`), 302 to the invite's project URL (05 §3.3 step 5).
//
// The `code` is a grant (04 §8) — it is never written to audit (the audit
// row carries only the verified `(origin, localName, displayName)` tuple).
//
// Mounted as nonCsrfRouter on webRouter, BEFORE the terminal provider
// catch-all (index.mjs) so oidc-provider's terminal handler never sees
// the callback path.

import logger from '@overleaf/logger'
import crypto from 'node:crypto'
import { User } from '../../../app/src/models/User.mjs'
import CollaboratorsHandler from '../../../app/src/Features/Collaborators/CollaboratorsHandler.mjs'
import PrivilegeLevels from '../../../app/src/Features/Authorization/PrivilegeLevels.mjs'
import UserSessionsManager from '../../../app/src/Features/User/UserSessionsManager.mjs'

import { audit, AUDIT_TYPES } from '../util/Audit.mjs'
import { verifySignedState, consumePkceState } from './State.mjs'
import { exchange } from './CodeExchange.mjs'

// Light user for the mirror session (mirrors `serializeUser`'s shape
// minus `email`/overleaf-v1 id; mirror rows have `email: ''` and no
// `overleaf.id` subdoc, and `serializeUser` refuses empty email — so the
// mirror shape is built here directly, LOCKED decision 11).
function buildSessionUser(mirror, claims) {
  const displayName = claims.displayName || mirror.email
  const [firstName = ''] = displayName.split(' ')
  return {
    _id: mirror._id,
    first_name: mirror.first_name || firstName,
    last_name: mirror.last_name || '',
    email: mirror.email, // '' for mirrors (04 §1)
    referal_id: mirror.referal_id || null,
    session_created: new Date().toISOString(),
    must_reconfirm: mirror.must_reconfirm ?? false,
    analyticsId: mirror.analyticsId || mirror._id,
    labsProgram: mirror.labsProgram ?? false,
    ip_address: null,
    federation: {
      origin: mirror.federation.origin,
      localName: mirror.federation.localName,
    },
  }
}

async function handleCallback(req, res) {
  // OIDC spec: a denied interaction redirects back WITH `error` instead
  // of `code` — that is an invalid grant (05 §3.3 step 4 refusal).
  if (req.query.error !== undefined) {
    return res.status(401).json({ message: 'invalid grant request' })
  }

  const { code, state } = req.query
  if (!code || !state) {
    return res.status(401).json({ message: 'invalid grant request' })
  }

  // ① single-use PKCE read (05 §3.3 step 1): Redis first (TTL 120 s is the
  //    single-use window), session slot as backup. `consumePkceState` does
  //    the Redis read+DELETE and clears the session slot in one pass.
  const session = req.session
  const rec = await consumePkceState(session, state)
  session.federationRp = null
  if (!rec || !rec.verifier) {
    // state not seen (or consumed) → forged / replayed.
    return res.status(401).json({ message: 'invalid grant request' })
  }

  // ② signed-state verify (HMAC, 05 §3.1). The intent is trust: it is
  //    what binds the code exchange to (origin, localName, projectId,
  //    privileges).
  const intent = verifySignedState(state)
  if (!intent || !intent.origin || !intent.localName || !intent.projectId) {
    return res.status(401).json({ message: 'invalid grant request' })
  }

  // ③ code exchange + id_token verification (05 §3.3 step 3).
  let claims
  try {
    claims = await exchange(intent.origin, {
      code,
      codeVerifier: rec.verifier,
      intent,
    })
  } catch (error) {
    logger.error({ error, origin: intent.origin }, 'federation: code exchange failed')
    return res.status(401).json({ message: 'invalid grant request' })
  }

  // ④ mirror row resolve-or-create (04 §1). `hashedPassword` is a
  //    consequence: never set. `email: ''` (mirrors are unreachable by
  //    email lookup — 04 §1, 06 §3).
  const origin = intent.origin
  const localName = intent.localName
  let mirror = await User.findOne({
    'federation.origin': origin,
    'federation.localName': localName,
  })
  if (!mirror) {
    const displayName = claims.displayName || localName
    const firstName = displayName.split(' ')[0]
    mirror = await User.create({
      email: '',
      first_name: firstName,
      last_name: '',
      institution: claims.institution || '',
      analyticsId: crypto.randomUUID(),
      federation: {
        origin,
        localName,
        federatedAt: new Date(),
      },
    })
  }

  // ⑤ grant (01 §5 step 9): the mirror becomes a collaborator at the
  //    invite's privilege ceiling. `addUserIdToProject(projectId,
  //    addingUserId, userId, privilegeLevel)` — this fork's grant path
  //    (the plan's `PermissionsService` is CE-absent). `addingUserId =
  //    null` so no ContactManager edge or TPDS flush is triggered.
  const privilege = intent.privileges ?? PrivilegeLevels.READ_AND_WRITE
  if (privilege) {
    try {
      await CollaboratorsHandler.promises.addUserIdToProject(
        intent.projectId,
        null,
        mirror._id,
        privilege,
      )
    } catch (error) {
      logger.error({ error, projectId: intent.projectId }, 'federation: grant failed')
      return res.status(401).json({ message: 'invalid grant request' })
    }
  }

  // ⑥ mirror session (01 §5 step 8): `req.session.user` — the standard
  //    express session the rest of the app reads via `SessionManager`.
  //    NOT passport: mirror rows have no email to serialize (LOCKED 11).
  req.session.user = buildSessionUser(mirror, claims)

  // ⑦ audit (04 §8 row: federation_session_issued). `code` is never in
  //    the row — only the verified anchor tuple.
  await audit({
    operation: AUDIT_TYPES.sessionIssued,
    projectId: intent.projectId,
    meta: {
      origin,
      localName,
      displayName: claims.displayName ?? null,
    },
    req,
  })

  // ⑧ 302 to the project URL (05 §3.3 step 5). Open-redirect hardening:
  //    `intent.url` is owner-set (HMAC-signed state), but the redirect target
  //    must still be a root-relative path on OUR host - absolute URLs,
  //    scheme-relative, and backslash forms are refused (browsers normalize
  //    a leading backslash to a slash, re-forming an absolute URL - the
  //    classic open-redirect trick), so fall back to '/' on any non-path.
  let target = intent.url || '/'
  if (target !== '/' && (target[0] !== '/' || target[1] === '/' || target.includes(String.fromCharCode(92)))) {
    target = '/'
  }
  UserSessionsManager.promises
    .trackSession(mirror, req.sessionID, {})
    .catch(err => logger.error({ err }, 'federation: trackSession failed'))
  return res.redirect(target)
}

/**
 * Mount `GET /federation/oidc/rp/callback` on webRouter.
 *
 * Non-csrf (it is a browser redirect landing, not a form post — the
 * same posture as the SAML login redirect), applied before the terminal
 * provider mount (index.mjs).
 *
 * @param {import('express').Router} webRouter
 */
export function apply(webRouter) {
  webRouter.get('/federation/oidc/rp/callback', (req, res, next) => {
    handleCallback(req, res).catch(error => {
      logger.error({ error }, 'federation: rp callback failed')
      next(error)
    })
  })
}

export default { apply, handleCallback }
