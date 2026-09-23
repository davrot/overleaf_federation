// B-side interaction bridge: login + consent, plan 05 §8.3.
//
// The provider's own interaction forms (devInteractions) are DISABLED; this
// bridge is the production interaction UI. It lives on the WEB router at
//
//   GET  /federation/oidc/interact/:uid                 302 to B /login (not logged in)
//                                                    render consent form (logged in)
//   POST /federation/oidc/interact/:uid/consent          grant → 303 to /resume
//   POST /federation/oidc/interact/:uid/deny             deny  → 303 to /resume (access_denied)
//
// Flow (plan 01 §3 step 4, "two-step, same-screen UX"):
//
//   A issues GET https://<B>/federation/oidc/auth?client_id=urn:overleaf-
//   federation:client:<A-origin>&scope=openid&response_type=code&<PKCE>
//
//   (B, oidc-provider) no session → create Interaction(uid) →
//   set op_interaction:<short>=uid cookie → 302 to
//     interactions.url(ctx, interaction) = https://<B>/federation/oidc/interact/<uid>
//
//   (B, this bridge) if visitor not logged in on B: set postLoginRedirect
//   and 302 to B /login.  Browser logs in (overleaf session cookie is
//   independent of op_* cookies) and lands back here on the bridge URL.
//
//   (B, this bridge) now B is logged in:
//     prompt.login  → auto: provider.interactionFinished(req,res,
//                      {login:{accountId: <User._id>}}, {mergeWithLastSubmission:true})
//     prompt.consent→ if an existing Grant covers (accountId, client_id,
//                      openid-claims): interactionFinished({...lastSubmission,
//                      consent:{grantId}}); else render consent.pug. On
//                      form submit: build Grant, addOIDCScope(openid),
//                      addOIDCClaims(...), grant.save(), interactionFinished
//                      ({lastSubmission..., consent:{grantId}},
//                      {mergeWithLastSubmission:true})
//     deny          → interactionFinished({error:'access_denied'},
//                      {mergeWithLastSubmission:false})
//
//   (B, oidc-provider) /federation/oidc/resume/<uid>  → session with
//     accountId → issue code → 302 to A's redirect_uri.

import path from 'node:path'
import logger from '@overleaf/logger'
import SessionManager from '../../../app/src/Features/Authentication/SessionManager.mjs'
import RedisWrapper from '../../../app/src/infrastructure/RedisWrapper.mjs'

import { getOidcProvider } from './createProvider.mjs'
import { findByAccountAndClient } from './RedisOidcProviderAdapter.mjs'

const __dirname = new URL('.', import.meta.url).pathname
const CONSENT_VIEW = path.resolve(__dirname, '../app/views/consent.pug')

/**
 * Mount the bridge on the given express router.
 *
 * MUST be mounted BEFORE `webRouter.use('/federation/oidc', provider.callback())`
 * (plan 05 §1.1 MOUNT ORDER) so that GETs for /federation/oidc/interact/:uid
 * never reach the oidc-provider router (its catch-all 404).
 *
 * @param {import('express').Router} webRouter
 */
export function mountBridge(webRouter) {
  const base = '/federation/oidc/interact'
  webRouter.get(`${base}/:uid`, (req, res, next) => {
    getOidcProvider()
      .then(provider => handleInteractGet(provider, req, res))
      .catch(next)
      .then(() => {})
  })
  webRouter.post(`${base}/:uid/consent`, (req, res, next) => {
    getOidcProvider()
      .then(provider => handleConsent(provider, req, res))
      .catch(next)
      .then(() => {})
  })
  webRouter.post(`${base}/:uid/deny`, (req, res, next) => {
    getOidcProvider()
      .then(provider => handleDeny(provider, req, res))
      .catch(next)
      .then(() => {})
  })
}

async function handleInteractGet(provider, req, res) {
  const userId = SessionManager.getLoggedInUserId(req.session)
  if (!userId) {
    // 302 to B /login with post-login redirect back here.
    const returnTo = req.originalUrl
    try {
      const { default: AuthenticationController } = await import(
        '../../../app/src/Features/Authentication/AuthenticationController.mjs'
      )
      AuthenticationController.setRedirectInSession(req, returnTo)
    } catch (err) {
      logger.error(`bridge: setRedirectInSession: ${err.message}`)
    }
    return res.redirect('/login')
  }

  const interaction = await provider.interactionDetails(req, res)
  const { prompt, params } = interaction

  if (prompt.name === 'login') {
    return finishLogin(provider, req, res, interaction)
  }
  if (prompt.name === 'consent') {
    const grant = await findExistingGrant(provider, userId, params.client_id)
    if (grant) {
      // Silent: Grant already covers (accountId, client, openid).
      await provider.interactionFinished(req, res, {
        ...(interaction.lastSubmission && !('error' in (interaction.lastSubmission || {}))
          ? interaction.lastSubmission
          : {}),
        consent: { grantId: await grant.save() },
      })
      return
    }
    return renderConsent(provider, req, res, interaction)
  }
  return res.status(501).send(`interaction prompt ${prompt.name} not supported`)
}

async function finishLogin(provider, req, res, interaction) {
  const userId = SessionManager.getLoggedInUserId(req.session)
  if (!userId) {
    return res.status(401).send('no logged-in user on B')
  }
  // B-side login, resolved against B's User._id.
  const result = {
    ...(interaction.lastSubmission && !('error' in (interaction.lastSubmission || {}))
      ? interaction.lastSubmission
      : {}),
    login: { accountId: String(userId), ts: Math.floor(Date.now() / 1000) },
  }
  return provider.interactionFinished(req, res, result, {
    mergeWithLastSubmission: true,
  })
}

async function handleConsent(provider, req, res) {
  const userId = SessionManager.getLoggedInUserId(req.session)
  if (!userId) return res.status(401).send('no logged-in user on B')

  const interaction = await provider.interactionDetails(req, res)
  const { prompt, params, lastSubmission } = interaction

  const grant = new provider.Grant({
    accountId: String(userId),
    clientId: params.client_id,
  })
  if (prompt.details?.missingOIDCScope) {
    // scope is `openid`; merge missing scope into the grant.
    grant.addOIDCScope(prompt.details.missingOIDCScope.join(' '))
  }
  if (prompt.details?.missingOIDCClaims) {
    grant.addOIDCClaims(prompt.details.missingOIDCClaims)
  }
  const grantId = await grant.save()
  const result = {
    ...(lastSubmission && !('error' in (lastSubmission || {})) ? lastSubmission : {}),
    consent: { grantId },
  }
  return provider.interactionFinished(req, res, result, {
    mergeWithLastSubmission: true,
  })
}

async function handleDeny(provider, req, res) {
  const interaction = await provider.interactionDetails(req, res)
  return provider.interactionFinished(req, res, {
    ...interaction.lastSubmission,
    error: 'access_denied',
    error_description: 'End-User denied consent',
  }, { mergeWithLastSubmission: true })
}

async function renderConsent(provider, req, res, interaction) {
  const { prompt, params } = interaction
  // The grant for this (userId, client) — if it exists and covers the
  // requested scope+claims, we would have short-circuited earlier and
  // not rendered the view.
  res.status(200)
  const locals = {
    title: 'Allow access',
    client_id: params.client_id,
    claims: prompt.details?.missingOIDCClaims || [],
    scopes: prompt.details?.missingOIDCScope || [],
    uid: interaction.uid,
    grantUrl: `/federation/oidc/interact/${interaction.uid}/consent`,
    denyUrl: `/federation/oidc/interact/${interaction.uid}/deny`,
  }
  res.render(CONSENT_VIEW, locals)
}

async function findExistingGrant(provider, userId, clientId) {
  // v1.1 (plan 01 §3 step 9, "no re-consent"; 2a LOCKED SESSION 11):
  // look up the LIVE consent grant for this (accountId, clientId) via
  // the adapter account index (written on Grant upsert, cascade-deleted
  // on Grant destroy). Hydrate it with v9 `Grant.instantiate` (the
  // stored payload is the exact pickPayload shape) and return it — the
  // caller saves + reuses (TTL refresh, no re-consent). Any miss (no
  // index, doc gone by TTL, payload mismatch, lookup error) falls back
  // to null → fresh grant (v1 behavior). Soft-degrade: a lookup failure
  // NEVER changes the consent outcome (a fresh grant is always valid).
  try {
    const redis = await RedisWrapper.client('federation')
    const grantId = await findByAccountAndClient(redis, String(userId), clientId)
    if (!grantId) return null
    const stored = await provider.Grant.adapter.find(grantId)
    if (!stored) return null
    if (stored.accountId !== String(userId) || stored.clientId !== clientId) {
      return null
    }
    return provider.Grant.instantiate(stored)
  } catch (err) {
    logger.debug({ err, userId, clientId }, 'bridge: findExistingGrant missed')
    return null
  }
}
