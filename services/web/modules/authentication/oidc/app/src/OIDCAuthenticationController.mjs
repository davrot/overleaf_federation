import logger from '@overleaf/logger'
import passport from 'passport'
import Settings from '@overleaf/settings'
import AuthenticationController from '../../../../../app/src/Features/Authentication/AuthenticationController.mjs'
import UserController from '../../../../../app/src/Features/User/UserController.mjs'
import ThirdPartyIdentityManager from '../../../../../app/src/Features/User/ThirdPartyIdentityManager.mjs'
import OIDCAuthenticationManager from './OIDCAuthenticationManager.mjs'
import OIDCModuleManager from './OIDCModuleManager.mjs'
import { evaluateAttrFilter, auditSsoLoginDenied } from '../../../../../app/src/Features/Authentication/ssoRoleEvaluator.mjs'
import { getProviderById } from '../../../ssoConfigLoader.mjs'

const OIDCAuthenticationController = {
  /**
   * GET /oidc/login (env fallback) and GET /oidc/login/:providerId (DB providers).
   * Sets req.session.oidcProviderId — the callback dispatches per session.
   */
  async passportLogin(req, res, next) {
    req.session.intent = req.query.intent
    const providerId = req.params.providerId || Settings.oidc?._firstProviderId || Settings.oidc?.providerId || 'oidc'
    req.session.oidcProviderId = providerId
    try {
      await OIDCModuleManager.ensureStrategy(providerId)
      const strategyId = OIDCModuleManager.strategyIdForProviderId(providerId)
      if (!passport._strategy(strategyId)) {
        return res.status(404).send(`OIDC provider '${providerId}' not found or disabled`)
      }
      passport.authenticate(strategyId)(req, res, next)
    } catch (err) {
      next(err)
    }
  },
  async passportLoginCallback(req, res, next) {
    // This function is middleware which wraps the passport.authenticate middleware,
    // so we can send back our custom `{message: {text: "", type: ""}}` responses on failure,
    // and send a `{redir: ""}` response on success
    const providerId = req.session.oidcProviderId || Settings.oidc?._firstProviderId || Settings.oidc?.providerId || 'oidc'
    try {
      await OIDCModuleManager.ensureStrategy(providerId)
      const strategyId = OIDCModuleManager.strategyIdForProviderId(providerId)
      passport.authenticate(
        strategyId,
        { keepSessionInfo: true },
        async function (err, user, info) {
          if (err) {
            return next(err)
          }
          if (req.session.intent === 'link') {
            delete req.session.intent
            // After linking, log out from the OIDC provider and redirect back to '/user/settings'.
            // Keycloak supports this; Authentik does not (yet).
            const logoutUrl = Settings._oidcDbProvider?.logoutURL || process.env.OVERLEAF_OIDC_LOGOUT_URL
            const redirectUri = `${Settings.siteUrl.replace(/\/+$/, '')}/user/settings`
            return res.redirect(`${logoutUrl}?id_token_hint=${info.idToken}&post_logout_redirect_uri=${encodeURIComponent(redirectUri)}`)
          }
          if (user) {
            req.session.idToken = info.idToken
            user.externalAuth = 'oidc'
            // `user` is either a user object or false
            AuthenticationController.setAuditInfo(req, {
              method: `OIDC login - ${providerId}`,
            })
            try {
              await AuthenticationController.promises.finishLogin(user, req, res)
            } catch (err) {
              return next(err)
            }
          } else {
            if (info.redir != null) {
              await UserController.doLogout(req)
              return res.redirect(info.redir)
            } else {
              res.status(info.status || 401)
              delete info.status
              const body = { message: info }
              return res.json(body)
            }
          }
        }
      )(req, res, next)
    } catch (err) {
      next(err)
    }
  },
  async doPassportLogin(req, issuer, uiProfile, idProfile, context, idToken, accessToken, refreshToken, params, done) {
    const profile = uiProfile ?? idProfile //id Profile if _skipUserProfile is true
    let user, info
    const providerId = req.session.oidcProviderId || Settings.oidc?._firstProviderId || Settings.oidc?.providerId || 'oidc'
    try {
      if (req.session.intent === 'link') {
        ;({ user, info } = await OIDCAuthenticationController._doLink(
          req,
          profile
        ))
      } else {
        ;({ user, info } = await OIDCAuthenticationController._doLogin(
          req,
          profile,
          { providerId }
        ))
      }
    } catch (error) {
      return done(error)
    }
    if (user) {
      info = {
        ...(info || {}),
        idToken: idToken
      }
    }
    return done(null, user, info)
  },
  async _doLogin(req, profile, { providerId } = {}) {
    const { fromKnownDevice } = AuthenticationController.getAuditInfo(req)
    const auditLog = {
      ipAddress: req.ip,
      info: { method: `OIDC login - ${providerId}`, fromKnownDevice },
    }

    // P1c: evaluate attrFilter and refuse `blocked` logins BEFORE account creation.
    let role = 'local'
    try {
      const provider = await getProviderById(providerId)
      if (provider && !provider.__envFallback) {
        role = evaluateAttrFilter(provider.attrFilter, profile).role
      }
    } catch (err) {
      logger.warn({ err, providerId }, 'OIDC attrFilter evaluation failed; defaulting role to local')
    }
    if (role === 'blocked') {
      logger.warn({ providerId }, 'OIDC login denied: attrFilter blocked')
      try { await auditSsoLoginDenied({ ipAddress: req.ip, providerId, reason: { method: 'oidc-attrFilter-blocked' } }) } catch (err) { logger.warn({ err }, 'failed to audit sso-login-denied (oidc)') }
      return {
        user: false,
        info: {
          type: 'error',
          text: 'Login denied by SSO role filter',
          status: 401,
        },
      }
    }

    let user
    try {
      user = await OIDCAuthenticationManager.promises.findOrCreateUser(profile, auditLog, { providerId, ssoRole: role })
    } catch (error) {
      logger.debug({ email : profile.emails[0].value }, `OIDC login failed: ${error}`)
      return {
        user: false,
        info: {
          type: 'error',
          text: error.message,
          status: 500,
        },
      }
    }
    if (user) {
      return { user, info: undefined }
    } else { // user account is not created
      logger.debug({ email : profile.emails[0].value }, 'OIDC JIT account creation is not allowed for this email')
      return {
        user: false,
        info: {
          redir: '/register',
          status: 401,
        },
      }
    }
  },
  async _doLink(req, profile) {
    const { user: { _id: userId }, ip } = req
    const providerId = req.session.oidcProviderId || Settings.oidc?._firstProviderId || Settings.oidc?.providerId || 'oidc'
    try {
      const auditLog = {
        ipAddress: ip,
        initiatorId: userId,
      }
      await OIDCAuthenticationManager.promises.linkAccount(userId, profile, auditLog, { providerId })
    } catch (error) {
      logger.error(error.info, error.message)
      return {
        user: true,
        info: {
          type: 'error',
          text: error.message,
          status: 200,
        },
      }
    }
    return { user: true, info: undefined }
  },
  async unlinkAccount(req, res, next) {
    try {
      const { user: { _id: userId }, body: { providerId }, ip } = req
      const auditLog = {
        ipAddress: ip,
        initiatorId: userId,
      }
      await ThirdPartyIdentityManager.promises.unlink(userId, providerId, auditLog)
      return res.status(204).end()
    } catch (error) {
      logger.error('Unexpected error in uninkAccount')
      return next({ stack: error.stack, info: {userId: req.user?._id} })
    }
  },
  /**
   * Logout (per-provider where possible).
   */
  async passportLogout(req, res, next) {
    // TODO: instead of storing idToken in session, use refreshToken to obtain a new idToken?
    const idTokenHint = req.session.idToken
    await UserController.doLogout(req)
    const logoutUrl = Settings._oidcDbProvider?.logoutURL || process.env.OVERLEAF_OIDC_LOGOUT_URL
    const redirectUri = Settings.siteUrl
    res.redirect(`${logoutUrl}?id_token_hint=${idTokenHint}&post_logout_redirect_uri=${encodeURIComponent(redirectUri)}`)
  },
}

export default OIDCAuthenticationController
