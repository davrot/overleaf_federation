import Settings from '@overleaf/settings'
import logger from '@overleaf/logger'
import passport from 'passport'
import AuthenticationController from '../../../../../app/src/Features/Authentication/AuthenticationController.mjs'
import SAMLAuthenticationManager from './SAMLAuthenticationManager.mjs'
import SAMLModuleManager from './SAMLModuleManager.mjs'
import UserController from '../../../../../app/src/Features/User/UserController.mjs'
import { handleAuthenticateErrors } from '../../../../../app/src/Features/Authentication/AuthenticationErrors.mjs'
import { xmlResponse } from '../../../../../app/src/infrastructure/Response.mjs'
import { readFilesContentFromEnv } from '../../../utils.mjs'
import { getProviderById } from '../../../ssoConfigLoader.mjs'
import { evaluateAttrFilter, auditSsoLoginDenied } from '../../../../../app/src/Features/Authentication/ssoRoleEvaluator.mjs'

const SAMLAuthenticationController = {
  /**
   * GET /saml/login (env fallback) and GET /saml/login/:providerId (DB providers).
   * Sets req.session.samlProviderId — the ACS callback dispatches per session.
   */
  async passportLogin(req, res, next) {
    const providerId = req.params.providerId || Settings.saml?._firstProviderId || '1'
    try {
      await SAMLModuleManager.ensureStrategy(providerId)
      const strategyId = SAMLModuleManager.strategyIdForProviderId(providerId)
      if (!passport._strategy(strategyId)) {
        return res.status(404).send(`SAML provider '${providerId}' not found or disabled`)
      }
      const strategy = passport._strategy(strategyId)
      if (strategy?._saml?.options.authnRequestBinding === 'HTTP-POST') {
        const csp = res.getHeader('Content-Security-Policy')
        if (csp) {
          res.setHeader(
            'Content-Security-Policy',
            csp.replace(/(?:^|\s)(default-src|form-action)[^;]*;?/g, '')
          )
        }
      }
      req.session.samlProviderId = providerId
      passport.authenticate(strategyId)(req, res, next)
    } catch (err) {
      next(err)
    }
  },
  async passportLoginCallback(req, res, next) {
    // This function is middleware which wraps the passport.authenticate middleware,
    // so we can send back our custom `{message: {text: "", type: ""}}` responses on failure,
    // and send a `{redir: ""}` response on success
    const providerId = req.session.samlProviderId || Settings.saml?._firstProviderId || '1'
    try {
      await SAMLModuleManager.ensureStrategy(providerId)
      const strategyId = SAMLModuleManager.strategyIdForProviderId(providerId)
      passport.authenticate(
        strategyId,
        { keepSessionInfo: true },
        async function (err, user, info) {
          if (err) {
            return next(err)
          }
          if (user) {
            // `user` is either a user object or false
            AuthenticationController.setAuditInfo(req, {
              method: `SAML login - ${providerId}`,
            })
            try {
              await AuthenticationController.promises.finishLogin(user, req, res)
            } catch (err) {
              return next(err)
            }
          } else {
            if (info.redir != null) {
              return res.json({ redir: info.redir })
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
  async doPassportLogin(req, profile, done) {
    let user, info
    try {
      ;({ user, info } = await SAMLAuthenticationController._doPassportLogin(
        req,
        profile
      ))
    } catch (error) {
      return done(error)
    }
    return done(undefined, user, info)
  },
  async _doPassportLogin(req, profile) {
    const { fromKnownDevice } = AuthenticationController.getAuditInfo(req)
    const samlProviderId = req.session.samlProviderId || Settings.saml?._firstProviderId || '1'
    const auditLog = {
      ipAddress: req.ip,
      info: { method: `SAML login - ${samlProviderId}`, fromKnownDevice },
    }

    // P1c: evaluate the per-provider attribute filter and refuse `blocked` logins
    // BEFORE account creation (no account, no session; audit sso-login-denied).
    let role = 'local'
    try {
      const provider = await getProviderById(samlProviderId)
      if (provider && !provider.__envFallback) {
        role = evaluateAttrFilter(provider.attrFilter, profile).role
      }
    } catch (err) {
      logger.warn({ err, samlProviderId }, 'SAML attrFilter evaluation failed; defaulting role to local')
    }
    if (role === 'blocked') {
      logger.warn({ samlProviderId }, 'SAML login denied: attrFilter blocked')
      try { await auditSsoLoginDenied({ ipAddress: req.ip, providerId: samlProviderId, reason: { method: 'saml-attrFilter-blocked' } }) } catch (err) { logger.warn({ err }, 'failed to audit sso-login-denied (saml)') }
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
      user = await SAMLAuthenticationManager.promises.findOrCreateUser(profile, auditLog, { providerId: samlProviderId, ssoRole: role })
    } catch (error) {
      return {
        user: false,
        info: handleAuthenticateErrors(error, req),
      }
    }
    if (user) {
      user.externalAuth = 'saml'
      req.session.saml_extce = {nameID : profile.nameID, sessionIndex : profile.sessionIndex}
      return { user, info: undefined }
    } else { // we cannot be here, something is terribly wrong
      logger.debug({ email : profile.mail }, 'failed SAML log in')
      return {
        user: false,
        info: {
          type: 'error',
          text: 'Unknown error',
          status: 500,
        },
      }
    }
  },
  async passportLogout(req, res, next) {
    const providerId = req.session.samlProviderId || Settings.saml?._firstProviderId || '1'
    try {
      await SAMLModuleManager.ensureStrategy(providerId)
      const strategyId = SAMLModuleManager.strategyIdForProviderId(providerId)
      passport._strategy(strategyId).logout(req, async (err, url) => {
        await UserController.doLogout(req)
        if (err) return next(err)
        res.redirect(url)
      })
    } catch (err) {
      next(err)
    }
  },
  async passportLogoutCallback(req, res, next) {
    const providerId = req.session.samlProviderId || Settings.saml?._firstProviderId || '1'
    try {
      await SAMLModuleManager.ensureStrategy(providerId)
      const strategyId = SAMLModuleManager.strategyIdForProviderId(providerId)
      passport.authenticate(strategyId)(req, res, (err) => {
        if (err) {
          return next(err)
        }
        res.redirect('/login')
      })
    } catch (err) {
      next(err)
    }
  },
  async getSPMetadata(req, res, next) {
    // First-enabled provider (env or DB); per-provider meta comes with the
    // admin test endpoints in Phase 2.
    const providerId = Settings.saml?._firstProviderId || '1'
    try {
      await SAMLModuleManager.ensureStrategy(providerId)
      const strategyId = SAMLModuleManager.strategyIdForProviderId(providerId)
      const samlStratery = passport._strategy(strategyId)
      // Cert overrides: DB row for the first-enabled provider (env-mode -> env vars fallback).
      // The provider is resolved from id; the env synthetic id yields a marker (no DB row).
      const provider = await getProviderById(providerId)
      const dbProvider = provider && !provider.__envFallback ? provider : null
      const decryptionCert = dbProvider?.decryptionCert
        ? readFilesContentFromEnv(dbProvider.decryptionCert)
        : readFilesContentFromEnv(process.env.OVERLEAF_SAML_DECRYPTION_CERT)
      const publicCert = dbProvider?.publicCert
        ? readFilesContentFromEnv(dbProvider.publicCert)
        : readFilesContentFromEnv(process.env.OVERLEAF_SAML_PUBLIC_CERT)
      res.setHeader('Content-Disposition', `attachment; filename="${samlStratery._saml.options.issuer}-meta.xml"`)
      xmlResponse(res,
        samlStratery.generateServiceProviderMetadata(
          {
            decryptionCert,
            publicCert
          },
          (err, xml) => {
            if (err) {
              next(err)
            } else {
              res.write(xml)
              res.end()
            }
          }
        )
      )
    } catch (err) {
      next(err)
    }
  },
}

export default SAMLAuthenticationController
