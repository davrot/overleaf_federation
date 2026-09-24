import Settings from '@overleaf/settings'
import logger from '@overleaf/logger'
import passport from 'passport'
import AuthenticationController from '../../../../../app/src/Features/Authentication/AuthenticationController.mjs'
import SAMLAuthenticationManager from './SAMLAuthenticationManager.mjs'
import SAMLModuleManager from './SAMLModuleManager.mjs'
import UserController from '../../../../../app/src/Features/User/UserController.mjs'
import { handleAuthenticateErrors } from '../../../../../app/src/Features/Authentication/AuthenticationErrors.mjs'
import { getProviderById, loadSSOConfig, isSAMLEnabled } from '../../../ssoConfigLoader.mjs'
import { generateServiceProviderMetadata } from '@node-saml/passport-saml'
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
  /**
   * GET /saml/meta — SAML **Service Provider** metadata for registry
   * submission (GERANT AAI / eduGAIN / DFN-AAI MDV, plan 11 §2.1).
   *
   * This is SP-direction XML (our own entityID + our ACS/SLO URLs) — it is
   * deliberately NOT derived from a per-IdP strategy (the strategy's
   * `issuer` is the *IdP's* issuer, plan 11 §1.2 BUG 1/2/4). Registration
   * config (org/contacts/keys) lives in `ssoConfigs.spMetadata` (masked in
   * the admin API; no separate route).
   */
  async getSPMetadata(req, res, next) {
    try {
      const enabled = process.env.EXTERNAL_AUTH?.includes('saml')
        || (await isSAMLEnabled())
      if (!enabled) {
        return res.status(404).send('SAML is not enabled')
      }
      const sp = (await loadSSOConfig())?.spMetadata || {}
      const xml = buildSPMetadataXml(sp, Settings.siteUrl)
      res.setHeader('Content-Disposition', `attachment; filename="${spFilename(sp, Settings.siteUrl)}"`)
      res.contentType('application/saml-metadata+xml; charset=utf-8')
      res.setHeader('X-Content-Type-Options', 'nosniff')
      return res.send(xml)
    } catch (err) {
      logger.error({ err }, 'Failed to generate SAML SP metadata')
      next(err)
    }
  },
}

/**
 * Build the SP metadata XML (plan 11 §2.1). Exported so the SSO admin
 * module can re-emit the XML for eyeballing before submission.
 * Registration config lives in `ssoConfigs.spMetadata`; signed IFF
 * `privateKey` + `publicCert` are both present (plan 11 §2.2).
 */
export function buildSPMetadataXml(sp, siteUrl) {
  const url_ = String(siteUrl || '').replace(/\/+$/, '')
  const siteOrigin = new URL(url_).origin
  const spEntityId = sp?.spEntityId || `${siteOrigin}/saml`
  const params = {
    issuer: spEntityId,
    callbackUrl: `${url_}/saml/login/callback`,
    logoutCallbackUrl: `${url_}/saml/logout/callback`,
    identifierFormat: sp?.identifierFormat
      || 'urn:oasis:names:tc:SAML:1.1:nameidentifier-format:persistent',
  }
  if (sp?.organization?.name) {
    params.metadataOrganization = {
      OrganizationName: [{ '@xml:lang': 'en', '#text': sp.organization.name }],
      ...(sp.organization.displayName
        ? { OrganizationDisplayName: [{ '@xml:lang': 'en', '#text': sp.organization.displayName }] }
        : {}),
      ...(sp.organization.url
        ? { OrganizationURL: [{ '@xml:lang': 'en', '#text': sp.organization.url }] }
        : {}),
    }
  }
  if (sp?.contacts?.length) {
    params.metadataContactPerson = sp.contacts
      .filter(c => c?.email)
      .map((c) => ({
        '@contactType': c.contactType || 'technical',
        EmailAddress: [c.email],
      }))
  }
  // v5 signing seam (plan 11 §2.2, verified empirically): signing needs
  // BOTH privateKey + publicCerts + signatureAlgorithm; the KEY is only for
  // computing the signature, the CERT is what the registry sees.
  if (sp?.privateKey && sp?.publicCert) {
    params.signMetadata = true
    params.privateKey = sp.privateKey
    params.publicCerts = [sp.publicCert]
    params.signatureAlgorithm = 'sha256'
  }
  return generateServiceProviderMetadata(params)
}
export function spFilename(sp, siteUrl) {
  const url_ = String(siteUrl || '').replace(/\/+$/, '')
  // Default: the site host (not the full <origin>/saml entityID, which would
  // slugify into "https---..." dashes).
  // Custom spEntityId: the host of the entityID (it is a URL).
  // Custom spEntityId: use the host when it parses as a URL, else slug the
  // full value (entity IDs may be bare domains/slugs too).
  let host
  if (sp?.spEntityId) {
    try {
      host = new URL(sp.spEntityId).host
    } catch {
      host = sp.spEntityId
    }
  } else {
    host = new URL(url_).host
  }
  return `${host.replace(/[^a-zA-Z0-9.-]/g, '-')}-meta.xml`
}

export default SAMLAuthenticationController
