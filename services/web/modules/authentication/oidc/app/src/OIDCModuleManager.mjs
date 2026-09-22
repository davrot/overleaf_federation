import logger from '@overleaf/logger'
import Settings from '@overleaf/settings'
import passport from 'passport'
import { boolFromEnv } from '../../../utils.mjs'
import { getOIDCProviderConfig, getProviderById, loadSSOConfig } from '../../../ssoConfigLoader.mjs'
import PermissionsManager from '../../../../../app/src/Features/Authorization/PermissionsManager.mjs'
import OIDCAuthenticationController from './OIDCAuthenticationController.mjs'
import { Strategy as OIDCStrategy } from 'passport-openidconnect'

/**
 * N-provider OIDC manager (P1b).
 *
 *  - ENV mode (EXTERNAL_AUTH=oidc + OVERLEAF_OIDC_*): ONE synthetic provider,
 *    strategy name 'openidconnect' (stock), providerId env/default — byte-identical
 *    to the pre-N module.
 *  - DB mode (ssoConfigs doc): each enabled OIDC provider is a strategy named
 *    'oidc-<id>', providerId = the provider's id. Registration is LAZY
 *    (ensureStrategy) so an admin save/delete is picked up on the next login
 *    with NO restart. The stock 'openidconnect' name is also bound so the
 *    un-parameterised URL redirects to the first-enabled provider.
 */
const OIDCModuleManager = {
  _registered: new Map(),

  async initSettings() {
    const first = await getOIDCProviderConfig()
    if (first) {
      const config = await loadSSOConfig()
      const providers = (config?.providers || []).filter(p => p.type === 'oidc' && p.enabled)
      const firstProvider = providers[0] || first
      Settings.oidc = {
        enable: true,
        _firstProviderId: firstProvider.id,
        providers: Object.fromEntries(providers.map(p => [p.id, {
          providerId: p.providerID || p.id,
          identityServiceName: p.identityServiceName || p.buttonLabel || `Log in with ${p.name || 'OIDC'}`,
          attUserId:    p.userIdField || 'id',
          attAdmin:     p.isAdminField || undefined,
          valAdmin:     p.isAdminFieldValue || undefined,
          updateUserDetailsOnLogin: !!p.updateUserDetailsOnLogin,
          allowedOIDCEmailDomains: p.allowedEmailDomains
            ? p.allowedEmailDomains.split(',').map(s => s.trim()).filter(Boolean)
            : null,
        }])),
      }
      // keep the single-provider seam for existing readers (logout URL etc.)
      Settings._oidcDbProvider = firstProvider
      // keep oauthProviders entry for the first provider (link UI / descriptions)
      const providerId = first.providerID || first.id
      if (!Settings.oauthProviders) Settings.oauthProviders = {}
      Settings.oauthProviders[providerId] = {
        name: first.providerName || first.name || 'OIDC Provider',
        descriptionKey: first.providerDescription || undefined,
        descriptionOptions: first.providerInfoLink ? { link: first.providerInfoLink } : undefined,
        hideWhenNotLinked: !!first.hideWhenNotLinked,
        linkPath: `/oidc/login/${providerId}`,
      }
    } else {
      let providerId = process.env.OVERLEAF_OIDC_PROVIDER_ID || 'oidc'
      Settings.oidc = {
        enable: true,
        _firstProviderId: providerId,
        providerId,   // legacy singleton read by the manager (env mode)
        identityServiceName: process.env.OVERLEAF_OIDC_IDENTITY_SERVICE_NAME || `Log in with ${Settings.oauthProviders[providerId]?.name || 'OIDC'}`,
        attUserId:    process.env.OVERLEAF_OIDC_USER_ID_FIELD || 'id',
        attAdmin:     process.env.OVERLEAF_OIDC_IS_ADMIN_FIELD,
        valAdmin:     process.env.OVERLEAF_OIDC_IS_ADMIN_FIELD_VALUE,
        updateUserDetailsOnLogin: boolFromEnv(process.env.OVERLEAF_OIDC_UPDATE_USER_DETAILS_ON_LOGIN),
        allowedOIDCEmailDomains: process.env.OVERLEAF_OIDC_ALLOWED_EMAIL_DOMAINS === undefined
          ? null
          : process.env.OVERLEAF_OIDC_ALLOWED_EMAIL_DOMAINS.split(',').map(s => s.trim()).filter(Boolean),
      }
    }
  },

  /**
   * providerId -> strategy id. Env-mode synthetic 'oidc' -> stock
   * 'openidconnect'; DB row ids -> 'oidc-<id>'. No global mode check — callers
   * pass the resolved (session) provider id.
   */
  strategyIdForProviderId(providerId) {
    if (!providerId || providerId === 'oidc') return 'openidconnect'
    return `oidc-${providerId}`
  },
  /** strategy id -> providerId (inverse of the above). */
  providerIdForStrategy(strategyId) {
    return String(strategyId).startsWith('oidc-') ? strategyId.slice('oidc-'.length)
      : Settings.oidc?.providerId || 'oidc'
  },

  /**
   * Build passport-openidconnect strategy options for ONE provider.
   * @param {object|null} provider  DB provider config; null => env (OVERLEAF_OIDC_*) fallback.
   */
  buildStrategyOptions(provider) {
    const site = Settings.siteUrl.replace(/\/+$/, '')
    const callbackURL = `${site}/oidc/login/callback`
    if (provider) {
      return {
        issuer: provider.issuer,
        authorizationURL: provider.authorizationURL || undefined,
        tokenURL: provider.tokenURL || undefined,
        userInfoURL: provider.userInfoURL || undefined,
        clientID: provider.clientID,
        clientSecret: provider.clientSecret,
        callbackURL,
        scope: provider.scope || 'openid profile email',
        passReqToCallback: true,
      }
    }
    return {
      issuer: process.env.OVERLEAF_OIDC_ISSUER,
      authorizationURL: process.env.OVERLEAF_OIDC_AUTHORIZATION_URL,
      tokenURL: process.env.OVERLEAF_OIDC_TOKEN_URL,
      userInfoURL: process.env.OVERLEAF_OIDC_USER_INFO_URL,
      clientID: process.env.OVERLEAF_OIDC_CLIENT_ID,
      clientSecret: process.env.OVERLEAF_OIDC_CLIENT_SECRET,
      callbackURL,
      scope: process.env.OVERLEAF_OIDC_SCOPE || 'openid profile email',
      passReqToCallback: true,
    }
  },

  /**
   * Lazily (re)register the strategy for the given provider (DB row id, or the
   * env synthetic in env mode). In DB mode also binds the stock 'openidconnect'
   * to the first-enabled provider (un-parameterised URLs redirect there).
   */
  async ensureStrategy(providerId) {
    const first = await getOIDCProviderConfig()
    if (first) {
      const provider = providerId ? await getProviderById(providerId) : first
      if (!provider || !provider.enabled) {
        logger.warn({ id: providerId }, 'OIDC provider not found or disabled — skipping strategy registration')
        return
      }
      const strategyId = OIDCModuleManager.strategyIdForProviderId(provider.id)
      OIDCModuleManager._register(strategyId, OIDCModuleManager.buildStrategyOptions(provider))
      if (strategyId !== 'openidconnect') {
        OIDCModuleManager._register('openidconnect', OIDCModuleManager.buildStrategyOptions(first))
      }
    } else {
      OIDCModuleManager._register('openidconnect', OIDCModuleManager.buildStrategyOptions(null))
    }
  },

  _register(strategyId, options) {
    try {
      // (re)register: admin edits/cert rotation apply without restart.
      if (passport._strategies && passport._strategies[strategyId]) {
        passport.unuse?.(strategyId)
      }
      passport.use(strategyId, new OIDCStrategy(
        options,
        OIDCAuthenticationController.doPassportLogin
      ))
      OIDCModuleManager._registered.set(strategyId, true)
    } catch (error) {
      logger.error({ error, strategyId }, 'Failed to register OIDC strategy')
    }
  },

  /** Evict a provider strategy (admin delete). Recon N5: passport.unuse is a plain map delete. */
  evictStrategy(providerId) {
    try {
      const strategyId = OIDCModuleManager.strategyIdForProviderId(providerId)
      passport.unuse?.(strategyId)
      OIDCModuleManager._registered.delete(strategyId)
    } catch (e) {
      logger.warn({ e, strategyId: providerId }, 'Failed to evict OIDC strategy')
    }
  },

  /**
   * Module hook (contract preserved). Registration is lazy (ensureStrategy on the
   * next login) so admin saves need no restart; hook kept for module contract.
   */
  passportSetup(passport, callback) {
    OIDCModuleManager.ensureStrategy().then(() => callback(null), error => callback(error))
    return undefined
  },

  initPolicy() {
    try {
      PermissionsManager.registerCapability('change-password', { default : true })
      PermissionsManager.registerCapability('use-ai', { default : false })
    } catch (error) {
      logger.info({}, error.message)
    }
    const oidcPolicyValidator = async ({ user, subscription }) => {
// If user is not logged in, user.externalAuth is undefined,
// in this case allow to change password if the user has a hashedPassword
      return user.externalAuth === 'oidc' || (user.externalAuth === undefined && !user.hashedPassword)
    }
    try {
    PermissionsManager.registerPolicy(
      'oidcPolicy',
      { 'change-password' : false },
      { validator: oidcPolicyValidator }
    )
    } catch (error) {
      logger.info({}, error.message)
    }
  },

  getGroupPolicyForUser(user, callback) {
    PermissionsManager.promises.getUserValidationStatus({
      user,
      groupPolicy : { 'oidcPolicy' : true },
      subscription : null
    }).then(userValidationMap => {
      let groupPolicy = Object.fromEntries(userValidationMap)
      callback(null, { groupPolicy })
    }).catch(error => {
      callback(error)
    })
  },
}

export default OIDCModuleManager
