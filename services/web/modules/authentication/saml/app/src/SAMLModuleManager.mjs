import logger from '@overleaf/logger'
import Settings from '@overleaf/settings'
import passport from 'passport'
import { readFilesContentFromEnv, numFromEnv, boolFromEnv } from '../../../utils.mjs'
import PermissionsManager from '../../../../../app/src/Features/Authorization/PermissionsManager.mjs'
import SAMLAuthenticationController from './SAMLAuthenticationController.mjs'
import { Strategy as SAMLStrategy } from '@node-saml/passport-saml'
import {
  loadSSOConfig,
  getSAMLProviderConfig,
  getProviderById,
} from '../../../ssoConfigLoader.mjs'

/**
 * N-provider SAML manager (P1b).
 *
 *  - ENV mode (EXTERNAL_AUTH=saml + OVERLEAF_SAML_*): ONE synthetic provider.
 *    Strategy name 'saml' (stock), providerId '1' (legacy samlIdentifiers key) —
 *    byte-identical to the pre-N module.
 *  - DB mode (ssoConfigs doc): each enabled SAML provider is a strategy named
 *    'saml-<id>' with providerId = the provider's id. Registration is LAZY
 *    (ensureStrategy) so an admin save/delete (clearConfigCache) is picked up on
 *    the next login with NO restart.
 */
const SAMLModuleManager = {
  _registered: new Map(), // strategyId -> registered flag

  async initSettings() {
    const firstProvider = await getSAMLProviderConfig()
    if (firstProvider) {
      const config = await loadSSOConfig()
      const providers = (config?.providers || []).filter(p => p.type === 'saml' && p.enabled)
      Settings.saml = {
        enable: true,
        _firstProviderId: providers[0]?.id,
        providers: Object.fromEntries(providers.map(p => [p.id, {
          identityServiceName: p.identityServiceName || p.buttonLabel || 'Log in with SAML IdP',
          attUserId:    p.userIdField || 'nameID',
          attEmail:     p.emailField || 'nameID',
          attFirstName: p.firstNameField || 'givenName',
          attLastName:  p.lastNameField || 'lastName',
          attAdmin:     p.isAdminField || undefined,
          valAdmin:     p.isAdminFieldValue || undefined,
          updateUserDetailsOnLogin: !!p.updateUserDetailsOnLogin,
        }])),
      }
    } else {
      Settings.saml = {
        enable: true,
        providerId: '1',          // legacy identifier key (env mode)
        _firstProviderId: '1',
        identityServiceName: process.env.OVERLEAF_SAML_IDENTITY_SERVICE_NAME || 'Log in with SAML IdP',
        attUserId:    process.env.OVERLEAF_SAML_USER_ID_FIELD || 'nameID',
        attEmail:     process.env.OVERLEAF_SAML_EMAIL_FIELD || 'nameID',
        attFirstName: process.env.OVERLEAF_SAML_FIRST_NAME_FIELD || 'givenName',
        attLastName:  process.env.OVERLEAF_SAML_LAST_NAME_FIELD || 'lastName',
        attAdmin:     process.env.OVERLEAF_SAML_IS_ADMIN_FIELD,
        valAdmin:     process.env.OVERLEAF_SAML_IS_ADMIN_FIELD_VALUE,
        updateUserDetailsOnLogin: boolFromEnv(process.env.OVERLEAF_SAML_UPDATE_USER_DETAILS_ON_LOGIN),
      }
    }
  },

  /**
   * providerId -> strategy id. Env-mode synthetic ids (or the env-mode
   * identifier '1') map to the stock 'saml' strategy; DB row ids map to
   * 'saml-<id>'. No global mode check needed — callers always pass the
   * resolved (session) provider id.
   */
  strategyIdForProviderId(providerId) {
    if (!providerId || providerId === '1' || providerId === 'saml') return 'saml'
    return `saml-${providerId}`
  },
  /** strategy id -> providerId (inverse of the above). */
  providerIdForStrategy(strategyId) {
    return strategyId === 'saml' ? '1' : String(strategyId).slice('saml-'.length)
  },

  /**
   * Lazily (re)register the strategy for the given provider (DB row id, or the
   * env synthetic id in env mode). Idempotent; re-reads provider config so cert
   * rotation / admin edits apply without restart.
   */
  async ensureStrategy(providerId) {
    const first = await getSAMLProviderConfig()
    if (first) {
      const provider = providerId ? await getProviderById(providerId) : first
      if (!provider || !provider.enabled) {
        logger.warn({ id: providerId }, 'SAML provider not found or disabled — skipping strategy registration')
        return
      }
      if (!provider.issuer || !provider.entryPoint) {
        logger.warn({ id: provider.id }, 'SAML provider is missing required fields (issuer/entryPoint) — skipping passport strategy registration')
        return
      }
      SAMLModuleManager._register(SAMLModuleManager.strategyIdForProviderId(provider.id), SAMLModuleManager.buildStrategyOptions(provider))
    } else {
      if (!process.env.OVERLEAF_SAML_ISSUER || !process.env.OVERLEAF_SAML_ENTRYPOINT) {
        logger.warn({}, 'SAML env vars OVERLEAF_SAML_ISSUER/ENTRYPOINT not set — skipping passport strategy registration')
        return
      }
      SAMLModuleManager._register('saml', SAMLModuleManager.buildStrategyOptions(null))
    }
  },

  /**
   * Build passport-SAML strategy options for ONE provider.
   * @param {object|null} provider  DB provider config; null => env (OVERLEAF_SAML_*) fallback.
   */
  buildStrategyOptions(provider) {
    const site = Settings.siteUrl.replace(/\/+$/, '')
    const logoutCallbackUrl = `${site}/saml/logout/callback`
    if (provider) {
      let authnContext
      if (provider.authnContext) {
        try { authnContext = JSON.parse(provider.authnContext) } catch(e) { /* ignore */ }
      }
      return {
        entryPoint: provider.entryPoint,
        callbackUrl: `${site}/saml/login/callback`,
        issuer: provider.issuer,
        audience: provider.audience || undefined,
        idpCert: provider.idpCert ? readFilesContentFromEnv(provider.idpCert) : undefined,
        privateKey: provider.privateKey ? readFilesContentFromEnv(provider.privateKey) : undefined,
        decryptionPvk: provider.decryptionPvk ? readFilesContentFromEnv(provider.decryptionPvk) : undefined,
        signatureAlgorithm: provider.signatureAlgorithm || undefined,
        additionalParams: provider.additionalParams ? JSON.parse(provider.additionalParams) : {},
        additionalAuthorizeParams: provider.additionalAuthorizeParams ? JSON.parse(provider.additionalAuthorizeParams) : {},
        identifierFormat: provider.identifierFormat || undefined,
        acceptedClockSkewMs: provider.acceptedClockSkewMs ? Number(provider.acceptedClockSkewMs) : undefined,
        attributeConsumingServiceIndex: provider.attributeConsumingServiceIndex || undefined,
        authnContext: authnContext,
        forceAuthn: !!provider.forceAuthn,
        disableRequestedAuthnContext: !!provider.disableRequestedAuthnContext,
        skipRequestCompression: provider.authnRequestBinding === 'HTTP-POST',
        authnRequestBinding: provider.authnRequestBinding || undefined,
        validateInResponseTo: provider.validateInResponseTo || undefined,
        requestIdExpirationPeriodMs: provider.requestIdExpirationPeriodMs ? Number(provider.requestIdExpirationPeriodMs) : undefined,
        logoutUrl: provider.logoutURL || undefined,
        logoutCallbackUrl,
        additionalLogoutParams: provider.additionalLogoutParams ? JSON.parse(provider.additionalLogoutParams) : {},
        wantAssertionsSigned: !!provider.wantAssertionsSigned,
        wantAuthnResponseSigned: !!provider.wantAuthnResponseSigned,
        passReqToCallback: true,
      }
    }
    return {
      entryPoint: process.env.OVERLEAF_SAML_ENTRYPOINT,
      callbackUrl: `${site}/saml/login/callback`,
      issuer: process.env.OVERLEAF_SAML_ISSUER,
      audience: process.env.OVERLEAF_SAML_AUDIENCE,
      idpCert: readFilesContentFromEnv(process.env.OVERLEAF_SAML_IDP_CERT),
      privateKey:  readFilesContentFromEnv(process.env.OVERLEAF_SAML_PRIVATE_KEY),
      decryptionPvk:  readFilesContentFromEnv(process.env.OVERLEAF_SAML_DECRYPTION_PVK),
      signatureAlgorithm: process.env.OVERLEAF_SAML_SIGNATURE_ALGORITHM,
      additionalParams: JSON.parse(process.env.OVERLEAF_SAML_ADDITIONAL_PARAMS || '{}'),
      additionalAuthorizeParams: JSON.parse(process.env.OVERLEAF_SAML_ADDITIONAL_AUTHORIZE_PARAMS || '{}'),
      identifierFormat: process.env.OVERLEAF_SAML_IDENTIFIER_FORMAT,
      acceptedClockSkewMs: numFromEnv(process.env.OVERLEAF_SAML_ACCEPTED_CLOCK_SKEW_MS),
      attributeConsumingServiceIndex: process.env.OVERLEAF_SAML_ATTRIBUTE_CONSUMING_SERVICE_INDEX,
      authnContext: process.env.OVERLEAF_SAML_AUTHN_CONTEXT ? JSON.parse(process.env.OVERLEAF_SAML_AUTHN_CONTEXT) : undefined,
      forceAuthn: boolFromEnv(process.env.OVERLEAF_SAML_FORCE_AUTHN),
      disableRequestedAuthnContext: boolFromEnv(process.env.OVERLEAF_SAML_DISABLE_REQUESTED_AUTHN_CONTEXT),
      skipRequestCompression: process.env.OVERLEAF_SAML_AUTHN_REQUEST_BINDING === 'HTTP-POST',
      authnRequestBinding: process.env.OVERLEAF_SAML_AUTHN_REQUEST_BINDING,
      validateInResponseTo: process.env.OVERLEAF_SAML_VALIDATE_IN_RESPONSE_TO,
      requestIdExpirationPeriodMs: numFromEnv(process.env.OVERLEAF_SAML_REQUEST_ID_EXPIRATION_PERIOD_MS),
      logoutUrl: process.env.OVERLEAF_SAML_LOGOUT_URL,
      logoutCallbackUrl,
      additionalLogoutParams: JSON.parse(process.env.OVERLEAF_SAML_ADDITIONAL_LOGOUT_PARAMS || '{}'),
      wantAssertionsSigned: boolFromEnv(process.env.OVERLEAF_SAML_WANT_ASSERTIONS_SIGNED),
      wantAuthnResponseSigned: boolFromEnv(process.env.OVERLEAF_SAML_WANT_AUTHN_RESPONSE_SIGNED),
      passReqToCallback: true,
    }
  },

  _register(strategyId, options) {
    try {
      passport.unuse?.(strategyId) // (re)register: admin edits/cert rotation apply without restart
      passport.use(strategyId, new SAMLStrategy(
        options,
        SAMLAuthenticationController.doPassportLogin,
        SAMLAuthenticationController.doPassportLogout
      ))
      SAMLModuleManager._registered.set(strategyId, true)
    } catch (error) {
      logger.error({ error, strategyId }, 'Failed to register SAML strategy')
    }
  },

  /** Evict a provider strategy (admin delete). Recon N5: passport._strategies is a plain map. */
  evictStrategy(providerId) {
    const strategyId = SAMLModuleManager.strategyIdForProviderId(providerId)
    try {
      passport.unuse?.(strategyId)
      SAMLModuleManager._registered.delete(strategyId)
    } catch (e) {
      logger.warn({ e, strategyId }, 'Failed to evict SAML strategy')
    }
  },

  /**
   * Module hook (contract preserved). Registration is lazy (ensureStrategy on the
   * next login) so admin saves need no restart; the hook is kept for the module
   * contract and module-order side effects (env mode registers eagerly for parity).
   */
  passportSetup(passport, callback) {
    SAMLModuleManager.ensureStrategy().then(() => callback(null), error => callback(error))
    return undefined
  },

  initPolicy() {
    try {
      PermissionsManager.registerCapability('change-password', { default : true })
      PermissionsManager.registerCapability('use-ai', { default : false })
    } catch (error) {
      logger.info({}, error.message)
    }
    const samlPolicyValidator = async ({ user, subscription }) => {
// If user is not logged in, user.externalAuth is undefined,
// in this case allow to change password if the user has a hashedPassword
      return user.externalAuth === 'saml' || (user.externalAuth === undefined && !user.hashedPassword)
    }
    try {
    PermissionsManager.registerPolicy(
      'samlPolicy',
      { 'change-password' : false },
      { validator: samlPolicyValidator }
    )
    } catch (error) {
      logger.info({}, error.message)
    }
  },

  getGroupPolicyForUser(user, callback) {
    PermissionsManager.promises.getUserValidationStatus({
      user,
      groupPolicy : { 'samlPolicy' : true },
      subscription : null
    }).then(userValidationMap => {
      let groupPolicy = Object.fromEntries(userValidationMap)
      callback(null, { groupPolicy })
    }).catch(error => {
      callback(error)
    })
  },
}

export default SAMLModuleManager
