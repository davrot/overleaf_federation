import logger from '@overleaf/logger'
import { db } from '../../app/src/infrastructure/mongodb.mjs'
import { connectionPromise } from '../../app/src/infrastructure/mongodb.mjs'

const SSO_CONFIG_ID = 'sso-settings'

let _cachedConfig = null

/**
 * Get the SSO configuration from the database.
 * Falls back to environment variables if no DB config exists.
 * Caches the result for the lifetime of the process.
 */
export async function loadSSOConfig() {
  if (_cachedConfig) return _cachedConfig

  try {
    await connectionPromise
    const config = await db.ssoConfigs.findOne({ _id: SSO_CONFIG_ID })
    if (config) {
      _cachedConfig = config
      logger.info({}, 'Loaded SSO configuration from database')
      return config
    }
  } catch (error) {
    logger.warn({ error }, 'Failed to load SSO config from database, falling back to env vars')
  }

  // Return null to indicate env-var mode
  return null
}

/**
 * Check if LDAP is enabled (from DB config or env vars)
 */
export async function isLDAPEnabled() {
  const config = await loadSSOConfig()
  if (config) return !!config.ldap?.enabled
  return !!process.env.EXTERNAL_AUTH?.includes('ldap')
}

/**
 * Check if any SAML provider is enabled
 */
export async function isSAMLEnabled() {
  const config = await loadSSOConfig()
  if (config) return config.providers?.some(p => p.type === 'saml' && p.enabled) || false
  return !!process.env.EXTERNAL_AUTH?.includes('saml')
}

/**
 * Check if any OIDC provider is enabled  
 */
export async function isOIDCEnabled() {
  const config = await loadSSOConfig()
  if (config) return config.providers?.some(p => p.type === 'oidc' && p.enabled) || false
  return !!process.env.EXTERNAL_AUTH?.includes('oidc')
}

/**
 * Get LDAP configuration from DB config
 */
export async function getLDAPConfig() {
  const config = await loadSSOConfig()
  if (config) return config.ldap
  return null
}

/**
 * Get the first enabled SAML provider config from DB
 * (kept for env-fallback single-provider mode; N-aware code uses getProviderById)
 */
export async function getSAMLProviderConfig() {
  const config = await loadSSOConfig()
  if (config) {
    const provider = config.providers?.find(p => p.type === 'saml' && p.enabled)
    return provider || null
  }
  return null
}

/**
 * Get the first enabled OIDC provider config from DB
 * (kept for env-fallback single-provider mode; N-aware code uses getProviderById)
 */
export async function getOIDCProviderConfig() {
  const config = await loadSSOConfig()
  if (config) {
    const provider = config.providers?.find(p => p.type === 'oidc' && p.enabled)
    return provider || null
  }
  return null
}

/**
 * Look up an SSO provider by its unique id (DB providers: ssoConfigs.providers[].id;
 * env-fallback providers: synthetic ids 'saml' / 'oidc'). N-provider dispatch uses this.
 */
export async function getProviderById(id, { envFallback = true } = {}) {
  if (id === 'saml' || id === 'oidc') {
    // env-fallback synthetic provider refs
    if (!envFallback) return null
    return { __envFallback: true, id, type: id }
  }
  const config = await loadSSOConfig()
  return config?.providers?.find(p => p.id === id) || null
}

/**
 * True when an ssoConfigs DB doc is the active config (loaded into the process
 * cache). After clearConfigCache the cache is empty until the next
 * loadSSOConfig() re-populates it, so consumers that need post-save state must
 * await loadSSOConfig() first (module boot / login / admin middleware all do).
 * In env mode there is exactly one synthetic provider per protocol; strategies
 * use the stock names to stay byte-identical with pre-N behaviour.
 */
export function isDbMode() {
  return _cachedConfig !== null
}

/**
 * Get all enabled providers sorted by order for login page
 */
export async function getEnabledProviders() {
  const config = await loadSSOConfig()
  if (config) {
    return (config.providers || [])
      .filter(p => p.enabled)
      .sort((a, b) => (a.order || 0) - (b.order || 0))
  }
  // Fall back to env-based providers (single synthetic provider per protocol)
  const providers = []
  if (process.env.EXTERNAL_AUTH?.includes('saml')) {
    providers.push({
      id: 'saml',
      type: 'saml',
      enabled: true,
      buttonLabel: process.env.OVERLEAF_SAML_IDENTITY_SERVICE_NAME || 'Log in with SAML',
      loginUrl: '/saml/login',
      order: 0,
    })
  }
  if (process.env.EXTERNAL_AUTH?.includes('oidc')) {
    providers.push({
      id: 'oidc',
      type: 'oidc',
      enabled: true,
      buttonLabel: process.env.OVERLEAF_OIDC_IDENTITY_SERVICE_NAME || 'Log in with OIDC',
      loginUrl: '/oidc/login',
      order: 1,
    })
  }
  return providers
}

/**
 * Get login page settings
 */
export async function getLoginPageSettings() {
  const config = await loadSSOConfig()
  if (config) {
    return config.loginPage || { localLoginEnabled: true, logoUrl: '', title: '' }
  }
  return {
    localLoginEnabled: process.env.OVERLEAF_SSO_HIDE_LOCAL_LOGIN?.toLowerCase() !== 'true',
    logoUrl: '',
    title: '',
  }
}

/**
 * Clear the cached config (e.g., after saving new config)
 */
export function clearConfigCache() {
  _cachedConfig = null
}
