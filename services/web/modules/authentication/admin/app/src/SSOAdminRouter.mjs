import logger from '@overleaf/logger'
import SSOAdminController from './SSOAdminController.mjs'
import { getEnabledProviders, getLoginPageSettings, isLDAPEnabled, isDbMode } from '../../../ssoConfigLoader.mjs'
import AuthorizationMiddleware from '../../../../../app/src/Features/Authorization/AuthorizationMiddleware.mjs'
import Settings from '@overleaf/settings'

export default {
  apply(webRouter) {
    logger.debug({}, 'Init SSO Admin router')

    // Middleware to inject SSO data into login page
    webRouter.use('/login', async (req, res, next) => {
      try {
        const providers = await getEnabledProviders()
        const loginSettings = await getLoginPageSettings()
        const ldapEnabled = await isLDAPEnabled()
        res.locals.ssoProviders = providers.map(p => ({
          type: p.type,
          id: p.id,
          buttonLabel: p.buttonLabel || p.name || `Log in with ${p.type.toUpperCase()}`,
          loginUrl: !isDbMode() || !p.id
            ? (p.type === 'saml' ? '/saml/login' : '/oidc/login')
            : (p.type === 'saml' ? `/saml/login/${p.id}` : `/oidc/login/${p.id}`),
        }))
        res.locals.ssoLoginPage = loginSettings
        res.locals.ssoLdapEnabled = ldapEnabled || !!(Settings.ldap && Settings.ldap.enable)
        res.locals.ssoLdapPlaceholder = Settings.ldap?.placeholder || 'Username'
      } catch (e) {
        logger.warn({ e }, 'Failed to load SSO config for login page')
      }
      next()
    })

    webRouter.get(
      '/admin/sso',
      AuthorizationMiddleware.ensureUserIsSiteAdmin,
      SSOAdminController.adminPage
    )

    webRouter.get(
      '/admin/sso/config',
      AuthorizationMiddleware.ensureUserIsSiteAdmin,
      SSOAdminController.getConfig
    )

    webRouter.post(
      '/admin/sso/config',
      AuthorizationMiddleware.ensureUserIsSiteAdmin,
      SSOAdminController.saveConfig
    )

    webRouter.post(
      '/admin/sso/provider',
      AuthorizationMiddleware.ensureUserIsSiteAdmin,
      SSOAdminController.addProvider
    )

    webRouter.delete(
      '/admin/sso/provider/:providerId',
      AuthorizationMiddleware.ensureUserIsSiteAdmin,
      SSOAdminController.deleteProvider
    )

    webRouter.post(
      '/admin/sso/providers/reorder',
      AuthorizationMiddleware.ensureUserIsSiteAdmin,
      SSOAdminController.reorderProviders
    )

    webRouter.post(
      '/admin/sso/test/ldap',
      AuthorizationMiddleware.ensureUserIsSiteAdmin,
      SSOAdminController.testLdap
    )

    webRouter.post(
      '/admin/sso/test/attr-filter',
      AuthorizationMiddleware.ensureUserIsSiteAdmin,
      SSOAdminController.testAttrFilter
    )

    webRouter.post(
      '/admin/sso/test/provider/:providerId',
      AuthorizationMiddleware.ensureUserIsSiteAdmin,
      SSOAdminController.testProvider
    )
  },
}
