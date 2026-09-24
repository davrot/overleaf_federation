import logger from '@overleaf/logger'
import { isSAMLEnabled } from '../ssoConfigLoader.mjs'

let samlModule = {}
const samlEnabled = process.env.EXTERNAL_AUTH?.includes('saml') || await isSAMLEnabled()
if (samlEnabled) {
  const { default: SAMLModuleManager } = await import('./app/src/SAMLModuleManager.mjs')
  const { default: router } = await import('./app/src/SAMLRouter.mjs')
  const { default: nonCsrfRouter } = await import('./app/src/SAMLNonCsrfRouter.mjs')
  const { sweepSsoCertExpiry } = await import('../ssoCertExpiry.mjs')
  await SAMLModuleManager.initSettings()
  SAMLModuleManager.initPolicy()
  samlModule = {
    name: 'saml-authentication',
    hooks: {
      passportSetup: SAMLModuleManager.passportSetup,
      getGroupPolicyForUser: SAMLModuleManager.getGroupPolicyForUser,
    },
    async start() {
      // plan/10 Phase 4: cert-expiry alerts (SP cert + SAML IdP/proxy certs)
      try {
        const rows = await sweepSsoCertExpiry()
        logger.info({ checked: rows.length }, 'sso cert expiry: sweep done')
      } catch (e) {
        logger.warn({ error: String(e) }, 'sso cert expiry: sweep failed — cert alerting degraded')
      }
    },
    router: router,
    nonCsrfRouter: nonCsrfRouter,
  }
}
export default samlModule
