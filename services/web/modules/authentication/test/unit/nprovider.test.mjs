import { vi, describe, it, expect, beforeEach } from 'vitest'
import passport from 'passport'

// N-provider dispatch unit test (P1b):
//  - strategyId <-> providerId mapping (env stock names; per-provider DB names)
//  - lazy ensureStrategy: env mode registers stock 'saml' once; DB mode registers
//    a strategy per provider id and leaves others unregistered
//  - evictStrategy (admin delete)
//
// All app/db deps are mocked; no DB. Mock paths are relative to THIS file.

const store = (globalThis.__SSO_TEST_STORE = globalThis.__SSO_TEST_STORE || {
  mode: 'env',         // 'env' | 'db'
  dbConfig: null,      // ssoConfig doc shape { _id, providers: [...], ... }
  cleared: 0,
})

vi.mock('@overleaf/logger', () => ({
  default: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
}))
// Mock ONLY the SAML strategy constructor so `new SAMLStrategy(opts, verify, logout)`
// does not validate certs against the (fake) provider options. The module manager's
// dispatch/registration logic is exercised fully.
vi.mock('@node-saml/passport-saml', () => ({
  Strategy: class SAMLStrategy {}
}))
vi.mock('@overleaf/settings', () => ({
  default: {
    siteUrl: 'https://overleaf.example',
    saml: undefined,
    oidc: undefined,
    ldap: undefined,
    _samlDbProvider: undefined,
    _oidcDbProvider: undefined,
    oauthProviders: {},
  },
}))
vi.mock('../../../../app/src/Features/Authorization/PermissionsManager.mjs', () => ({
  default: {
    registerCapability: () => {},
    registerPolicy: () => {},
    promises: { getUserValidationStatus: async () => ({}) },
  },
}))
vi.mock('../../../utils.mjs', () => ({
  numFromEnv: (v) => (v === undefined ? undefined : Number(v)),
  boolFromEnv: (v) => v === 'true',
  readFilesContentFromEnv: (v) => v,
}))
vi.mock('../../ssoConfigLoader.mjs', () => ({
  loadSSOConfig: async () => (store.mode === 'db' ? store.dbConfig : null),
  getProviderById: async (id) => {
    if (store.mode === 'env') {
      return id === 'saml' || id === 'oidc' ? { __envFallback: true, id, type: id } : null
    }
    return store.dbConfig?.providers?.find((p) => p.id === id) || null
  },
  getSAMLProviderConfig: async () =>
    (store.mode === 'db'
      ? store.dbConfig?.providers?.find((p) => p.type === 'saml' && p.enabled) || null
      : null),
  getOIDCProviderConfig: async () =>
    (store.mode === 'db'
      ? store.dbConfig?.providers?.find((p) => p.type === 'oidc' && p.enabled) || null
      : null),
  isDbMode: () => store.mode === 'db',
  clearConfigCache: () => { store.cleared += 1 },
}))
vi.mock('../../saml/app/src/SAMLAuthenticationController.mjs', () => ({
  default: {
    passportLogin: () => {},
    passportLoginCallback: () => {},
    doPassportLogin: async () => null,
    doPassportLogout: async () => null,
    passportLogout: () => {},
  },
}))
vi.mock('../../oidc/app/src/OIDCAuthenticationController.mjs', () => ({
  default: {
    doPassportLogin: async () => ({ user: false, info: {} }),
  },
}))

const SAMLModuleManager = (await import('../../saml/app/src/SAMLModuleManager.mjs')).default
const OIDCModuleManager = (await import('../../oidc/app/src/OIDCModuleManager.mjs')).default

const DB_SAML_A = {
  id: 'abc', type: 'saml', enabled: true,
  issuer: 'https://a.example',
  entryPoint: 'https://a.example/sso',
  additionalParams: '{}',
  additionalAuthorizeParams: '{}',
  additionalLogoutParams: '{}',
  order: 0,
}
const DB_SAML_B = {
  id: 'def', type: 'saml', enabled: true,
  issuer: 'https://b.example',
  entryPoint: 'https://b.example/sso',
  additionalParams: '{}',
  additionalAuthorizeParams: '{}',
  additionalLogoutParams: '{}',
  order: 1,
}
const DB_OIDC_1 = {
  id: 'oid1', type: 'oidc', enabled: true,
  issuer: 'https://p.example',
  authorizationURL: 'https://p.example/authorize',
  tokenURL: 'https://p.example/token',
  clientID: 'c1',
  clientSecret: 'sec1',
  scope: 'openid profile email',
  order: 0,
}
const DB_OIDC_2 = {
  id: 'oid2', type: 'oidc', enabled: true,
  issuer: 'https://q.example',
  authorizationURL: 'https://q.example/authorize',
  tokenURL: 'https://q.example/token',
  clientID: 'c2',
  clientSecret: 'sec2',
  scope: 'openid profile email',
  order: 1,
}

function registeredStrategyIds() {
  return Object.keys(passport._strategies || {}).slice().sort()
}

describe('N-provider dispatch (P1b)', () => {
  beforeEach(() => {
    for (const key of registeredStrategyIds()) passport.unuse(key)
    store.mode = 'env'
    store.dbConfig = null
    store.cleared = 0
    process.env.OVERLEAF_SAML_ISSUER = 'https://env.example'
    process.env.OVERLEAF_SAML_ENTRYPOINT = 'https://env.example/sso'
  })

  it('maps env legacy ids to stock strategy names; DB ids to per-provider names', () => {
    expect(SAMLModuleManager.strategyIdForProviderId('1')).toBe('saml')
    expect(SAMLModuleManager.strategyIdForProviderId('saml')).toBe('saml')
    expect(SAMLModuleManager.strategyIdForProviderId('abc')).toBe('saml-abc')
    expect(SAMLModuleManager.providerIdForStrategy('saml-abc')).toBe('abc')
    expect(SAMLModuleManager.providerIdForStrategy('saml')).toBe('1')

    expect(OIDCModuleManager.strategyIdForProviderId(undefined)).toBe('openidconnect')
    expect(OIDCModuleManager.strategyIdForProviderId('oidc')).toBe('openidconnect')
    expect(OIDCModuleManager.strategyIdForProviderId('oid1')).toBe('oidc-oid1')
    expect(OIDCModuleManager.providerIdForStrategy('oidc-oid1')).toBe('oid1')
  })

  describe('SAML', () => {
    it('env mode: ensureStrategy registers the stock "saml" (only)', async () => {
      await SAMLModuleManager.ensureStrategy('1')
      expect(registeredStrategyIds()).toEqual(['saml'])
    })

    it('db mode: lazy per-provider registration; missing provider skipped', async () => {
      store.mode = 'db'
      store.dbConfig = { providers: [DB_SAML_A, DB_SAML_B] }
      await SAMLModuleManager.ensureStrategy('abc')
      expect(registeredStrategyIds()).toEqual(['saml-abc'])
      await SAMLModuleManager.ensureStrategy('def')
      expect(registeredStrategyIds()).toEqual(['saml-abc', 'saml-def'])
      await SAMLModuleManager.ensureStrategy('missing')
      expect(registeredStrategyIds()).toEqual(['saml-abc', 'saml-def'])
    })

    it('db mode: evictStrategy removes only the provider strategy', async () => {
      store.mode = 'db'
      store.dbConfig = { providers: [DB_SAML_A] }
      await SAMLModuleManager.ensureStrategy('abc')
      SAMLModuleManager.evictStrategy('abc')
      expect(registeredStrategyIds()).toEqual([])
    })
  })

  describe('OIDC', () => {
    it('db mode: registers oidc-<id> AND binds stock "openidconnect" to first-enabled', async () => {
      store.mode = 'db'
      store.dbConfig = { providers: [DB_OIDC_1, DB_OIDC_2] }
      await OIDCModuleManager.ensureStrategy('oid2')
      expect(registeredStrategyIds()).toEqual(['oidc-oid2', 'openidconnect'])
    })

    it('db mode: evictStrategy removes the provider strategy, keeps stock', async () => {
      store.mode = 'db'
      store.dbConfig = { providers: [DB_OIDC_2] }
      await OIDCModuleManager.ensureStrategy('oid2')
      OIDCModuleManager.evictStrategy('oid2')
      expect(registeredStrategyIds()).toEqual(['openidconnect'])
    })
  })
})
