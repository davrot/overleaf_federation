import { vi, describe, it, expect, beforeEach } from 'vitest'

// R1 synthetic-email JIT (plan 10 §3 Phase 2) — eduGAIN/DFN + GEANT IdPs do
// NOT guarantee an email attribute/claim; the login anchor (SAML eppn/nameID,
// OIDC sub) is present. When the email is absent the manager JITs
// `<userpart>@<OVERLEAF_*_SYNTHETIC_EMAIL_DOMAIN || siteUrl host>` and flags
// the identifier synthetic so it is distinguishable from a real email.
// SAML flag: `samlIdentifiers[0].syntheticEmail: true`. OIDC flag: the
// thirdPartyIdentifier `externalData { syntheticEmail: true }`.
//
// All app/db deps are mocked; no DB. Mock factories read `globalThis.__*`
// thunks (bootstrap runs vi.resetAllMocks + resetModules after each test).

const settings = {
  siteUrl: 'https://home-a.example',
  saml: { attUserId: 'eduPersonPrincipalName', attEmail: 'email' },
  oidc: { attUserId: 'id' },
}

vi.mock('@overleaf/settings', () => ({ default: settings }))

vi.mock('../../../../app/src/models/User.mjs', () => ({
  User: {
    findOne: () => ({
      exec: () => Promise.resolve(globalThis.__findOneUser ?? null),
    }),
    updateOne: (filter, update) => ({
      exec: () => {
        globalThis.__updateOneCalls.push({ filter, update })
        return Promise.resolve({ modifiedCount: 1 })
      },
    }),
  },
}))
vi.mock('../../../../app/src/Features/User/SAMLIdentityManager.mjs', () => ({
  default: {
    getUser: (providerId, externalUserId, userIdAttribute) =>
      globalThis.__samlIdentityGetUser(providerId, externalUserId, userIdAttribute),
  },
}))
vi.mock('../../../../app/src/Features/User/UserCreator.mjs', () => ({
  default: {
    promises: {
      createNewUser: (body) => {
        globalThis.__createdUsers.push(body)
        return Promise.resolve({ _id: globalThis.__createUserId ?? 'u-new' })
      },
    },
  },
}))
vi.mock('../../../../app/src/Features/User/ThirdPartyIdentityManager.mjs', () => ({
  default: {
    promises: {
      login: (providerId, externalUserId, externalData) =>
        globalThis.__tpiLogin(providerId, externalUserId, externalData),
      link: (userId, providerId, externalUserId, externalData, auditLog) => {
        globalThis.__tpiLinkCalls.push({ userId, providerId, externalUserId, externalData, auditLog })
        return Promise.resolve({ _id: globalThis.__tpiLinkedUserId ?? 'u-new' })
      },
    },
  },
}))
vi.mock('../../../../app/src/Features/Authentication/AuthenticationErrors.mjs', () => ({
  ParallelLoginError: class ParallelLoginError extends Error {},
}))
vi.mock('../../ssoConfigLoader.mjs', () => ({
  getProviderById: async (id) => globalThis.__getProviderById(id),
}))

const SAMLAuthenticationManager = (await import('../../saml/app/src/SAMLAuthenticationManager.mjs')).default
const OIDCAuthenticationManager = (await import('../../oidc/app/src/OIDCAuthenticationManager.mjs')).default

function samlProfile(overrides = {}) {
  return {
    eduPersonPrincipalName: 'j.smith@edugain.example',
    email: 'real@example.org',
    displayName: 'J.Smith',
    ...overrides,
  }
}

function oidcProfile(overrides = {}) {
  return {
    id: 'sub-42',
    name: { givenName: 'Jana' },
    emails: [{ value: 'real@example.org' }],
    ...overrides,
  }
}

function resetState() {
  globalThis.__updateOneCalls = []
  globalThis.__createdUsers = []
  globalThis.__createUserId = 'u-new'
  globalThis.__findOneUser = null
  globalThis.__samlIdentityGetUser = () => null
  globalThis.__tpiLogin = () => Promise.reject(new Error('no linked account'))
  globalThis.__tpiLinkCalls = []
  globalThis.__tpiLinkedUserId = 'u-new'
  globalThis.__getProviderById = () => null
  delete process.env.OVERLEAF_SAML_SYNTHETIC_EMAIL_DOMAIN
  delete process.env.OVERLEAF_OIDC_SYNTHETIC_EMAIL_DOMAIN
}

function samlSyntheticFlagUpdates() {
  return globalThis.__updateOneCalls.filter(
    (c) => c.update?.$set?.['samlIdentifiers.0.syntheticEmail'] === true
  )
}

// chai-as-promised is active (repo vitest setup) and breaks
// `expect(promise).rejects...` — assert rejections manually.
async function expectRejectedToContain(fn, substring) {
  try {
    await fn()
  } catch (err) {
    if (err.message?.includes(substring)) return
    throw new Error(`expected error containing "${substring}", got: ${err.message}`)
  }
  throw new Error(`expected rejection with "${substring}" but the promise resolved`)
}

describe('R1 synthetic-email JIT — SAML manager', () => {
  beforeEach(() => resetState())

  it('real email present → unchanged (no flag)', async () => {
    const user = await SAMLAuthenticationManager.promises.findOrCreateUser(
      samlProfile(),
      {},
      { providerId: '1', ssoRole: 'local' }
    )
    expect(user._id).toBe('u-new')
    expect(globalThis.__createdUsers[0].email).toBe('real@example.org')
    expect(globalThis.__createdUsers[0].samlIdentifiers[0].syntheticEmail).toBeUndefined()
    expect(samlSyntheticFlagUpdates()).toHaveLength(0)
  })

  it('email absent + eppn present → JIT <userpart>@siteUrl host + flag', async () => {
    await SAMLAuthenticationManager.promises.findOrCreateUser(
      samlProfile({ email: undefined }),
      {},
      { providerId: '1', ssoRole: 'local' }
    )
    expect(globalThis.__createdUsers[0].email).toBe('j.smith@home-a.example')
    expect(globalThis.__createdUsers[0].samlIdentifiers[0]).toMatchObject({
      providerId: '1',
      syntheticEmail: true
    })
    // identifier $set on the link step carries the flag too
    expect(samlSyntheticFlagUpdates()).toHaveLength(1)
  })

  it('env knob OVERLEAF_SAML_SYNTHETIC_EMAIL_DOMAIN overrides the siteUrl host', async () => {
    process.env.OVERLEAF_SAML_SYNTHETIC_EMAIL_DOMAIN = 'synth.example'
    await SAMLAuthenticationManager.promises.findOrCreateUser(
      samlProfile({ email: undefined }),
      {},
      { providerId: '1', ssoRole: 'local' }
    )
    expect(globalThis.__createdUsers[0].email).toBe('j.smith@synth.example')
  })

  it('email absent AND no eppn → throws (no anchor to JIT from)', async () => {
    await expectRejectedToContain(
      async () =>
        SAMLAuthenticationManager.promises.findOrCreateUser(
          samlProfile({ email: undefined, eduPersonPrincipalName: undefined }),
          {},
          { providerId: '1', ssoRole: 'local' }
        ),
      'no email attribute and no eppn/nameID'
    )
  })
})

describe('R1 synthetic-email JIT — OIDC manager', () => {
  beforeEach(() => resetState())

  it('email claim present → unchanged (no flag)', async () => {
    await OIDCAuthenticationManager.promises.findOrCreateUser(
      oidcProfile(),
      {},
      { providerId: 'oidc', ssoRole: 'local' }
    )
    expect(globalThis.__createdUsers[0].email).toBe('real@example.org')
    expect(globalThis.__tpiLinkCalls[0].externalData).toBeNull()
  })

  it('email claim absent + sub present → JIT <sub>@siteUrl host + flag on the identifier', async () => {
    const user = await OIDCAuthenticationManager.promises.findOrCreateUser(
      oidcProfile({ emails: undefined }),
      {},
      { providerId: 'oidc', ssoRole: 'local' }
    )
    expect(user._id).toBe('u-new')
    expect(globalThis.__createdUsers[0].email).toBe('sub-42@home-a.example')
    // the flag travels into the thirdPartyIdentifier externalData
    expect(globalThis.__tpiLinkCalls[0].externalData).toEqual({ syntheticEmail: true })
  })

  it('env knob OVERLEAF_OIDC_SYNTHETIC_EMAIL_DOMAIN overrides the siteUrl host', async () => {
    process.env.OVERLEAF_OIDC_SYNTHETIC_EMAIL_DOMAIN = 'synth.example'
    await OIDCAuthenticationManager.promises.findOrCreateUser(
      oidcProfile({ emails: undefined }),
      {},
      { providerId: 'oidc', ssoRole: 'local' }
    )
    expect(globalThis.__createdUsers[0].email).toBe('sub-42@synth.example')
  })

  it('email claim absent AND no sub → throws (no anchor to JIT from)', async () => {
    await expectRejectedToContain(
      async () =>
        OIDCAuthenticationManager.promises.findOrCreateUser(
          oidcProfile({ emails: undefined, id: undefined }),
          {},
          { providerId: 'oidc', ssoRole: 'local' }
        ),
      'no email claim and no sub'
    )
  })
})
