import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest'
import { generateKeyPairSync } from 'node:crypto'

/**
 * SAML SP metadata (plan 11, TODO-223faa6a) — the XML served at GET
 * /saml/meta is the artifact submitted to identity registries (GEANT AAI
 * Sandbox/production, eduGAIN, DFN-AAI MDV). It MUST be SP-direction:
 * our own entityID (NOT an IdP issuer), our Organization + ContactPerson,
 * and signed IFF BOTH spMetadata.privateKey + publicCert are present
 * (plan 11 §2.2 — v5 seam: signMetadata + privateKey + publicCerts +
 * signatureAlgorithm 'sha256' required together).
 *
 * All app/db deps are mocked via `globalThis.__*` (bootstrap runs
 * vi.resetAllMocks + resetModules after each test). The v5
 * @node-saml/node-saml lib runs for real (pure, no network).
 */

// Real RSA private key for the signed-metadata path (v5 computes a
// RSA-SHA256 signature with it; the cert string is only embedded, not
// validated, at metadata-generation time).
const SP_PRIVATE_KEY = generateKeyPairSync('rsa', { modulusLength: 1024 })
  .privateKey.export({ type: 'pkcs8', format: 'pem' })
// Stub cert (registry just embeds the base64 body). Body is a distinct token.
const CERT_BODY = 'Zm9yLXRlc3Qta2V5LWVtYmVkZC1vbmx5'
const STUB_CERT =
  `-----BEGIN CERTIFICATE-----\n${CERT_BODY}\n-----END CERTIFICATE-----`

vi.mock('@overleaf/settings', () => ({
  default: {
    siteUrl: 'https://home.example.com',
    saml: { attUserId: 'eduPersonPrincipalName', attEmail: 'email' },
  },
}))

vi.mock('@overleaf/logger', () => ({
  default: {
    debug: vi.fn(), info: vi.fn(), warn: vi.fn(), log: vi.fn(),
    error: vi.fn(), err: vi.fn(), fatal: vi.fn(),
  },
}))

vi.mock('passport', () => ({ default: {} }))

vi.mock('../../../../app/src/infrastructure/mongodb.mjs', () => ({
  db: {
    ssoConfigs: {
      findOne: () => Promise.resolve(globalThis.__ssoDoc ?? null),
      replaceOne: (f, doc) => {
        globalThis.__replacedDoc = doc
        return Promise.resolve({ value: { value: doc } })
      },
    },
  },
}))

vi.mock('../../../../modules/authentication/ssoConfigLoader.mjs', () => ({
  loadSSOConfig: () => Promise.resolve(globalThis.__ssoDoc ?? null),
  getProviderById: () => Promise.resolve(null),
  getSAMLProviderConfig: () => Promise.resolve(null),
  isSAMLEnabled: () =>
    Promise.resolve(
      (globalThis.__ssoDoc?.providers ?? [])
        .some(p => p.type === 'saml' && p.enabled)
        || !!process.env.EXTERNAL_AUTH?.includes('saml'),
    ),
  isOIDCEnabled: () => Promise.resolve(false),
  clearConfigCache: () => (globalThis.__cleared = true),
}))

vi.mock('../../../../app/src/Features/Authentication/ssoRoleEvaluator.mjs', () => ({
  default: {},
  evaluateAttrFilter: () => ({ role: 'local' }),
  persistedRoleForProvider: () => null,
  sanitizeAttrFilter: (v) => v,
  auditSsoLoginDenied: () => Promise.resolve({}),
}))

vi.mock('../../../../modules/authentication/saml/app/src/SAMLModuleManager.mjs', () => ({
  default: {
    ensureStrategy: () => Promise.resolve(),
    initSettings: () => Promise.resolve(),
    initPolicy: () => {},
  },
}))
vi.mock('../../../../modules/authentication/saml/app/src/SAMLAuthenticationManager.mjs',
  () => ({ default: {} }))
vi.mock('../../../../app/src/Features/Authentication/AuthenticationController.mjs',
  () => ({ default: {} }))
vi.mock('../../../../app/src/Features/User/UserController.mjs', () => ({ default: {} }))
vi.mock('../../../../app/src/Features/Authentication/AuthenticationErrors.mjs',
  () => ({ handleAuthenticateErrors: () => {} }))

import SAMLAuthenticationController, { buildSPMetadataXml, spFilename }
  from '../../../../modules/authentication/saml/app/src/SAMLAuthenticationController.mjs'
import SSOAdminController
  from '../../../../modules/authentication/admin/app/src/SSOAdminController.mjs'

const MASK = '••••••••'
let savedEA
beforeEach(() => {
  savedEA = process.env.EXTERNAL_AUTH
  delete globalThis.__ssoDoc
  delete globalThis.__replacedDoc
  delete globalThis.__body
  delete globalThis.__json
  delete globalThis.__sent404
})
afterEach(() => {
  if (savedEA === undefined) delete process.env.EXTERNAL_AUTH
  else process.env.EXTERNAL_AUTH = savedEA
  delete globalThis.__cleared
})

describe('buildSPMetadataXml (plan 11 §2.2)', () => {
  it('defaults the SP entityID to <siteOrigin>/saml and our ACS/SLO URLs (BUG 1/5)', () => {
    const xml = buildSPMetadataXml(undefined, 'https://home.example.com')
    expect(xml).toContain('entityID="https://home.example.com/saml"')
    expect(xml).toContain('https://home.example.com/saml/login/callback')
    expect(xml).toContain('https://home.example.com/saml/logout/callback')
    expect(xml).toContain(
      'urn:oasis:names:tc:SAML:1.1:nameidentifier-format:persistent',
    )
  })

  it('uses the configured spMetadata.spEntityId override', () => {
    const xml = buildSPMetadataXml(
      { spEntityId: 'https://sp.example.org/instance' },
      'https://home.example.com',
    )
    expect(xml).toContain('entityID="https://sp.example.org/instance"')
  })

  it('is SP-direction: uses own id, never an IdP issuer', () => {
    const xml = buildSPMetadataXml(
      { spEntityId: 'https://sp.example.org/x', organization: { name: 'O' } },
      'https://home.example.com',
    )
    expect(xml).toContain('entityID="https://sp.example.org/x"')
    expect(xml).not.toContain('idp.example-idp')
  })

  it('embeds Organization + ContactPerson (BUG 2: registrable metadata)', () => {
    const xml = buildSPMetadataXml(
      {
        organization: {
          name: 'Overleaf Ltd',
          displayName: 'Overleaf',
          url: 'https://overleaf.example',
        },
        contacts: [
          { contactType: 'technical', email: 'it@example.com' },
          { contactType: 'support', email: 'ops@example.com' },
        ],
      },
      'https://home.example.com',
    )
    expect(xml).toContain('<OrganizationName xml:lang="en">Overleaf Ltd</OrganizationName>')
    expect(xml).toContain(
      '<OrganizationDisplayName xml:lang="en">Overleaf</OrganizationDisplayName>',
    )
    expect(xml).toContain(
      '<OrganizationURL xml:lang="en">https://overleaf.example</OrganizationURL>',
    )
    expect(xml).toContain('contactType="technical"')
    expect(xml).toContain('it@example.com')
    expect(xml).toContain('contactType="support"')
    expect(xml).toContain('ops@example.com')
  })

  it('defaults contactType to "technical" and drops rows without an email', () => {
    const xml = buildSPMetadataXml(
      {
        contacts: [
          { email: 'no-type@example.com' },
          { contactType: 'legal', email: '' },
        ],
      },
      'https://home.example.com',
    )
    expect(xml).toContain('<EmailAddress>no-type@example.com</EmailAddress>')
    expect(xml).toContain('ContactPerson contactType="technical"')
  })

  it('is unsigned by default and when only ONE half of the key pair is set', () => {
    const unsigned = buildSPMetadataXml({}, 'https://home.example.com')
    expect(unsigned).not.toContain('<KeyDescriptor')
    expect(unsigned).not.toContain('<Signature ')

    const keyOnly = buildSPMetadataXml(
      { privateKey: SP_PRIVATE_KEY },
      'https://home.example.com',
    )
    expect(keyOnly).not.toContain('<KeyDescriptor')
    const certOnly = buildSPMetadataXml(
      { publicCert: STUB_CERT },
      'https://home.example.com',
    )
    expect(certOnly).not.toContain('<KeyDescriptor')
  })

  it('is signed IFF BOTH privateKey + publicCert are present (BUG 3)', () => {
    const signed = buildSPMetadataXml(
      { privateKey: SP_PRIVATE_KEY, publicCert: STUB_CERT },
      'https://home.example.com',
    )
    expect(signed).toContain('use="signing"')
    expect(signed).toContain('<Signature ')
    // the cert body is what the registry sees (embedded), not the private key
    expect(signed).toContain(CERT_BODY)
  })
})

describe('spFilename', () => {
  it('derives a safe attachment filename from the SP entityID', () => {
    expect(spFilename(undefined, 'https://home.example.com')).toBe(
      'home.example.com-meta.xml',
    )
    expect(spFilename({ spEntityId: 'sp.example.org' }, 'https://home.example.com')).toBe(
      'sp.example.org-meta.xml',
    )
  })
})

describe('GET /saml/meta route (BUG 5: no more 500 when SAML disabled)', () => {
  it('404s "SAML is not enabled" (graceful, no deref) when no SAML provider', async () => {
    delete process.env.EXTERNAL_AUTH
    globalThis.__ssoDoc = { providers: [] }
    const res = {
      status: (v) =>
        v === 404
          ? { send: (s) => (globalThis.__sent404 = s) }
          : { send: (s) => (globalThis.__body = s) },
      contentType: () => ({}),
      setHeader: () => ({}),
      send: (s) => (globalThis.__body = s),
    }
    await SAMLAuthenticationController.getSPMetadata({}, res, () => {})
    expect(globalThis.__sent404).toBe('SAML is not enabled')
  })

  it('serves SP metadata with saml-metadata Content-Type when enabled', async () => {
    delete process.env.EXTERNAL_AUTH
    globalThis.__ssoDoc = {
      providers: [{ id: 's1', type: 'saml', enabled: true }],
      spMetadata: { organization: { name: 'Acme' } },
    }
    const headers = {}
    const res = {
      contentType: (v) => (headers['Content-Type'] = v),
      setHeader: (k, v) => (headers[k] = v),
      status: (v) => ({ send: (s) => (globalThis.__body = s) }),
      send: (s) => (globalThis.__body = s),
    }
    await SAMLAuthenticationController.getSPMetadata({}, res, () => {})
    expect(globalThis.__body).toContain('entityID="https://home.example.com/saml"')
    expect(globalThis.__body).toContain('Acme')
    expect(headers['Content-Type']).toContain('application/saml-metadata+xml')
    expect(headers['X-Content-Type-Options']).toBe('nosniff')
  })
})

describe('SSO admin spMetadata masking/restore (plan 11 §2.2)', () => {
  it('masks privateKey + publicCert on GET (non-sensitive fields intact)', async () => {
    globalThis.__ssoDoc = {
      _id: 'sso-settings',
      providers: [],
      spMetadata: {
        spEntityId: 'sp.example.org',
        organization: { name: 'A', displayName: 'B', url: 'https://a.b' },
        contacts: [{ contactType: 'technical', email: 'x@example.com' }],
        privateKey: 'REAL-PRIVATE',
        publicCert: 'REAL-CERT',
      },
    }
    const res = {
      json: (v) => (globalThis.__json = v),
      status: () => ({ json: (v) => (globalThis.__json = v) }),
    }
    await SSOAdminController.getConfig({}, res, () => {})
    expect(globalThis.__json.spMetadata.privateKey).toBe(MASK)
    expect(globalThis.__json.spMetadata.publicCert).toBe(MASK)
    expect(globalThis.__json.spMetadata.spEntityId).toBe('sp.example.org')
    expect(globalThis.__json.spMetadata.organization.name).toBe('A')
  })

  it('restores stored values when the sentinel is saved back (no key rotation)', async () => {
    globalThis.__ssoDoc = {
      _id: 'sso-settings',
      providers: [],
      spMetadata: { privateKey: 'REAL-PRIVATE', publicCert: 'REAL-CERT' },
    }
    const req = {
      body: {
        providers: [],
        spMetadata: { privateKey: MASK, publicCert: MASK, organization: { name: 'New' } },
      },
    }
    const res = {
      json: (v) => (globalThis.__json = v),
      status: (v) => ({ json: (w) => (globalThis.__json = w) }),
    }
    await SSOAdminController.saveConfig(req, res, () => {})
    expect(globalThis.__replacedDoc.spMetadata.privateKey).toBe('REAL-PRIVATE')
    expect(globalThis.__replacedDoc.spMetadata.publicCert).toBe('REAL-CERT')
    expect(globalThis.__replacedDoc.spMetadata.organization.name).toBe('New')
  })

  it('clears stored values when the sentinel is sent with nothing stored', async () => {
    globalThis.__ssoDoc = {
      _id: 'sso-settings',
      providers: [],
      spMetadata: { organization: { name: 'A' } },
    }
    const req = {
      body: {
        providers: [],
        spMetadata: { privateKey: MASK, publicCert: MASK, organization: { name: 'A' } },
      },
    }
    const res = {
      json: (v) => (globalThis.__json = v),
      status: (v) => ({ json: (w) => (globalThis.__json = w) }),
    }
    await SSOAdminController.saveConfig(req, res, () => {})
    expect(globalThis.__replacedDoc.spMetadata.privateKey).toBeUndefined()
    expect(globalThis.__replacedDoc.spMetadata.publicCert).toBeUndefined()
  })
})
