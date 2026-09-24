import { vi, describe, it, expect, beforeAll, afterAll } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { execSync } from 'node:child_process'
import express from 'express'

// plan/10 Phase 2 (G3): admin SAML metadata probe.
//  - extractSigningInfo (entityID / signing KeyDescriptor cert / org / contacts)
//  - verifyMetadataSignature (valid → true, tampered → false, wrong cert → false)
//  - probeSamlMetadataUrl end-to-end against a local express server that
//    serves our OWN signed SP metadata (generateServiceProviderMetadata —
//    the exact shape /saml/meta emits)
//  - controller wiring (POST → SSOAdminController.testProvider) with mocked
//    db (repo bootstrap pattern: vi.mock + globalThis store)

const { generateServiceProviderMetadata } = await import('@node-saml/passport-saml')

// admin controller deps (mocked before import)
const store = (globalThis.__SSO_TEST_STORE = globalThis.__SSO_TEST_STORE || {
  dbConfig: null,
})
vi.mock('@overleaf/logger', () => ({
  default: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
}))
vi.mock('../../../../app/src/infrastructure/mongodb.mjs', () => ({
  db: {
    ssoConfigs: {
      findOne: async () => (store.dbConfig ? store.dbConfig : null),
      replaceOne: async () => ({}),
      upsert: async () => ({}),
    },
  },
  connectionPromise: Promise.resolve(),
  connect: async () => {},
}))
vi.mock('../../ssoConfigLoader.mjs', () => ({
  loadSSOConfig: async () => (store.dbConfig ? store.dbConfig : null),
  getEnabledProviders: async () => (store.dbConfig?.providers || []).filter((p) => p?.enabled),
  getProviderById: async (id) => (store.dbConfig?.providers || []).find((p) => p.id === id) || null,
  isSAMLEnabled: async () => !!store.dbConfig,
  isLDAPEnabled: async () => false,
  isOIDCEnabled: async () => false,
  clearConfigCache: () => {},
}))
vi.mock('../../../../app/src/Features/Authentication/ssoRoleEvaluator.mjs', () => ({
  evaluateAttrFilter: () => ({ role: 'local' }),
  sanitizeAttrFilter: () => [],
}))

import {
  extractSigningInfo,
  verifyMetadataSignature,
  probeSamlMetadataUrl,
} from '../../saml/app/src/samlMetadataProbe.mjs'
import SSOAdminController from '../../admin/app/src/SSOAdminController.mjs'

let tmpDir
let key
let cert
let signedXml
let unsignedXml
let server
let base

beforeAll(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g3-probe-'))
  execSync(
    `openssl req -x509 -newkey rsa:2048 -nodes -keyout '${tmpDir}/k.pem' -out '${tmpDir}/c.pem' ` +
      `-days 60 -subj '/CN=g3-probe' 2>/dev/null`,
  )
  key = fs.readFileSync(path.join(tmpDir, 'k.pem'), 'utf8')
  cert = fs.readFileSync(path.join(tmpDir, 'c.pem'), 'utf8')
  execSync(
    `openssl req -x509 -newkey rsa:2048 -nodes -keyout '${tmpDir}/wk.pem' -out '${tmpDir}/wrong.pem' ` +
      `-days 60 -subj '/CN=g3-wrong' 2>/dev/null`,
  )
  const baseParams = {
    issuer: 'https://idp.example.com/shibboleth',
    callbackUrl: 'https://sp.example/saml/login/callback',
    identifierFormat: 'urn:oasis:cards:subject:entropy',
    metadataOrganization: {
      OrganizationName: [{ '@xml:lang': 'en', '#text': 'Example GmbH' }],
      OrganizationURL: ['https://example.org'],
    },
    metadataContactPerson: [{ '@contactType': 'technical', 'EmailAddress': ['it@example.org'] }],
  }
  signedXml = generateServiceProviderMetadata({
    ...baseParams,
    signMetadata: true,
    privateKey: key,
    publicCerts: [cert],
    signatureAlgorithm: 'sha256',
  })
  unsignedXml = generateServiceProviderMetadata(baseParams)
})

afterAll(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true })
})

// live local server: serves our own (signed/unsigned) metadata
beforeAll(async () => {
  const app = express()
  app.get('/meta.xml', (req, res) => res.type('application/saml-metadata+xml').send(signedXml))
  app.get('/unsigned.xml', (req, res) => res.type('application/saml-metadata+xml').send(unsignedXml))
  app.get('/tampered.xml', (req, res) =>
    res
      .type('application/saml-metadata+xml')
      .send(signedXml.replace('entityID="https://idp.example.com/shibboleth"', 'entityID="https://evil.example/saml"')),
  )
  app.get('/not-saml', (req, res) => res.send('<html>login</html>'))
  server = app.listen(0)
  await new Promise((r) => server.on('listening', r))
  base = `http://127.0.0.1:${server.address().port}`
})

afterAll(async () => {
  await new Promise((r) => server.close(r))
})

describe('extractSigningInfo', () => {
  it('empty input ⇒ safe defaults', () => {
    const info = extractSigningInfo('')
    expect(info.entityID).toBeNull()
    expect(info.signed).toBe(false)
    expect(info.certs).toEqual([])
  })

  it('our signed metadata: entityID + signing cert + org/contacts', () => {
    const info = extractSigningInfo(signedXml)
    expect(info.entityID).toBe('https://idp.example.com/shibboleth')
    expect(info.signed).toBe(true)
    expect(info.certPem).toContain('BEGIN CERTIFICATE')
    expect(info.certs).toHaveLength(1)
    expect(info.certs[0].daysLeft).toBeGreaterThan(30)
    expect(info.hasOrganization).toBe(true)
    expect(info.hasContactPerson).toBe(true)
  })

  it('unsigned metadata: signed=false, no cert', () => {
    const info = extractSigningInfo(unsignedXml)
    expect(info.entityID).toBe('https://idp.example.com/shibboleth')
    expect(info.signed).toBe(false)
    expect(info.certPem).toBeNull()
  })
})

describe('verifyMetadataSignature', () => {
  it('valid signature ⇒ true', () => {
    expect(verifyMetadataSignature(signedXml, cert)).toBe(true)
  })

  it('tampered subtree (entityID inside signed range) ⇒ false', () => {
    const tampered = signedXml.replace(
      'entityID="https://idp.example.com/shibboleth"',
      'entityID="https://evil.example/saml"',
    )
    expect(verifyMetadataSignature(tampered, cert)).toBe(false)
  })

  it('wrong signing cert ⇒ false', () => {
    const wrongCert = fs.readFileSync(
      path.join(tmpDir, 'wrong.pem'),
      'utf8',
    )
    expect(verifyMetadataSignature(signedXml, wrongCert)).toBe(false)
  })
})

describe('probeSamlMetadataUrl (live local server)', () => {
  it('signed metadata URL + matching pin ⇒ reachable + valid + matches', async () => {
    const out = await probeSamlMetadataUrl(`${base}/meta.xml`, { trustedPem: cert })
    expect(out.reachable).toBe(true)
    expect(out.signed).toBe(true)
    expect(out.signatureValid).toBe(true)
    expect(out.matchesTrustedCert).toBe(true)
    expect(out.entityID).toBe('https://idp.example.com/shibboleth')
    expect(out.certDaysLeft).toBeGreaterThan(30)
    expect(out.hasOrganization).toBe(true)
  })

  it('pin mismatch (trusted pem ≠ signing cert) ⇒ matchesTrustedCert=false', async () => {
    const wrongPem = fs.readFileSync('/tmp/certtest/cn90.pem', 'utf8')
    const out = await probeSamlMetadataUrl(`${base}/meta.xml`, { trustedPem: wrongPem })
    expect(out.signatureValid).toBe(true) // self-verify (own key) still passes
    expect(out.matchesTrustedCert).toBe(false)
  })

  it('tampered metadata ⇒ signature INVALID', async () => {
    const out = await probeSamlMetadataUrl(`${base}/tampered.xml`)
    expect(out.reachable).toBe(true)
    expect(out.signed).toBe(true)
    expect(out.signatureValid).toBe(false)
    expect(out.message).toMatch(/INVALID/)
  })

  it('unsigned metadata ⇒ signed=false + UNSIGNED warn', async () => {
    const out = await probeSamlMetadataUrl(`${base}/unsigned.xml`)
    expect(out.signed).toBe(false)
    expect(out.message).toMatch(/UNSIGNED/)
  })

  it('non-XML body ⇒ rejected as not SAML metadata', async () => {
    const out = await probeSamlMetadataUrl(`${base}/not-saml`)
    expect(out.reachable).toBe(true)
    expect(out.error).toBe('not-xml')
  })

  it('404 URL ⇒ reachable=false', async () => {
    const out = await probeSamlMetadataUrl(`${base}/missing`)
    expect(out.reachable).toBe(false)
  })
})

describe('SSOAdminController.testProvider (SAML metadataUrl wiring)', () => {
  it('provider.metadataUrl configured ⇒ probe path (success + details entityID)', async () => {
    store.dbConfig = {
      _id: '1',
      ldap: { enabled: false },
      providers: [
        {
          id: 'p1',
          type: 'saml',
          enabled: true,
          entryPoint: 'https://idp.example.com/sso/saml',
          metadataUrl: `${base}/meta.xml`,
          idpCert: path.join(tmpDir, 'c.pem'),
        },
      ],
    }
    let data
    const res = {
      json: (d) => (data = d),
      status: (n) => res,
      render: () => res,
    }
    await SSOAdminController.testProvider({ params: { providerId: 'p1' } }, res)
    expect(data.success).toBe(true)
    expect(data.details['entityID']).toBe('https://idp.example.com/shibboleth')
    expect(data.details['signature']).toBe('valid')
    expect(data.details['matches trusted idpCert']).toBe('yes')
    expect(data.details['registrability']).toMatch(/Organization \+ ContactPerson/)
  })

  it('metadataUrl with invalid signature ⇒ success=false + INVALID details', async () => {
    store.dbConfig = {
      _id: '1',
      ldap: { enabled: false },
      providers: [
        {
          id: 'p2',
          type: 'saml',
          enabled: true,
          entryPoint: 'https://idp.example.com/sso/saml',
          metadataUrl: `${base}/tampered.xml`,
          idpCert: path.join(tmpDir, 'c.pem'),
        },
      ],
    }
    let data
    const res = { json: (d) => (data = d), status: (n) => res, render: () => res }
    await SSOAdminController.testProvider({ params: { providerId: 'p2' } }, res)
    expect(data.success).toBe(false)
    expect(data.message).toMatch(/INVALID/)
  })

  it('no metadataUrl + unreachable entryPoint ⇒ legacy fetch-fail path', async () => {
    store.dbConfig = {
      _id: '1',
      ldap: { enabled: false },
      providers: [
        {
          id: 'p3',
          type: 'saml',
          enabled: true,
          entryPoint: 'http://127.0.0.1:1/nope',
          metadataUrl: '',
        },
      ],
    }
    let data
    const res = { json: (d) => (data = d), status: (n) => res, render: () => res }
    await SSOAdminController.testProvider({ params: { providerId: 'p3' } }, res)
    expect(data.success).toBe(false)
    expect(data.message).toMatch(/SAML test failed/)
  })
})
