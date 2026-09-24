import { vi, describe, it, expect, beforeAll, beforeEach } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { execSync } from 'node:child_process'

// plan/10 Phase 4: SSO/SP cert-expiry alerts (ops runbook).
//  - extractCertificates / certExpiryInfo / parseCertExpiry (pure X.509 notAfter)
//  - sweepSsoCertExpiry: spMetadata.publicCert (inline) + env path + provider path
//  - never-throws contract; warn-days env knob
//
// Certs generated via openssl in beforeAll (no fixtures committed).
// ssoConfigLoader mocked (globalThis store, repo pattern).

const store = (globalThis.__SSO_TEST_STORE = globalThis.__SSO_TEST_STORE || {
  dbConfig: null,
})

vi.mock('@overleaf/logger', () => ({
  default: {
    info: () => {},
    warn: () => {},
    error: () => {},
    debug: () => {},
  },
}))
vi.mock('../../ssoConfigLoader.mjs', () => ({
  loadSSOConfig: async () => (store.dbConfig ? store.dbConfig : null),
  getEnabledProviders: async () =>
    (store.dbConfig?.providers || []).filter((p) => p?.enabled),
  isSAMLEnabled: async () => !!store.dbConfig,
  isLDAPEnabled: async () => false,
  isOIDCEnabled: async () => false,
  clearConfigCache: () => {},
}))

import {
  extractCertificates,
  certExpiryInfo,
  parseCertExpiry,
  certExpiryWarnDays,
  sweepSsoCertExpiry,
} from '../../ssoCertExpiry.mjs'

// --- openssl-generated certs (90d normal / 10d warning / 1d near-expired) ---
let tmpDir
let cert90
let cert10
let cert1

function genCert(days, subject) {
  const keyFile = path.join(tmpDir, `${subject}-${days}.key`)
  const certFile = path.join(tmpDir, `${subject}-${days}.pem`)
  execSync(
    `openssl req -x509 -newkey rsa:2048 -keyout '${keyFile}' -out '${certFile}' ` +
      `-days ${days} -subj '/CN=${subject} OU=CertExpiryTest O=overleaf-fed' ` +
      `-passout pass:x 2>/dev/null`,
  )
  return fs.readFileSync(certFile, 'utf8')
}

beforeAll(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'certexpirey-'))
  cert90 = genCert(90, 'sp-normal')
  cert10 = genCert(10, 'sp-warning')
  cert1 = genCert(1, 'sp-near')
})

beforeEach(() => {
  store.dbConfig = null
  delete process.env.SSO_CERT_EXPIRY_WARN_DAYS
  delete process.env.OVERLEAF_SAML_IDP_CERT
})

describe('extractCertificates', () => {
  it('returns [] for empty/absent', () => {
    expect(extractCertificates(undefined)).toEqual([])
    expect(extractCertificates('')).toEqual([])
    expect(extractCertificates(null)).toEqual([])
  })

  it('extracts two concatenated certs', () => {
    const blocks = extractCertificates(cert90 + '\n' + cert10)
    expect(blocks).toHaveLength(2)
    expect(blocks[0]).toContain('BEGIN CERTIFICATE')
  })

  it('ignores non-PEM text', () => {
    expect(extractCertificates('not a cert at all')).toEqual([])
  })
})

describe('certExpiryInfo / parseCertExpiry', () => {
  it('parses a 90-day cert: daysLeft in (60, 90]', () => {
    const info = certExpiryInfo(cert90)
    expect(info.daysLeft).toBeGreaterThan(60)
    expect(info.daysLeft).toBeLessThanOrEqual(90)
    expect(info.notAfter).toMatch(/^\d{4}-\d{2}-\d{2}T/)
    expect(info.subject).toContain('CN=sp-normal')
  })

  it('parses a 10-day cert: daysLeft in (0, 10]', () => {
    const info = certExpiryInfo(cert10)
    expect(info.daysLeft).toBeGreaterThan(0)
    expect(info.daysLeft).toBeLessThanOrEqual(10)
  })

  it('a 1-day cert against a "now" 2d ahead ⇒ daysLeft <= 0', () => {
    const now = new Date(Date.now() + 2 * 24 * 3600 * 1000)
    const info = certExpiryInfo(cert1, now)
    expect(info.daysLeft).toBeLessThanOrEqual(0)
  })

  it('parseCertExpiry on multi-cert PEM returns one row per cert', () => {
    const rows = parseCertExpiry(cert10 + '\n' + cert1)
    expect(rows).toHaveLength(2)
  })
})

describe('certExpiryWarnDays', () => {
  it('defaults to 30', () => {
    expect(certExpiryWarnDays()).toBe(30)
  })

  it('reads env override', () => {
    process.env.SSO_CERT_EXPIRY_WARN_DAYS = '14'
    expect(certExpiryWarnDays()).toBe(14)
  })

  it('falls back to 30 on non-finite / negative', () => {
    process.env.SSO_CERT_EXPIRY_WARN_DAYS = 'oops'
    expect(certExpiryWarnDays()).toBe(30)
    process.env.SSO_CERT_EXPIRY_WARN_DAYS = '-5'
    expect(certExpiryWarnDays()).toBe(30)
  })
})

describe('sweepSsoCertExpiry', () => {
  it('empty/no-cert config ⇒ no rows (absence is not an alert)', async () => {
    store.dbConfig = { _id: '1' }
    const rows = await sweepSsoCertExpiry()
    expect(rows).toEqual([])
  })

  it('flags spMetadata.publicCert inline (90d row, no error)', async () => {
    store.dbConfig = { _id: '1', spMetadata: { publicCert: cert90 } }
    const rows = await sweepSsoCertExpiry()
    expect(rows).toHaveLength(1)
    expect(rows[0].label).toBe('sp-metadata:publicCert')
    expect(rows[0].daysLeft).toBeGreaterThan(60)
    expect(rows[0].error).toBeUndefined()
  })

  it('flags provider idpCert via file path', async () => {
    const p = path.join(tmpDir, 'provider.pem')
    fs.writeFileSync(p, cert10)
    store.dbConfig = {
      _id: '1',
      providers: [{ id: 'p1', type: 'saml', enabled: true, issuer: 'https://idp.example', idpCert: p }],
    }
    const rows = await sweepSsoCertExpiry()
    expect(rows).toHaveLength(1)
    expect(rows[0].label).toBe('saml-provider:p1:https://idp.example')
    expect(rows[0].daysLeft).toBeGreaterThan(0)
  })

  it('missing file ⇒ error row, never throws', async () => {
    store.dbConfig = {
      _id: '1',
      providers: [{ id: 'p1', type: 'saml', enabled: true, issuer: 'https://idp.example', idpCert: path.join(tmpDir, 'nope.pem') }],
    }
    const rows = await sweepSsoCertExpiry()
    expect(rows[0].error).toMatch(/cannot read cert file/)
  })

  it('garbage PEM ⇒ error row, doesn\'t crash', async () => {
    store.dbConfig = { _id: '1', spMetadata: { publicCert: '---- not pem ----' } }
    const rows = await sweepSsoCertExpiry()
    expect(rows[0].error).toMatch(/no X.509 certificate block/)
  })

  it('env-mode OVERLEAF_SAML_IDP_CERT is swept', async () => {
    const p = path.join(tmpDir, 'env.pem')
    fs.writeFileSync(p, cert90)
    process.env.OVERLEAF_SAML_IDP_CERT = p
    store.dbConfig = { _id: '1' }
    const rows = await sweepSsoCertExpiry()
    expect(rows[0].label).toBe('saml-env:OVERLEAF_SAML_IDP_CERT')
    expect(rows[0].daysLeft).toBeGreaterThan(60)
  })

  it('near-expired cert against future "now" ⇒ daysLeft within warn window', async () => {
    store.dbConfig = { _id: '1', spMetadata: { publicCert: cert1 } }
    const now = new Date(Date.now() + 50 * 24 * 3600 * 1000)
    const rows = await sweepSsoCertExpiry({ now })
    expect(rows[0].daysLeft).toBeLessThanOrEqual(30)
  })
})
