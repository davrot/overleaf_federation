// ssoCertExpiry.mjs — plan/10 Phase 4: SSO/SP cert-expiry alerts (ops runbook).
//
// Pure X.509 notAfter parsing + one boot-time sweep over the certs THIS
// instance can read locally:
//   1. `ssoConfigs.spMetadata.publicCert` (inline PEM, plan 11) — OUR SP
//      metadata signing cert.
//   2. env-mode SAML IdP cert (OVERLEAF_SAML_IDP_CERT path).
//   3. each enabled SAML provider `idpCert` (path — the cert we TRUST the
//      IdP/proxy to sign assertions with; for eduGAIN this is the proxy's
//      signing cert).
// `logger.warn` per cert whose notAfter is within `sso.certExpiryWarnDays`
// (default 30d; override via env `SSO_CERT_EXPIRY_WARN_DAYS`) or already
// expired. Ops subscribes to the `sso cert expiry:` log lines (runbook in
// FINDINGS.md §"eduGAIN interop"). Expiry of the *proxy's* metadata on the
// DFN/eduGAIN side is metadata-URL monitoring (ops), not app-parsed.
//
// Never-throws by contract: missing/unparseable certs are returned as
// `{ label, error }` rows and WARN-logged — the app must not fail boot.

import { X509Certificate } from 'node:crypto'
import fs from 'node:fs'
import logger from '@overleaf/logger'

const PEM_BLOCK_RE =
  /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g

/**
 * Split arbitrary cert-ish text (inline PEM, concatenated certs) into its
 * `-----BEGIN CERTIFICATE-----…END…-----` blocks.
 * @param {string} [pem]
 * @returns {string[]}
 */
export function extractCertificates(pem) {
  if (typeof pem !== 'string' || !pem) {
    return []
  }
  return pem.match(PEM_BLOCK_RE) || []
}

/**
 * Parse one PEM block into an expiry descriptor.
 * @param {string} pemBlock
 * @param {Date} [now]
 * @returns {{ notAfter: string, subject: string, daysLeft: number }}
 * @throws {Error} when the block is not a parseable X.509 cert.
 */
export function certExpiryInfo(pemBlock, now = new Date()) {
  const cert = new X509Certificate(pemBlock)
  const notAfter = new Date(cert.validTo) // node parses "MMM d HH:mm:ss yyyy GMT"
  return {
    notAfter: notAfter.toISOString(),
    subject: cert.subject,
    daysLeft: Math.ceil((notAfter.getTime() - now.getTime()) / (24 * 3600 * 1000)),
  }
}

/**
 * Parse multi-cert PEM text into expiry descriptors.
 * @param {string} [pem]
 * @param {Date} [now]
 * @returns {Array<{ notAfter: string, subject: string, daysLeft: number }>}
 */
export function parseCertExpiry(pem, now = new Date()) {
  return extractCertificates(pem).map((block) => certExpiryInfo(block, now))
}

/**
 * Warning window (days) from env (no settings-namespace entry needed for a
 * single ops knob); defaults to 30.
 * @returns {number}
 */
export function certExpiryWarnDays() {
  const n = Number(process.env.SSO_CERT_EXPIRY_WARN_DAYS)
  return Number.isFinite(n) && n >= 0 ? n : 30
}

function _sweepInline(label, pem, now, push) {
  const certs = extractCertificates(pem)
  if (!certs.length) {
    if (pem === undefined || pem === null || pem === '') {
      return // absence is not an alert (SP cert is optional; IdP cert arrives with the provider)
    }
    push({ label, error: 'no X.509 certificate block found' })
    return
  }
  for (const block of certs) {
    try {
      push({ label, ...certExpiryInfo(block, now) })
    } catch (e) {
      push({ label, error: String(e.message || e) })
    }
  }
}

function _sweepPath(label, path, now, push) {
  let pem
  try {
    pem = fs.readFileSync(path, 'utf8')
  } catch (e) {
    push({ label, error: `cannot read cert file ${path}: ${e.message}` })
    return
  }
  _sweepInline(label, pem, now, push)
}

/**
 * Boot-time sweep (called from the saml-authentication module `start()`,
 * mounted only when SAML is enabled — the only mode where these certs bind).
 * Returns all parsed rows; WARN-logs entries within the window.
 * @param {{ now?: Date }} [opts]
 * @returns {Promise<Array<{ label: string, notAfter?: string, subject?: string, daysLeft?: number, error?: string }>>}
 */
export async function sweepSsoCertExpiry({ now = new Date() } = {}) {
  const rows = []
  const push = (row) => rows.push(row)

  // ① OUR SP metadata signing cert (plan 11, inline in ssoConfigs).
  let spCert
  try {
    const { loadSSOConfig } = await import('./ssoConfigLoader.mjs')
    const config = await loadSSOConfig()
    spCert = config?.spMetadata?.publicCert
  } catch {
    spCert = undefined
  }
  _sweepInline('sp-metadata:publicCert', spCert, now, push)

  // ② env-mode SAML IdP cert.
  const envCert = process.env.OVERLEAF_SAML_IDP_CERT
  if (envCert) {
    _sweepPath('saml-env:OVERLEAF_SAML_IDP_CERT', envCert, now, push)
  }

  // ③ enabled SAML providers (DB mode).
  let providers = []
  try {
    const { getEnabledProviders } = await import('./ssoConfigLoader.mjs')
    providers = (await getEnabledProviders()).filter((p) => p.type === 'saml')
  } catch {
    providers = []
  }
  for (const provider of providers) {
    if (!provider.idpCert) continue
    _sweepPath(
      `saml-provider:${provider.id}:${provider.issuer || 'unknown-issuer'}`,
      provider.idpCert,
      now,
      push,
    )
  }

  const warnDays = certExpiryWarnDays()
  for (const row of rows) {
    if (row.error) {
      logger.warn(
        { cert: row.label, error: row.error },
        'sso cert expiry: cert unreadable — fix the cert (runbook: FINDINGS.md)',
      )
    } else if (row.daysLeft <= 0) {
      logger.warn(
        { cert: row.label, notAfter: row.notAfter, daysLeft: row.daysLeft },
        'sso cert expiry: EXPIRED — rotate now (runbook: FINDINGS.md)',
      )
    } else if (row.daysLeft <= warnDays) {
      logger.warn(
        { cert: row.label, notAfter: row.notAfter, daysLeft: row.daysLeft },
        'sso cert expiry: expiring within warning window (runbook: FINDINGS.md)',
      )
    }
  }
  return rows
}
