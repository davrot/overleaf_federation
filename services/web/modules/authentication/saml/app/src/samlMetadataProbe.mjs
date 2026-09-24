// samlMetadataProbe.mjs — plan/10 Phase 2 (G3): admin SAML metadata probe.
//
// Fetch a SAML metadata URL (IdP/proxy/registry metadata), parse it, and
// verify:
//   1. it parses as SAML 2.0 Metadata (EntityDescriptor),
//   2. entityID,
//   3. signing KeyDescriptor → extracted cert (notAfter + cert itself),
//   4. the XML-DSig signature of the metadata element (self-verification:
//      signed by the signing KeyDescriptor cert it publishes),
//   5. OPTIONAL pin: extracted cert vs the provider's trusted `idpCert`
//      (PEM path) — `matchesTrustedCert` (cert-rotation mismatch is a
//      hard failure, so the admin knows the metadata URL or the trusted
//      cert is stale),
//   6. registrability markers: `<Organization>` + `<ContactPerson>`
//      (required for eduGAIN/GEANT SP/IdP registration metadata).
//
// Uses only declared deps: global fetch (undici), @xmldom/xmldom (DOM
// parse), and the xml-crypto v6 that `@node-saml/node-saml` signs with
// (loaded nested — its API is what the sign side uses, so verify mirrors
// it exactly; importing it nested is zero new deps).
//
// Pure + side-effect-free except the fetch; exported for unit tests.

import { createRequire } from 'node:module'
import { DOMParser } from '@xmldom/xmldom'
import { X509Certificate } from 'node:crypto'

// The signer is the nested xml-crypto; verification must use the SAME
// library version to avoid canonicalization drift.
const requireX = createRequire(import.meta.url)
const xmlCrypto = requireX('@node-saml/node-saml/node_modules/xml-crypto')

const PROBE_TIMEOUT_MS = 15000

/**
 * Extract signing/registrability facts from SAML metadata XML.
 * @param {string} xml metadata document
 * @returns {{
 *   entityID: string|null,
 *   signed: boolean,
 *   certs: Array<{ notAfter: string, subject: string, daysLeft: number }>,
 *   certPem: string|null,            // first signing KeyDescriptor cert (PEM)
 *   hasOrganization: boolean,
 *   hasContactPerson: boolean,
 * }}
 */
export function extractSigningInfo(xml) {
  const out = {
    entityID: null,
    signed: false,
    certs: [],
    certPem: null,
    hasOrganization: false,
    hasContactPerson: false,
  }
  if (typeof xml !== 'string' || !xml.trim()) {
    return out
  }
  const entityMatch = xml.match(/\bentityID="([^"]*)"/)
  out.entityID = entityMatch ? entityMatch[1] : null
  out.hasOrganization = /<[^>]*Organization(Name|DisplayName|URL)[^>]*>/.test(xml) && xml.includes('Organization')
  // xmlbuilder emits `ContactPerson` (or prefixed, esp. `<nsX:ContactPerson`)
  out.hasContactPerson = /<[^>]*ContactPerson[^>]*\s/.test(xml) || /ContactPerson/.test(xml)
  const kdMatch = xml.match(/use="signing"[^>]*>([\s\S]*?)<\/K\w*eyDescriptor>|KeyDescriptor[^>]*use="signing"[^>]*>([\s\S]*?)<\/KeyDescriptor>/)
  const kd = kdMatch && (kdMatch[1] || kdMatch[2])
  if (kd) {
    out.signed = true
    const certBody = kd.match(/X509Certificate>([\s\S]+?)</)
    if (certBody) {
      out.certPem =
        '-----BEGIN CERTIFICATE-----\n' +
        certBody[1].replace(/\s+/g, '') +
        '\n-----END CERTIFICATE-----'
      try {
        const cert = new X509Certificate(out.certPem)
        const notAfter = new Date(cert.validTo)
        out.certs.push({
          notAfter: notAfter.toISOString(),
          subject: cert.subject,
          daysLeft: Math.ceil((notAfter.getTime() - Date.now()) / (24 * 3600 * 1000)),
        })
      } catch {
        out.certPem = null // present but unparseable — treat as unverifiable
      }
    }
  } else if (/<Signature[\s>]/.test(xml)) {
    // signed but no `use="signing"` KeyDescriptor (unusual) — flag but no cert
    out.signed = true
  }
  return out
}

/**
 * Verify the metadata element's XML-DSig against a public cert PEM
 * (mirrors @node-saml/node-saml assertion verification: load the Signature
 * node, `checkSignature(fullXml)` with `publicCert`).
 * @param {string} xml metadata document
 * @param {string} certPem public certificate to verify against
 * @returns {boolean}
 */
export function verifyMetadataSignature(xml, certPem) {
  try {
    const doc = new DOMParser().parseFromString(xml, 'text/xml')
    const signatureNode = doc.getElementsByTagName('Signature')[0]
    if (!signatureNode) {
      return false
    }
    const sig = new xmlCrypto.SignedXml()
    sig.publicCert = certPem
    sig.loadSignature(signatureNode)
    return sig.checkSignature(xml) === true
  } catch {
    return false
  }
}

/**
 * Probe a SAML metadata URL end-to-end.
 *
 * @param {string} url metadata URL
 * @param {{
 *   trustedPem?: string,   // the provider's pinned idpCert (PEM) — optional pin
 *   timeoutMs?: number,    // fetch timeout (default 15s)
 * }} [opts]
 * @returns {Promise<{
 *   reachable: boolean,
 *   message: string,
 *   entityID?: string,
 *   signed?: boolean,
 *   signatureValid?: boolean,
 *   matchesTrustedCert?: boolean,
 *   certNotAfter?: string,
 *   certDaysLeft?: number,
 *   hasOrganization?: boolean,
 *   hasContactPerson?: boolean,
 *   error?: string,
 * }>}
 */
export async function probeSamlMetadataUrl(url, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? PROBE_TIMEOUT_MS
  let body
  try {
    const res = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(timeoutMs) })
    if (res.status >= 400) {
      return { reachable: false, message: `metadata URL returned HTTP ${res.status}`, error: 'http-error' }
    }
    body = await res.text()
  } catch (e) {
    return { reachable: false, message: `fetch failed: ${e.message}`, error: String(e.message || e) }
  }
  if (!body || !/<\?xml|<[^>]*EntityDescriptor/.test(body)) {
    return { reachable: true, message: 'not SAML metadata (no EntityDescriptor in body)', error: 'not-xml' }
  }

  const info = extractSigningInfo(body)
  const out = {
    reachable: true,
    entityID: info.entityID || undefined,
    signed: info.signed,
    hasOrganization: info.hasOrganization,
    hasContactPerson: info.hasContactPerson,
  }
  if (info.certPem) {
    out.certNotAfter = info.certs[0]?.notAfter
    out.certDaysLeft = info.certs[0]?.daysLeft
    out.signatureValid = verifyMetadataSignature(body, info.certPem)
    if (opts.trustedPem) {
      // pin check: extracted cert == trusted cert (X.509 fingerprint —
      // ignores PEM framing differences)
      try {
        const trustedFp = new X509Certificate(opts.trustedPem).fingerprint256
        const extractedFp = new X509Certificate(info.certPem).fingerprint256
        out.matchesTrustedCert = trustedFp === extractedFp
      } catch {
        out.matchesTrustedCert = false
      }
    }
  } else {
    out.signatureValid = false
  }

  if (!out.signed) {
    out.message = 'metadata reachable but UNSIGNED (eduGAIN/GEANT registry metadata must be signed — verify manually before enabling)'
    return out
  }
  if (!out.signatureValid) {
    out.message = 'metadata signature INVALID (do not trust this metadata URL until the mismatch is resolved)'
    return out
  }
  if (out.matchesTrustedCert === false) {
    out.message = 'metadata signed by a DIFFERENT cert than the trusted idpCert (cert rotation in progress or wrong metadata URL — update the IdP Certificate path)'
    return out
  }
  out.message = `metadata OK — entityID ${out.entityID || '?'}, signature valid${out.certNotAfter ? `, cert expires ${out.certNotAfter}` : ''}`
  return out
}
