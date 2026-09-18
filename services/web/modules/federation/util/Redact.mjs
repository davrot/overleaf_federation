// Log redaction for the federation module (06 §6).
//
// Structured logs and audit must NEVER contain:
//   - `code=<OIDC code>` (01 §8.1) — in any URL query / body
//   - `id_token` (token endpoint response) — written as `id_token: [REDACTED]`
//   - Client-assertion *values* — the S2S audit row holds `{iss, aud,
//     jtiHash}` (hashed, 03 §6); the body `payload` is logged only for
//     approved actions and only allow-listed fields
//   - The federation private-key material (private JWK `d`, PEM) — 02 §5
//   - Invite tokens (`encryptedToken`) — unchanged overleaf-cep behaviour
//
// Enforcement points (06 §6): the structured-logger filter (this module),
// the S2S router (assertion → `{iss, aud, jtiHash}`), and the oidc-provider
// token-endpoint response (provider logs at `debug`; the module raises it
// to `info`+ so the redacted shape is what appears).
//
// All helpers are pure and TOTAL (always return something usable) so a
// redaction bug can never 500 an audit/log write.

import crypto from 'node:crypto'

// The claim allow-list a redaction step may surface in logs (04 §8 meta
// allow-list, 06 §8). Everything else on a claims object is dropped.
export const CLAIM_LOG_ALLOWLIST = [
  'sub',
  'origin',
  'localName',
  'displayName',
  'institution',
]

// Private-side JWK fields that mark a key (or an object holding it) as
// private (06 §6).
const PRIVATE_JWK_FIELDS = ['d', 'p', 'q', 'dp', 'dq', 'qi']

/**
 * Return a copy of `value` with known secret keys redacted. Never mutates
 * the input (log objects are shared; in-place mutation leaks back into the
 * caller's request context).
 *
 * @param {any} value  a JSON-ish object/array/primitive
 * @returns {any} a redacted copy
 */
export function redact(value) {
  if (value === null || typeof value !== 'object') return value
  if (Array.isArray(value)) return value.map(redact)
  /** @type {Record<string, any>} */
  const out = {}
  for (const [k, v] of Object.entries(value)) {
    out[k] = isSecretKey(k, v) ? '[REDACTED]' : redact(v)
  }
  return out
}

function isSecretKey(key, v) {
  const lower = key.toLowerCase()
  // Whole-object secrets (OIDC wire values, tokens, private material).
  if (
    ['id_token', 'code', 'privatekey', 'private_key', 'secret', 'client_secret', 'access_token', 'encryptedtoken'].includes(lower)
  ) {
    return true
  }
  // Private-side JWK fields (a bare `d` is the EC private scalar).
  if (
    PRIVATE_JWK_FIELDS.includes(lower) &&
    typeof v === 'string' &&
    v.length > 0
  ) {
    return true
  }
  return false
}

/**
 * Reduce a JWKS doc to its PUBLIC halves only (06 §6). Any key carrying a
 * private field is DROPPED entirely — we never log a JWK we can't prove is
 * public (safer than field-stripping: a future private field can't slip
 * through a whitelist).
 * @param {{ keys?: Array<object> } | null} jwks
 * @returns {{ keys: Array<object> } | null}
 */
export function publicJwks(jwks) {
  if (!jwks || !Array.isArray(jwks.keys)) return jwks
  /** @type {Array<object>} */
  const keys = []
  for (const k of jwks.keys) {
    if (!k || typeof k !== 'object') continue
    if (PRIVATE_JWK_FIELDS.some(f => f in k && k[f] !== null && k[f] !== undefined)) {
      continue // private key: drop, not redact
    }
    /** @type {Record<string, any>} */
    const pub = {}
    for (const field of ['kty', 'kid', 'alg', 'use', 'crv', 'x', 'y', 'n', 'e']) {
      if (k[field] !== undefined && k[field] !== null) pub[field] = k[field]
    }
    keys.push(pub)
  }
  return { keys }
}

/**
 * Shape an S2S client assertion for audit/log (03 §6, 06 §6). The audit
 * row and the log both hold ONLY `{ iss, aud, jtiHash }` (sha256 32-hex of
 * the raw jti, 03 §6 "the jti is hashed"); the raw JWS is a cross-admin
 * artifact and is never logged (06 §6).
 *
 * @param {{ iss?: string, aud?: string, jti?: string } | null} assertion
 * @returns {{ iss: string|null, aud: string|null, jtiHash: string|null }}
 */
export function assertionMeta(assertion) {
  if (!assertion || typeof assertion !== 'object') {
    return { iss: null, aud: null, jtiHash: null }
  }
  const jtiHash =
    assertion.jti != null
      ? crypto
          .createHash('sha256')
          .update(String(assertion.jti))
          .digest('hex')
          .slice(0, 32)
      : null
  return {
    iss: assertion.iss ?? null,
    aud: assertion.aud ?? null,
    jtiHash,
  }
}
