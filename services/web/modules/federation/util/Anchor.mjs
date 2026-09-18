// Identity anchor utilities (01 §3, 04 §1).
//
// The identity anchor is a TUPLE `(origin, localName)`:
//   origin    — the home instance's FQDN (host of Settings.siteUrl), no
//               scheme, no port, e.g. `overleaf.uni-bremen.de`.
//   localName — the home login name (the home user's email convention;
//               may contain `@`), e.g. `bla@example.com`.
//
// Display serialization `localName:origin` exists ONLY at human I/O
// boundaries (invite form, admin search, audit rendering); the wire
// carries two separate OIDC id_token claims (`origin`, `localName`) and
// storage is two separate fields (01 §3.1, 03 §2). The display string is
// split on the LAST colon so `origin` is unambiguous, and `:` is banned
// in new `localName` values for that single reason (01 §3.3).
//
// NOTHING here stores or transmits the concatenated anchor string.

import crypto from 'node:crypto'

import Settings from '@overleaf/settings'

/**
 * Split a display anchor `localName:origin` on the LAST colon.
 * @returns {{ localName: string, origin: string } | null}
 */
export function parseAnchor(str) {
  if (typeof str !== 'string' || str.length === 0) return null
  const idx = str.lastIndexOf(':')
  if (idx <= 0) return null
  const localName = str.slice(0, idx)
  const origin = str.slice(idx + 1)
  if (localName.length === 0 || origin.length === 0) return null
  return { localName, origin }
}

/**
 * Display serialization `localName:origin` (01 §3.1). null when the
 * anchor is incomplete.
 */
export function formatAnchor(anchor) {
  if (!anchor || !anchor.localName || !anchor.origin) return null
  return `${anchor.localName}:${anchor.origin}`
}

/**
 * Validate an anchor. Rejects `:` in `localName` (01 §3.3 display-layer
 * constraint) and a non-bare-FQDN origin.
 */
export function validateAnchor({ localName, origin } = {}) {
  if (typeof localName !== 'string' || localName.length === 0) {
    throw new Error('federation: localName required (non-empty string)')
  }
  if (typeof origin !== 'string' || origin.length === 0) {
    throw new Error('federation: origin required (non-empty string)')
  }
  if (localName.includes(':')) {
    throw new Error(
      'federation: localName cannot contain ":" (01 §3.3, display-layer)',
    )
  }
  if (
    !/^[a-z][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i.test(
      origin,
    )
  ) {
    throw new Error(`federation: invalid origin FQDN: ${origin}`)
  }
  return { localName, origin }
}

/**
 * `ProjectInvite.federated.localNameHash` (04 §1/§2). A `sha256:<hex>` of
 * the display string `<localName>:<origin>` — a stable per-row identifier
 * for the invitee. NOT a claim: it is a row field and an audit key.
 */
export function hashInviteeEmail(localName, origin) {
  const display = `${localName}:${origin}`
  return `sha256:${crypto.createHash('sha256').update(display).digest('hex')}`
}

/**
 * Redis-key component `localNameHash` (04 §6: `federation:ratelimit:*` /
 * `federation:invite-cache:*`). A SECRET-SALTED HMAC over
 * `<localName>:<origin>` — a key component, never the raw claim. 32-hex
 * (128-bit) of the HMAC is returned; the salt is the site session secret
 * so two instances do not key on shared material.
 */
export function saltedLocalNameHash(localName, origin) {
  const salt =
    Settings.security?.sessionSecret || 'overleaf-federation-salt'
  const data = `${localName}:${origin}`
  return crypto.createHmac('sha256', salt).update(data).digest('hex').slice(0, 32)
}

/**
 * Resolve a (federated OR local) account for the given anchor (07 §3,
 * "local user on a partner machine"). The identity is determined ONLY by
 * `(origin, localName)`, never by an invite-row attribute.
 *
 * - Mirror row: `User.federation.{origin, localName}` matches (subdocument
 *   PRESENCE is the mirror mark — 04 §1, no `kind` field).
 * - Otherwise a local account whose home-login `email` matches `localName`
 *   (home oracle; 01 §3.2) resolves to it.
 * - Neither: NOT found → `{ ok: false, code: 'invitee-unknown' }`. The
 *   caller must NOT silently promote a fresh local account; a grant is
 *   refused until the mirror exists (or the home user has an account).
 *
 * `User` is imported lazily (module-load cycle guard).
 * @returns {Promise<{ ok: true, user: object } | { ok: false, code: string, detail: string }>}
 */
export async function resolveAnchorUser({ origin, localName }) {
  const { User } = await import('../../../app/src/models/User.mjs')

  const mirror = await User.findOne({
    'federation.origin': origin,
    'federation.localName': localName,
  }).lean()
  if (mirror) {
    return { ok: true, user: mirror }
  }

  const local = await User.findOne({ email: localName }).lean()
  if (local) {
    return { ok: true, user: local }
  }

  return {
    ok: false,
    code: 'invitee-unknown',
    detail: `no account for anchor ${localName}:${origin}`,
  }
}
