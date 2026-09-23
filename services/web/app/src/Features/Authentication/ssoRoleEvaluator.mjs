/**
 * SSO per-provider role evaluation (P1c / plan 10 §0.8).
 *
 * Attribute filters configured per provider (`ssoConfigs.providers[i].attrFilter`)
 * decide, from the attributes/claims actually released by the provider, which
 * role a login gets:
 *
 *   - local   — normal account (may create own projects)
 *   - guest   — may log in, cannot create own projects
 *   - blocked — refused at login entirely (no account, no session)
 *
 * Rules (plan §0.8, decisions locked 2026-09-22):
 *   - Evaluation order is ARRAY ORDER (top row first); first matching row wins.
 *   - No matching row => 'local' (default). Absent `attrFilter` => 'local'.
 *   - Admin is NOT evaluated here: the existing attAdmin mechanism stays as-is.
 *   - `attribute` is the provider-released attribute name/OID for SAML or the
 *     OIDC claim name; values are `equals` / `includes` / `regex` (regex has no
 *     ReDoS guard — keep values simple, ≤10 rows per provider).
 *
 * Pure (no I/O) so both the SSO login path and the project-creation refusal
 * check can use it without layer-inversion.
 */

const MATCH_MODES = ['equals', 'includes', 'regex']

function _rowMatches(row, profile) {
  const raw = profile?.[row.attribute]
  if (raw === undefined || raw === null) return false
  const caseSensitive = row.caseSensitive !== false
  const norm = (v) => (caseSensitive ? String(v) : String(v).toLowerCase())
  const claim = Array.isArray(raw) ? raw : [raw]
  const values = (Array.isArray(row.values) ? row.values : [row.values])
    .map(String)

  // equals: claim contains a value equal to one of the configured values.
  // includes: scalar claim contains a value as substring (or claim is a list that
  //   contains an equal value). For OIDC multi-valued claims (e.g. GEANT
  //   `entitlements`), `includes` on a list acts as membership.
  // regex: any claim value matches one of the configured regexes.
  switch (row.match) {
    case 'includes':
      // Array claim (OIDC multi-valued, e.g. `entitlements`, or SAML list):
      // membership — any claim value equals a configured value.
      // Scalar claim: substring containment.
      return Array.isArray(raw)
        ? claim.some((cv) => values.some((v) => norm(cv) === norm(v)))
        : values.some((v) => norm(raw).includes(norm(v)))
    case 'regex':
      return claim.some((cv) =>
        values.some((v) => {
          try {
            return new RegExp(v, caseSensitive ? undefined : 'i').test(String(cv))
          } catch {
            return false // invalid regex: no-match (G5)
          }
        })
      )
    case 'equals':
    default:
      // claim value equal to one of the configured values
      return claim.some((cv) => values.some((v) => norm(cv) === norm(v)))
  }
}

/**
 * Evaluate the provider's attrFilter rows against a login profile.
 *
 * @param {Array<object>} attrFilter  ssoConfigs.providers[i].attrFilter (may be
 *   absent/undefined => 'local')
 * @param {object} profile  SAML: per-provider parsed attribute map; OIDC: the
 *   passport profile (claims from ID token + userinfo when fetched)
 * @returns {{role: 'local'|'guest'|'blocked', reason?: object, filterId?: number}}
 */
export function evaluateAttrFilter(attrFilter, profile) {
  for (const [i, row] of (attrFilter || []).entries()) {
    if (!row || !row.attribute) continue
    const role = row.role
    if (role === 'local') continue // explicit row can only ever match local (default anyway)
    if (role !== 'guest' && role !== 'blocked') continue // 'admin' handled by attAdmin
    if (_rowMatches(row, profile)) {
      return { role, reason: { attribute: row.attribute }, filterId: i }
    }
  }
  return { role: 'local' }
}

/**
 * The role a user has under one SSO provider, for the create-refusal check.
 * Reads the persisted evaluation written at login (P1b/P1c seam:
 * `user.ssoRoles[providerId]`, keying on `user.ssoLoginProviderId`).
 *
 * @param {object|undefined} ssoRoles  user.ssoRoles (may be undefined)
 * @param {string} providerId  ssoLoginProviderId of this session's login
 * @returns {'local'|'guest'|'blocked'}
 */
export function persistedRoleForProvider(ssoRoles, providerId) {
  const entry = ssoRoles?.[providerId]
  if (!entry) return 'local' // no evaluation yet => default local (G4)
  return entry.role === 'guest' || entry.role === 'blocked' ? entry.role : 'local'
}

/** Validate/sanitize admin-submitted attrFilter rows (admin save path). */
export function sanitizeAttrFilter(input) {
  if (!Array.isArray(input)) return undefined
  return input
    .map((row) => {
      if (!row || typeof row !== 'object') return undefined
      const role = row.role === 'guest' || row.role === 'blocked' ? row.role : undefined
      const attribute = typeof row.attribute === 'string' ? row.attribute : undefined
      if (!attribute) return undefined
      const match = MATCH_MODES.includes(row.match) ? row.match : 'equals'
      const values = Array.isArray(row.values)
        ? row.values.map(String).slice(0, 10)
        : row.values != null
          ? [String(row.values)]
          : []
      return {
        role: role || 'local',
        attribute,
        values,
        match,
        caseSensitive: row.caseSensitive !== false,
      }
    })
    .filter(Boolean)
    .slice(0, 10)
}

import { UserAuditLogEntry } from '../../models/UserAuditLogEntry.mjs'

/**
 * Audit a blocked SSO login (no account row exists / is created). `userId` is
 * null per plan §0.8 — the denied row is operational evidence (ip + provider).
 */
export async function auditSsoLoginDenied({ ipAddress, providerId, reason }) {
  await UserAuditLogEntry.create({
    userId: null,
    operation: 'sso-login-denied',
    ipAddress: String(ipAddress || ''),
    info: { providerId: String(providerId || ''), reason: reason || {} },
  })
}

export default {
  evaluateAttrFilter,
  persistedRoleForProvider,
  sanitizeAttrFilter,
  MATCH_MODES,
}
