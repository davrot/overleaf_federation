import { describe, it, expect, beforeEach, vi } from 'vitest'

// P1c (plan 10 §0.8) — unit test for the per-provider attrFilter role evaluator.
//
// The evaluator is the decision core of "who may log in and what they may do":
//   - evaluateAttrFilter(attrFilter, profile) -> { role, filterId?, reason? }
//   - sanitizeAttrFilter(input) -> safe rows (drop invalid, cap, normalize)
//   - persistedRoleForProvider(ssoRoles, providerId) -> the role the *choked*
//     project-creation refusal + the session read (user.ssoRoles[id]) depend on.
//
// It is pure except auditSsoLoginDenied (not exercised here). No DB.

// The evaluator imports UserAuditLogEntry only for auditSsoLoginDenied; keep it
// out of the way so the module loads without a Mongo connection.
vi.mock('../../app/src/models/UserAuditLogEntry.mjs', () => ({
  UserAuditLogEntry: { create: () => {} },
}))
vi.mock('@overleaf/logger', () => ({
  default: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
}))

import {
  evaluateAttrFilter,
  sanitizeAttrFilter,
  persistedRoleForProvider,
} from '../../../../app/src/Features/Authentication/ssoRoleEvaluator.mjs'

describe('ssoRoleEvaluator (P1c attrFilter roles)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('evaluateAttrFilter', () => {
    it('no attrFilter => local (default)', () => {
      expect(evaluateAttrFilter(undefined, { email: 'a@b.c' }).role).toBe('local')
      expect(evaluateAttrFilter([], { email: 'a@b.c' }).role).toBe('local')
    })

    it('admin role is NOT evaluated here (fallthrough handled by attAdmin)', () => {
      const rows = [{ role: 'admin', attribute: 'isAdmin', values: ['1'] }]
      // an admin row must not block/guest; it is local for our purposes
      const r = evaluateAttrFilter(rows, { isAdmin: '1' })
      expect(r.role).toBe('local')
    })

    it('blocked row matching profile => blocked', () => {
      const rows = [{ role: 'blocked', attribute: 'entitlements', values: ['svc:anon'] }]
      const r = evaluateAttrFilter(rows, { entitlements: ['a', 'svc:anon'] })
      expect(r.role).toBe('blocked')
    })

    it('no matching value => local (first match wins, falls through)', () => {
      const rows = [{ role: 'guest', attribute: 'entitlements', values: ['svc:anon'] }]
      const r = evaluateAttrFilter(rows, { entitlements: ['other'] })
      expect(r.role).toBe('local')
    })

    it('first matching row wins (order matters)', () => {
      const rows = [
        { role: 'guest', attribute: 'x', values: ['a'] },
        { role: 'blocked', attribute: 'x', values: ['a'] },
      ]
      const r = evaluateAttrFilter(rows, { x: 'a' })
      // top row (guest) wins because it is evaluated first
      expect(r.role).toBe('guest')
      expect(r.filterId).toBe(0)
    })

    it('equals: claim (array) contains a configured value', () => {
      const rows = [{ role: 'guest', attribute: 'ent', values: ['k1'] }]
      expect(evaluateAttrFilter(rows, { ent: ['k1', 'k2'] }).role).toBe('guest')
      expect(evaluateAttrFilter(rows, { ent: ['other'] }).role).toBe('local')
    })

    it('equals: scalar claim equal', () => {
      const rows = [{ role: 'guest', attribute: 'role', values: ['anon'] }]
      expect(evaluateAttrFilter(rows, { role: 'anon' }).role).toBe('guest')
    })

    it('includes: list membership equals; scalar containment needs match includes', () => {
      const row = { role: 'guest', attribute: 'ent', values: ['svc:t'], match: 'includes' }
      expect(evaluateAttrFilter([row], { ent: ['a', 'svc:t'] }).role).toBe('guest')
      // substring containment on a scalar (documented fallback)
      expect(evaluateAttrFilter([row], { ent: 'has svc:t inside' }).role).toBe('guest')
      // but default (equals) does NOT substring-match
      const eqRow = { role: 'guest', attribute: 'ent', values: ['svc:t'] }
      expect(evaluateAttrFilter([eqRow], { ent: 'has svc:t inside' }).role).toBe('local')
    })

    it('regex: any claim value matches', () => {
      const rows = [{ role: 'blocked', attribute: 'nameID', values: ['^urn:bad'], match: 'regex' }]
      expect(evaluateAttrFilter(rows, { nameID: 'urn:bad:1' }).role).toBe('blocked')
      expect(evaluateAttrFilter(rows, { nameID: 'urn:ok:1' }).role).toBe('local')
      // invalid regex => no match, not a throw
      const bad = [{ role: 'blocked', attribute: 'x', values: ['(unclosed'], match: 'regex' }]
      expect(evaluateAttrFilter(bad, { x: 'y' }).role).toBe('local')
    })

    it('caseSensitive (default true): case mismatch does NOT match', () => {
      const rows = [{ role: 'guest', attribute: 'ent', values: ['SVC:ANON'] }]
      expect(evaluateAttrFilter(rows, { ent: ['svc:anon'] }).role).toBe('local')
    })

    it('caseSensitive false: case-insensitive match', () => {
      const rows = [
        { role: 'guest', attribute: 'ent', values: ['SVC:ANON'], caseSensitive: false },
      ]
      expect(evaluateAttrFilter(rows, { ent: ['svc:anon'] }).role).toBe('guest')
    })

    it('rows without an attribute are skipped (explicit local + junk)', () => {
      const rows = [
        { role: 'guest', attribute: undefined, values: ['x'] }, // no attribute => skip
        { role: 'guest', attribute: 'role', values: ['a'] },
      ]
      expect(evaluateAttrFilter(rows, { role: 'a' }).role).toBe('guest')
    })
  })

  describe('sanitizeAttrFilter', () => {
    it('non-array => undefined', () => {
      expect(sanitizeAttrFilter(undefined)).toBeUndefined()
      expect(sanitizeAttrFilter('nope')).toBeUndefined()
    })

    it('drops rows without an attribute, caps values, normalizes caseSensitive', () => {
      const out = sanitizeAttrFilter([
        { role: 'guest', attribute: 'a', values: ['1', '2', '3'] },
        { role: 'blocked', attribute: undefined, values: ['x'] }, // dropped
        { role: 'local', attribute: 'b', values: 'single' },
      ])
      expect(out).toHaveLength(2)
      expect(out[0]).toEqual({
        role: 'guest',
        attribute: 'a',
        values: ['1', '2', '3'],
        match: 'equals',
        caseSensitive: true,
      })
      expect(out[1].role).toBe('local')
      expect(out[1].values).toEqual(['single'])
    })

    it('values are string-coerced and capped at 10 per row', () => {
      const many = Array.from({ length: 20 }, (_, i) => i)
      const out = sanitizeAttrFilter([{ role: 'guest', attribute: 'a', values: many }])
      expect(out[0].values).toHaveLength(10)
      expect(out[0].values.every((v) => typeof v === 'string')).toBe(true)
    })

    it('role restricted to guest|blocked (admin/local fall to local default)', () => {
      const out = sanitizeAttrFilter([{ role: 'admin', attribute: 'x', values: ['v'] }])
      expect(out[0].role).toBe('local')
    })
  })

  describe('persistedRoleForProvider (choked-creation predicate)', () => {
    it('no ssoRoles / no login marker => local', () => {
      expect(persistedRoleForProvider(undefined, undefined)).toBe('local')
      expect(persistedRoleForProvider({}, 'p1')).toBe('local')
      expect(persistedRoleForProvider({ p1: { role: 'guest' } }, undefined)).toBe('local')
    })

    it('read role is keyed by the session ssoLoginProviderId', () => {
      const ssoRoles = {
        p1: { role: 'guest' },
        p2: { role: 'local' },
      }
      expect(persistedRoleForProvider(ssoRoles, 'p1')).toBe('guest')
      expect(persistedRoleForProvider(ssoRoles, 'p2')).toBe('local')
      // a password login clears ssoLoginProviderId => local even with guest row
      expect(persistedRoleForProvider(ssoRoles, undefined)).toBe('local')
    })

    it('blocked is surfaced (for diagnostics; login path refuses earlier)', () => {
      const ssoRoles = { p1: { role: 'blocked' } }
      expect(persistedRoleForProvider(ssoRoles, 'p1')).toBe('blocked')
    })
  })
})
