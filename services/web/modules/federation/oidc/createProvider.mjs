// Build the oidc-provider instance (B-side OP).
//
// MUST be called after `keystore.ensureBootstrapped()` because the v9
// keystore eagerly validates `jwks.keys[*].d` at `new` (EC keys need
// crv/d/x/y non-empty strings). So the factory is invoked in the module's
// `start()` (post-DB), not `apply()` (pre-DB).
//
// The provider is a Koa app. Mount it on the (already session-parsed) web
// router:
//   webRouter.use('/federation/oidc', provider.callback())
//
// Koa then sees req.url relative to the mount:
//   GET  /auth                                  (authorization endpoint)
//   POST /token
//   GET  /jwks
//   GET  /.well-known/openid-configuration
//   GET  /resume/:uid                           (RESUME endpoint)
//   GET  /interaction/:uid                      (devInteractions — DISABLED)
//
// The interaction bridge (our /federation/oidc/interact/:uid) is mounted on the
// WEB router, BEFORE the provider, at a distinct path.

import { Provider } from 'oidc-provider'
import Settings from '@overleaf/settings'
import { oidcSigningKeys } from '../oidf/keystore.mjs'
import { buildOidcProviderClients } from './clients.mjs'
import createAdapter from './RedisOidcProviderAdapter.mjs'
import {
  User,
} from '../../../app/src/models/User.mjs'

/**
 * findAccount (v9 contract, verified against v9.12.2 source):
 *   (ctx, sub, source) => ({ accountId, claims: (use, scope, allowedClaims, rejected) => claimsMap })
 *
 * The `claims` function MUST be a function (v9's Grant source throws
 * `mustChange` otherwise). v9 then calls:
 *   account.claims(use, scope, allowedClaims, rejected)
 * and merges the returned object into the id_token payload (after
 * claim-name filtering per 05 §8.3).
 *
 * v1 identity claims (plan 01 §3, 02 §4):
 *   sub:         accountId (v9 injects as ctx.oidc.account.accountId)
 *   origin:      B's origin (FQDN)             <- the portable identity half
 *   localName:   user.email                     <- the portable identity half
 *   displayName: first+last (falls back to email)
 *   institution: user.institution (optional)
 */
async function findAccount(ctx, sub, source) {
  const user = await User.findById(sub).catch(() => null)
  if (!user || user.suspended) {
    // v9: returning null means "not found / account not available".
    return null
  }
  return {
    accountId: sub,
    claims: async () => ({
      origin: new URL(Settings.siteUrl).hostname,
      localName: user.email,
      displayName: `${user.first_name || ''} ${user.last_name || ''}`.trim() || user.email,
      institution: user.institution || null,
    }),
  }
}

let _provider = null

export async function getOidcProvider() {
  if (_provider) return _provider
  const keys = await oidcSigningKeys()
  const adapter = createAdapter()
  const siteOrigin = new URL(Settings.siteUrl).origin
  _provider = new Provider(`${siteOrigin}/federation/oidc`, {
    adapter,
    jwks: {
      // v9 keystore: JWKS object, `keys` is a plain array of private JWKs.
      keys: keys.map(k => ({ ...k, alg: k.alg || 'ES256', crv: k.crv, d: k.d, x: k.x, y: k.y })),
    },
    findAccount,
    clients: await buildOidcProviderClients(),
    interactions: {
      // Absolute URL pointing at our bridge under the mount prefix.
      // v9: `interactions.url` returns the redirect target for the interaction
      // page — this is where 302 + `op_interaction` cookie go.
      url: (ctx, interaction) =>
        `${siteOrigin}/federation/oidc/interact/${interaction.uid}`,
    },
    ttl: {
      AuthorizationCode: 120,
      Grant: 30 * 86400,
      Interaction: 600,
      Session: 8 * 3600,
    },
    subjectTypes: ['public'],
    // v9: the id_token's claim NAMES are pruned to `claimsSupported`, which
    // is built from this `claims` mapping (defaults.js only seeds sub).
    // Without it, findAccount's custom claims (origin, localName, displayName,
    // institution) are silently dropped from the id_token (verified in
    // e2e_probe.mjs: with this option absent, only sub rides the token).
    // list = exactly what findAccount supplies; v9 auto-adds `sub` if absent.
    claims: {
      openid: ['sub', 'origin', 'localName', 'displayName', 'institution'],
    },
    scopes: ['openid'],
    features: {
      devInteractions: { enabled: false },
    },
  })
  return _provider
}

export function _resetForTest() {
  _provider = null
}
