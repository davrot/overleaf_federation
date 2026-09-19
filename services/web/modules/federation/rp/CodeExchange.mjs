// A-side code exchange + id_token verification (05 §3.2, 01 §5 step 7).
//
// No OIDC client library — plain `fetch` + `jose` (repo-top-level 6.2.10).
// Verified against the oidc-provider v9.12.2 B side (FINDINGS + source):
//   - `nonce` rides the id_token via IdToken.extra (`token.set('nonce', ...)`
//     in grant_common.js) — the provider's `claims` override does NOT drop
//     it (extra claims are merged after claim-name masking, id_token.js).
//   - `aud` for a public client is the raw `client_id` string (id_token.js
//     `signOptions.audience = client.clientId`).
//   - `iss` is the provider issuer: `https://<peerOrigin>/federation/oidc`.
//
// JWKS: fetched from `https://<peerOrigin>/federation/oidc/jwks` (the
// provider mount, NOT the leaf — 01 §6 item 3), cached in Redis
// `federation:jwks:<origin>` TTL 1 h (04 §6), refetch on `kid` mismatch.

import { jwtVerify, decodeProtectedHeader } from 'jose'
import Settings from '@overleaf/settings'
import logger from '@overleaf/logger'
import RedisWrapper from '../../../app/src/infrastructure/RedisWrapper.mjs'

// 04 §6: 1 h cache.
const JWKS_CACHE_TTL_SECONDS = 3600
const JWKS_CACHE_PREFIX = 'federation:jwks:'

function getRedis(redis) {
  return redis ?? RedisWrapper.client('federation')
}

async function fetchAndCacheJwks(redis, origin) {
  const resp = await fetch(`https://${origin}/federation/oidc/jwks`)
  if (!resp.ok) {
    throw new Error(`jwks-fetch-failed: ${resp.status}`)
  }
  const jwks = await resp.json()
  try {
    await redis.set(`${JWKS_CACHE_PREFIX}${origin}`, JSON.stringify(jwks), 'EX', JWKS_CACHE_TTL_SECONDS)
  } catch (err) {
    logger.warn({ err }, 'federation: jwks cache set failed')
  }
  return jwks
}

async function fetchCachedJwks(redis, origin) {
  try {
    const hit = await redis.get(`${JWKS_CACHE_PREFIX}${origin}`)
    if (hit) return JSON.parse(hit)
  } catch (err) {
    logger.warn({ err }, 'federation: jwks cache get failed')
  }
  return fetchAndCacheJwks(redis, origin)
}

/**
 * Pick the public JWK from the cached JWKS by `kid`. Returns the JWK
 * with public fields only (never `d`). Both B-side key purposes
 * (federation + oidc) are EC P-256 / ES256 (05 §8.6), so `kty:'EC'`,
 * `crv:'P-256'` — jose `jwtVerify` must see the right key type.
 *
 * jose v6 `decodeJwt` returns only the (verified-unchecked) payload —
 * the header has to be read manually from the first segment.
 */
function resolveJwk(jwks, token) {
  const { kid } = decodeProtectedHeader(token)
  if (!kid) return null
  const key = jwks.keys?.find(k => k.kid === kid)
  if (!key) return null
  return {
    kid: key.kid,
    kty: key.kty,
    crv: key.crv,
    x: key.x,
    y: key.y,
    alg: key.alg,
  }
}

/**
 * Exchange the authorization code and verify the returned id_token
 * (05 §3.2). Throws `exchange-failed` / `identity-mismatch` /
 * `state-mismatch` (audit codes, 04 §8).
 *
 * @param {string} peerOrigin  B origin (FQDN, no port)
 * @param {object} opts
 * @param {string} opts.code    the authorization code
 * @param {string} opts.codeVerifier  PKCE code_verifier
 * @param {object} opts.intent  { projectId, privileges, nonce, origin, localName, url }
 * @param {ioredis|null} [redis]  client override (tests)
 * @returns {Promise<object>} the verified id_token claims
 */
export async function exchange(peerOrigin, opts, redis) {
  const client = getRedis(redis)
  let jwks = null
  try {
    jwks = await fetchCachedJwks(client, peerOrigin)
  } catch (err) {
    logger.warn({ err, peerOrigin }, 'federation: initial jwks fetch failed')
  }

  const clientId = `urn:overleaf-federation:client:${new URL(Settings.siteUrl).hostname}`
  const tokenResp = await fetch(`https://${peerOrigin}/federation/oidc/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: clientId,
      code: opts.code,
      // Registered at boot (clients.mjs) for every approved peer; sent
      // so the token endpoint can re-bind it (OIDC 4.1.3, v9 checks it).
      redirect_uri: `https://${new URL(Settings.siteUrl).hostname}/federation/oidc/rp/callback`,
      code_verifier: opts.codeVerifier,
    }),
  }).then(async r => {
    const body = await r.json().catch(() => ({}))
    if (!r.ok || !body.id_token) {
      throw new Error(`exchange-failed: ${body.error || r.status}`)
    }
    return body
  })

  // kid mismatch → bypass the cache and refetch once (04 §6).
  let key = resolveJwk(jwks, tokenResp.id_token)
  if (!key) {
    const fresh = await fetchAndCacheJwks(client, peerOrigin)
    key = resolveJwk(fresh, tokenResp.id_token)
  }
  if (!key) {
    throw new Error('exchange-failed: kid-not-in-jwks')
  }

  let claims
  try {
    const result = await jwtVerify(tokenResp.id_token, key, {
      audience: clientId,
      issuer: `https://${peerOrigin}/federation/oidc`,
    })
    claims = result.payload
  } catch (err) {
    throw new Error(`exchange-failed: signature-verify (${err.message})`)
  }

  if (claims.origin !== peerOrigin || claims.localName !== opts.intent.localName) {
    throw new Error('identity-mismatch')
  }
  if (claims.nonce !== opts.intent.nonce) {
    throw new Error('state-mismatch')
  }
  return claims
}
