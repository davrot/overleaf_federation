// Leaf Entity Configuration serving (pairwise mode, 02 §2, 05 §8.4).
//
// GET <entityId>/.well-known/openid-federation
//   responds with a raw EC JWT, Content-Type:
//   `application/entity-statement+jwt; charset=utf-8` (exact match required
//   by peers; verified from `isExactContentType` in @oidfed/core v1.0.0).
//
// Pairwise leaf EC:
//   - NO `authority_hints` (nothing above us; peers pin us directly).
//   - metadata.openid_provider.issuer MUST equal the entity id (leaf EC
//     check 16 — verified on the npm v1.0.0 wire: signing succeeds with a
//     mismatch, `verifyEntityStatement` is what rejects it, so the check is
//     verifier-side; we set it correctly anyway).
//   - metadata.openid_relying_party: who we are when *someone else* uses us;
//     pinned by the peer's admin (TOFU, 02 §3).
//   - The leaf EC is also our OIDF identity statement for admin pin
//     (02 §4, pairwise trust establishment = admin pin, NOT registration).
import Settings from '@overleaf/settings'
import logger from '@overleaf/logger'

import { signEntityConfiguration } from '@oidfed/core'

import { createKeyProvider, leafJwksPayload } from './keystore.mjs'

const PROVIDER_KEY = 'provider'
const KEY_PROVIDER = 'provider'

/**
 * Our entity identifier (02 §5, 04 §1): the HTTPS origin of this instance,
 * WITHOUT port. MUST be HTTPS (OIDF 1.0 requires the `https:` scheme on
 * entity identifiers; the `entityId` zod schema rejects otherwise).
 * This is the OIDF *entity id* — it is what the leaf EC and admin pinning
 * carry.
 * */
export function getEntityId() {
  const siteUrl = Settings.siteUrl
  if (typeof siteUrl !== 'string' || siteUrl.length === 0) {
    throw new Error(
      'federation: Settings.siteUrl must be set (entity id is derived from it)',
    )
  }
  const url = new URL(siteUrl)
  if (url.protocol !== 'https:') {
    throw new Error(
      `federation: entity id must use https: (Settings.siteUrl is ${url.protocol})`,
    )
  }
  return `${url.protocol}//${url.host.replace(/:\d+$/, '')}`
}

/**
 * Bare FQDN origin (no scheme, no port). This is the S2S wire's identity
 * unit (03 §2: `from`/`to` = "origin FQDN", `iss` = `urn:overleaf-federation:
 * client:<origin>`). Distinct from the OIDF entity id in {@link getEntityId}
 * (which carries the `https:` scheme for the leaf EC).
 * */
export function getOrigin() {
  const siteUrl = Settings.siteUrl
  if (typeof siteUrl !== 'string' || siteUrl.length === 0) {
    throw new Error(
      'federation: Settings.siteUrl must be set (origin is derived from it)',
    )
  }
  const url = new URL(siteUrl)
  return url.host.replace(/:\d+$/, '')
}

/**
 * Absolute OP endpoints for this instance (05 §8.6). Same host/port as
 * Settings.siteUrl; paths under /federation/oidc (oidc-provider mount).
 * */
export function oidcEndpoints() {
  const url = new URL(Settings.siteUrl)
  const base = `https://${url.host}`
  const issuer = `${base}/federation/oidc`
  return {
    issuer,
    authorization: `${base}/federation/oidc/authorize`,
    token: `${base}/federation/oidc/token`,
    jwks: `${base}/federation/oidc/jwks`,
    callback: `${base}/federation/oidc/callback`,
    endSession: `${base}/federation/oidc/session/end`,
  }
}

/**
 * Leaf EC metadata. Kept minimal + correct (02 §2):
 *  - `openid_provider`: who we are as the OP our peers federate with.
 *    `issuer` = entity id (leaf EC check 16). We do NOT advertise
 *    `client_registration_types_supported` (pairwise has no registration
 *    service), so no `federation_registration_endpoint` (FINDINGS).
 *  - `openid_relying_party`: who we are to *their* OP; the deterministic
 *    client id (04 §7) is advertised so a peer's OP-side registration /
 *    pin flow can bind us.
 * Institutional mode (P3) adds `federation_registration_endpoint` and the
 * registration claim fields (02 §4) — not present in pairwise (03 §1).
 * */
export function buildLeafMetadata(entityId) {
  const endpoints = oidcEndpoints()
  return {
    openid_provider: {
      issuer: endpoints.issuer, // = <entity id>/federation/oidc; provider issuer
      authorization_endpoint: `${endpoints.issuer}/authorize`,
      token_endpoint: `${endpoints.issuer}/token`,
      jwks_uri: `${endpoints.issuer}/jwks`,
      grant_types_supported: ['authorization_code'],
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['ES256'],
    },
    openid_relying_party: {
      client_id: entityId, // deterministic client id for OP-side (04 §7)
      client_name: 'Overleaf Federation (CEP)',
      redirect_uris: [endpoints.callback],
      grant_types: ['authorization_code'],
      response_types: ['code'],
      response_modes: ['fragment'],
    },
  }
}

/**
 * Sign the leaf EC we serve. Signed by the ACTIVE federation key
 * (02 §5); `jwks` carries public halves of every non-revoked key
 * (published + active + retiring = grace window, 02 §5).
 * TTL 48h (DEFAULT_ENTITY_STATEMENT_TTL_SECONDS in @oidfed/core).
 * Not signed per-request on purpose: ES256 is cheap and this avoids a
 * cache layer; peers re-fetch on kid mismatch (06 §2).
 * */
export async function buildLeafEntityConfiguration() {
  const entityId = getEntityId()
  const provider = createKeyProvider()
  const keySet = await provider.getFederationKeySet()
  const jwks = await leafJwksPayload()
  return await signEntityConfiguration({
    signer: keySet.signer,
    entityId,
    jwks,
    metadata: buildLeafMetadata(entityId),
  })
}

/**
 * Express handler: GET /.well-known/openid-federation (05 §1.1).
 * Serves the raw EC with the exact Content-Type peers require.
 * */
export function leafHandler(req, res, next) {
  buildLeafEntityConfiguration()
    .then((jwt) => {
      res
        .set('Content-Type', 'application/entity-statement+jwt; charset=utf-8')
        .set('Cache-Control', 'no-store')
        .send(jwt)
    })
    .catch((error) => {
      logger.error({ error }, 'federation: failed to serve leaf entity configuration')
      next(error)
    })
}
