/**
 * clients.mjs — the OIDC provider's static `clients[]` (05 §8.3).
 *
 * Plan 05 §8.3 authority: "OIDC provider `clients[]` 是 boot-time 从
 * approved FederationPeer 重建的静态数组;无 `findClient` hook(v9 无)"
 * (clients[] is a boot-time static array rebuilt from approved peers;
 * v9 has no findClient hook).
 *
 * Each approved B-side peer gets one client whose metadata `client_id`
 * equals the plan 03 §2 issuer/clientId convention:
 *
 *   client_id = urn:overleaf-federation:client:<peer.origin>
 *
 * (the bare FQDN origin of the peer, e.g. overleaf.uni-bremen.de).
 *
 * v9 hard requirements, verified against oidc-provider 9.12.2:
 *   - `client_id` is MANDATORY for statically configured clients
 *     (lib/helpers/initialize_clients.js throws InvalidClientMetadata
 *     without it). The metadata is the client — there is no separate
 *     `id` field in v9.
 *   - `id_token_signed_response_alg: 'ES256'` is mandatory for
 *     public clients (probe: without it v9 refuses).
 *   - oidc-provider metadata keys are SNAKE_CASE: redirect_uris,
 *     grant_types, response_types, token_endpoint_auth_method,
 *     application_type.
 */

import { FederationPeer } from '../app/models/FederationPeer.mjs'

/**
 * Rebuild the OIDC provider clients[] snapshot from approved peers.
 *
 * @returns {Promise<Array<object>>}
 */
export async function buildOidcProviderClients() {
  const peers = await FederationPeer.find({ status: 'approved' })
  return peers.map((peer) => ({
    client_id: `urn:overleaf-federation:client:${peer.origin}`,
    redirect_uris: [`https://${peer.origin}/federation/oidc/rp/callback`],
    application_type: 'web',
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    // v9 client metadata: `scope` is a STRING, not an array (the `scopes:`
    // constructor option is the array form). InvalidClientMetadata "scope
    // must be a non-empty string if provided" otherwise.
    scope: 'openid',
    // Mandatory for public clients under oidc-provider defaults.
    id_token_signed_response_alg: 'ES256',
  }))
}

/**
 * The provider-level `clientDefaults` (05 §8.1). Every federation client
 * inherits these; the per-client rows above add redirect_uris + auth
 * method. Keeping shared defaults here (rather than baking them into each
 * row) means a future per-peer override is a single client-metadata
 * change, not a per-client re-encode.
 */
export const clientDefaults = {
  application_type: 'web',
  token_endpoint_auth_method: 'none',
  grant_types: ['authorization_code'],
  response_types: ['code'],
  // OIDC client metadata `scope` is a string (not an array).
  scope: 'openid',
  id_token_signed_response_alg: 'ES256',
}
