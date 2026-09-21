import { test, expect, beforeEach, vi } from 'vitest'
import {
  buildOidcProviderClients,
  federationClientId,
  clientDefaults,
} from '../../../oidc/clients.mjs'
import { FederationPeer } from '../../../app/models/FederationPeer.mjs'

vi.mock('../../../app/models/FederationPeer.mjs', () => ({
  FederationPeer: { find: vi.fn() },
}))

beforeEach(() => {
  vi.clearAllMocks()
})

test('federationClientId follows the plan 03 §2 convention', () => {
  const id = federationClientId('overleaf.uni-bremen.de')
  expect(id).toBe('urn:overleaf-federation:client:overleaf.uni-bremen.de')
  // The sweep index (adapter) and the provider clients[] both key on
  // this exact string — no second convention.
  expect(id.startsWith('urn:overleaf-federation:client:')).toBe(true)
})

test('clients[]: one per approved peer, v9-mandatory metadata present', async () => {
  FederationPeer.find.mockResolvedValue([
    { origin: 'a.example' },
    { origin: 'b.example' },
  ])
  const clients = await buildOidcProviderClients()
  expect(FederationPeer.find).toHaveBeenCalledWith({ status: 'approved' })
  expect(clients.map(c => c.client_id)).toEqual([
    'urn:overleaf-federation:client:a.example',
    'urn:overleaf-federation:client:b.example',
  ])
  for (const c of clients) {
    // v9 hard requirements (verified against 9.12.2): public client,
    // ES256 id_tokens, and the bare `scope` STRING (an array is
    // InvalidClientMetadata).
    expect(c.token_endpoint_auth_method).toBe('none')
    expect(c.id_token_signed_response_alg).toBe('ES256')
    expect(c.scope).toBe('openid')
    expect(c.redirect_uris.join('\n')).toContain('/federation/oidc/rp/callback')
    expect(c.application_type).toBe('web')
    expect(c.grant_types).toContain('authorization_code')
    expect(c.response_types).toContain('code')
  }
})

test('clients[]: revoked peers are excluded (find filters status: approved)', async () => {
  // `buildOidcProviderClients` queries `FederationPeer.find({status:'approved'})`
  // — the revocation exclusion is the find filter itself; with zero rows
  // the provider boots with no federation clients.
  FederationPeer.find.mockResolvedValue([])
  const clients = await buildOidcProviderClients()
  expect(clients).toEqual([])
  expect(FederationPeer.find).toHaveBeenCalledWith({ status: 'approved' })
})

test('clientDefaults: provider-level metadata shared by every client', () => {
  expect(clientDefaults.token_endpoint_auth_method).toBe('none')
  expect(clientDefaults.id_token_signed_response_alg).toBe('ES256')
  expect(clientDefaults.scope).toBe('openid')
  expect(clientDefaults.redirect_uris).toBeUndefined()
})
