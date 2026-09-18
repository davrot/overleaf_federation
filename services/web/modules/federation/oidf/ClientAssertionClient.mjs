// Outbound S2S client assertions (03 §2, 04 §7).
//
// SIGNED BY THE FEDERATION KEY (03 §2: "the federation key (NOT the OIDC
// key)") — the exact key peers pinned at trust establishment (TOFU admin
// pin, 02 §3; published in our leaf EC `jwks`). A's admin pins B's active
// federation key; B verifies A's assertions against that pinned key.
// The OIDC signing key (05 §8.6) is separate: it signs id_tokens inside
// oidc-provider and never leaves the instance.
//
// Wire (plan 03 §2 — authority for wire; npm v1.0.0 verified 2026-09-18
// in FINDINGS.md):
//   POST https://<peer>/federation/s2s
//     Content-Type: application/json
//     client_assertion: <JWT>
//     client_assertion_type: urn:ietf:params:oauth:client-assertion-type:jwt
//   body:
//     { "action": ..., "from": <origin, no port>, "to": <origin, no port>,
//       "ts": <unix-ms advisory>, "payload": {...} }
//
//   The assertion JWT (03 §1: "one signing key (federation key), one
//   JWT shape, one replay store"):
//     iss:  urn:overleaf-federation:client:<A origin, bare FQDN>
//     aud:  https://<peer origin, bare FQDN>/federation/s2s
//     iat/exp: now + 5 minutes (clock skew tolerated on the wire, 03 §3)
//     jti:  UUID (Redis replay dedup — `federation:replay:<jti>`, 03 §3)
//
// On receive (03 §2 step 2): `iss == urn:overleaf-federation:client:<from>`,
// `aud == our S2S endpoint`, `exp/iat` within tolerance, signature against
// the caller's pinned federation key (peerKeys), then `jti` dedup (03 §3).
import { OidcRelyingPartyRole } from '@oidfed/oidc'

import { createKeyProvider } from './keystore.mjs'
import { getEntityId, getOrigin } from './leaf.mjs'

export const S2S_CLIENT_ASSERTION_TYPE =
  'urn:ietf:params:oauth:client-assertion-type:jwt'

// 5 min (03 §2).
const CLIENT_ASSERTION_TTL_SECONDS = 300

// Deterministic client (04 §7): one per instance, one per peer pair.
export function getClientId() {
  return `urn:overleaf-federation:client:${getOrigin()}`
}

/**
 * OUR S2S endpoint (03 §2 step 2: the `aud` we check on receive).
 * */
export function getS2sEndpoint() {
  return `${getEntityId()}/federation/s2s`
}

/**
 * Build the HTTP headers + JSON body for one outbound S2S call (03 §2).
 * The client assertion is the signature itself: no body signature, no
 * RFC 9421 (03 §1). `ts` is advisory (audit readability); the
 * JWT `iat`/`exp` are authoritative.
 *
 * @param {string} peerOrigin  target entity id (peer origin, no port)
 * @param {string} action      'authorize-invite' | 'invited' | 'revoke'
 * @param {object} payload     action-specific payload (03 §4)
 * */
export async function buildS2sRequest(peerOrigin, action, payload) {
  const provider = createKeyProvider()
  const keySet = await provider.getFederationKeySet()

  // Static, verified npm v1.0.0 (FINDINGS.md): the claim shape is
  // { iss: clientId, sub: clientId, aud, jti, iat, exp } — `iss`/`sub`
  // are our deterministic client id (04 §7), `aud` is the peer's S2S
  // endpoint, `jti` is a fresh UUID for receiver-side dedup (03 §3).
  const assertion = await OidcRelyingPartyRole.createClientAssertion(
    getClientId(),
    `https://${peerOrigin}/federation/s2s`,
    keySet.signer,
    { expiresInSeconds: CLIENT_ASSERTION_TTL_SECONDS },
  )

  return {
    headers: {
      'Content-Type': 'application/json',
      client_assertion: assertion,
      client_assertion_type: S2S_CLIENT_ASSERTION_TYPE,
    },
    body: {
      action,
      from: getOrigin(),
      to: peerOrigin,
      ts: Date.now(),
      payload,
    },
  }
}
