// Institutional trust anchor (TA) row (02 §3, 04 §2, 07 §P3).
//
// The v1 trust unit is the PER-PEER PIN (pairwise). Institutional
// operation (02 §6 / 07 §P3) adds TA rows to the SAME `trustAnchors`
// set: the leaf's `authority_hints` walk up through IA statements to a
// configured TA — the resolve path is the same, only the anchor set
// grows (scale-out is data, not code).
//
// A row is what an admin pinned as "known-good institutional root":
//   - `entityId`: the TA's OIDF entity id (`https://<FQDN>`)
//   - `jwks`:     the TA's public JWK set (TOFU — the pin IS the trust
//                 decision; the raw JWS is never stored, 04 §2)
//
// Used at PEER PIN TIME (institutional peers): the leaf EC's
// `authority_hints` must terminate in a TA that has a row here, and the
// subordinate statement chain is re-verified offline
// (02 §3/§4, plan 07 §P3 "resolve institutional chain").
//
// Module-local model, auto-registered by import (same pattern as
// FederationKey.mjs).

import mongoose from '../../../../app/src/infrastructure/Mongoose.mjs'
const { Schema } = mongoose

export const FederationTrustAnchorSchema = new Schema(
  {
    // OIDF entity id, e.g. 'https://ta.oidf-pilot.edugain.org'
    entityId: { type: String, required: true, unique: true },
    // admin-facing label ('eduGAIN OIDF pilot TA')
    displayName: String,
    // TOFU-pinned public JWK set ({ keys: [...] }). Never served raw;
    // surfaced as thumbprints in the admin listing (02 §5 "public
    // halves only").
    jwks: { type: Object, required: true },
    pinnedAt: { type: Date, default: Date.now },
  },
  { collection: 'federationTrustAnchors' },
)

export const FederationTrustAnchor = mongoose.model(
  'FederationTrustAnchor',
  FederationTrustAnchorSchema,
)

export default FederationTrustAnchor
