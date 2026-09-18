// Federation OIDF ES256 signing keys (02 §5 keystore, 04 §4).
// Module-local model, registered by import via models/federation.mjs
// (github-sync convention; githubSyncUserCredentials.mjs).
//
// `purpose` separates the two key sets (02 §5 table):
//   'federation' — signs Entity Configurations (leaf) + client assertions;
//                  public half is PINNED by peers (TOFU).
//   'oidc'       — signs id_tokens / tokens; served at /federation/oidc/jwks
//                  by oidc-provider (not pinned; A re-fetches at runtime).
//
// Lifecycle (02 §5 states): published -> active -> retiring -> revoked.
//   published : public half served (leaf jwks / historical endpoint).
//   active    : the single signing key.
//   retiring  : no longer signs; verification continues for the grace
//               window (Settings.federation.keyRotationGraceDays, default 14).
//   revoked   : removed from the historical set (after grace).
//
// Private halves are stored (JWK `d`) so rotation works: leaf must sign
// with a durable key and key outlives everything else.
//
import mongoose from '../../../../app/src/infrastructure/Mongoose.mjs'
const { Schema } = mongoose

export const FederationKeySchema = new Schema(
  {
    purpose: {
      type: String,
      enum: ['federation', 'oidc'],
      required: true,
    },
    kid: { type: String, required: true },
    algorithm: {
      type: String,
      default: 'ES256',
      enum: ['ES256'],
    },
    // Public JWK ({ kty, kid, alg, use?, x, y }).
    publicKey: {
      type: Object,
      required: true,
    },
    // Private JWK (full, incl. `d`). Never served.
    privateKey: {
      type: Object,
      required: true,
    },
    state: {
      type: String,
      enum: ['published', 'active', 'retiring', 'revoked'],
      default: 'published',
    },
    // Expiration (epoch seconds) for the `GET /federation/federation-keys`
    // historical payload (02 §5). Set when published; honored while
    // `state !== 'revoked'`.
    expiresAt: { type: Number },
    revokedAt: { type: Number },
    revokeReason: { type: String },
    publishedAt: { type: Number, default: 0 },
    // Last state transition (epoch seconds); the grace sweep (P0
    // start() sweep, 07 §2) reclaims `retiring` keys whose
    // stateChangedAt + keyRotationGraceDays < now.
    stateChangedAt: { type: Number, default: 0 },
  },
  { collection: 'federationKeys' },
)

FederationKeySchema.index({
  purpose: 1,
  kid: 1,
}, { unique: true })
FederationKeySchema.index({
  purpose: 1,
  state: 1,
})

export const FederationKey = mongoose.model('FederationKey', FederationKeySchema)

export default FederationKey
