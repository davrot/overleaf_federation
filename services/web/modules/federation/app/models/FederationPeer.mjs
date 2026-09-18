import mongoose from '../../../../app/src/infrastructure/Mongoose.mjs'

const { Schema } = mongoose

/**
 * A federated peer: another overleaf-cep instance our admins have (partially)
 * trusted. In OIDF terms the row stores the anchor (federation-key public
 * JWK we pin/verify for this peer), and in institutional mode also the
 * OIDF explicit-registration result.
 *
 * Trust direction (04-data-model §2, plan v2):
 *   'outbound' = we pin them for calls they make to us (S2S receive + grants
 *                 they may mint against us, when direction inbound/both)
 * The row is the single source for:
 *  - the oidc-provider `clients[]` reconstruction (approved, inbound/both)
 *  - S2S `authorize-invite`/`invited`/`revoke` approvals (approved status)
 *  - trust anchor set for the OIDC role (institutional: registered anchors)
 */
export const FederationPeerSchema = new Schema(
	{
		// home FQDN, e.g. 'overleaf.uni-bremen.de'
		origin: {
			type: String,
			unique: true,
			match: /^[a-z0-9][a-z0-9.-]+$/i,
		},
		// admin-entered (pairwise); registration metadata (institutional)
		displayName: String,
		// OIDF entity id, e.g. 'https://overleaf.uni-bremen.de'
		entityId: String,
		mode: {
			type: String,
			enum: ['pairwise', 'institutional'],
			default: 'pairwise',
		},
		// Institutional mode only (02 §4): explicit registration statement
		// result. Pairwise mode has no registration statement — pinning IS
		// establishment (02 §3).
		registration: {
			clientId: String,
			// exp of the registration statement
			expiresAt: Number,
			// 02 §4 explicitlyRegister result: how long the trust chain
			// (up to the trust anchor) is valid
			trustChainExpiresAt: Number,
			// audit/replay only — the anchor pin itself is ground truth
			childAnchorJwks: String,
			childAnchorKid: String,
		},
		// The federation public JWK we verify this peer's S2S client
		// assertions and leaf ECs against. JSON-serialized single JWK.
		anchorJwks: String,
		kid: String,
		// SHA-256 thumbprint of anchorJwks — admin display (TOFU, 02 §3)
		thumbprint: String,
		direction: {
			type: String,
			enum: ['outbound', 'inbound', 'both'],
		},
		status: {
			type: String,
			enum: ['pending', 'approved', 'revoked'],
			default: 'pending',
		},
		federatedAt: { type: Date, default: Date.now },
		approvedAt: Date,
		// leaf/JWKS re-fetch on kid mismatch (04 §6)
		lastTrustRefreshAt: Date,
		// S2S `revoke` (03 §4.3): invalidate outstanding auth codes for
		// this peer on approval
		killOutstandingCodes: { type: Boolean, default: false },
	},
	{ collection: 'federationPeers' }
)

FederationPeerSchema.index({ status: 1, direction: 1 })

export const FederationPeer = mongoose.model('FederationPeer', FederationPeerSchema)
