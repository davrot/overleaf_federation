// B-side export grant ledger (09 §3.1) — the MIRROR of the consent grant:
// one row per exported project, holding the minted PAT id so 2c can sweep
// the `db.oauthAccessTokens` doc when the grant is revoked/expired.
//
// NOT the consent itself: the consent lives in the oidc-provider Grant doc
// (30-day TTL, Redis). This row is the durable audit + sweep anchor.
import mongoose from '../../../../app/src/infrastructure/Mongoose.mjs'

const { Schema } = mongoose

export const FederationExportGrantSchema = new Schema(
	{
		owner: { type: Schema.Types.ObjectId, required: true },
		projectId: { type: String, required: true },
		homeOrigin: { type: String, required: true },
		scope: { type: String, required: true },
		patHashPrefix: { type: String, required: true },
		patId: { type: String, required: true },
		expiresAt: { type: Date, required: true },
		status: { type: String, required: true },
		createdAt: { type: Date },
	},
	{ collection: 'federationExportGrants' },
)

export const FederationExportGrant = mongoose.model(
	'FederationExportGrant',
	FederationExportGrantSchema,
)

export default FederationExportGrant
