import mongoose from '../infrastructure/Mongoose.mjs'

const { Schema } = mongoose
const { ObjectId } = Schema

export const EXPIRY_IN_SECONDS = 60 * 60 * 24 * 30

const ExpiryDate = function () {
  const timestamp = new Date()
  timestamp.setSeconds(timestamp.getSeconds() + EXPIRY_IN_SECONDS)
  return timestamp
}

export const ProjectInviteSchema = new Schema(
  {
    email: String,
    encryptedToken: String,
    tokenHmac: String,
    sendingUserId: ObjectId,
    projectId: ObjectId,
    // privileges contains a PrivilegeLevels value, which may be Boolean `false` or a String
    privileges: {
      type: Schema.Types.Union,
      of: [String, Boolean],
    },
    createdAt: { type: Date, default: Date.now },
    expires: {
      type: Date,
      default: ExpiryDate,
      index: { expireAfterSeconds: 10 },
    },
    reusable: { type: Boolean, default: false },
    subscriptionId: ObjectId,
    // Federated invite (federation module, plan 04 §3). Present ONLY on
    // federated invites — `federated` subdoc presence is the mark (the
    // `federated: true` boolean in v1 is retired, 04 §2.1). The owner
    // types the anchor `bla@example.com:overleaf.uni-bremen.de` into
    // the existing invite field; the controller splits on the LAST
    // colon. `email` stays empty for federated rows (the anchor is not
    // an email). `localNameHash` is the audit/rate-limit key component
    // (04 §6), never the claim itself.
    federated: {
      origin: String,
      localName: String,
      localNameHash: String,
      invitedBy: ObjectId,
      homeDisplayName: String,
      homeAvatarUrl: String,
      authorized: { type: Boolean, default: false },
      authorizedAt: Date,
      status: {
        type: String,
        enum: ['active', 'expired', 'revoked'],
        default: 'active',
      },
    },
  },
  {
    collection: 'projectInvites',
    minimize: false,
  }
)

export const ProjectInvite = mongoose.model(
  'ProjectInvite',
  ProjectInviteSchema
)
