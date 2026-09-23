import logger from '@overleaf/logger'
import crypto from 'crypto'
import { ObjectId } from 'mongodb'
import { db } from '../../../../app/src/infrastructure/mongodb.mjs'
import { OauthApplication } from '../../../../app/src/models/OauthApplication.mjs'

const PAT_PREFIX = 'olp_'
const PAT_LENGTH = 36 // without 'olp_' prefix
const PAT_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

function _hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex')
}

function _generateToken(length) {
  const patCharsLength = PAT_CHARS.length
  let token = ''
  for (let i = 0; i < length; i++) {
    token += PAT_CHARS[crypto.randomInt(patCharsLength)]
  }
  return token
}

const GitBridgePATManager = {

  async getTokens(user_id) {
    const query = {
      user_id,
      scope: /\bgit_bridge\b/,
      type: 'personal_access_token'
    }
    const projection = {
      accessTokenPartial: 1,
      createdAt: 1,
      expiresAt: 1,
      lastUsedAt: 1
    }

    return await db.oauthAccessTokens
      .find(query, { projection })
      .sort({ createdAt: 1 })
      .toArray()
  },

  async countTokens(user_id) {
    const query = {
      user_id,
      scope: /\bgit_bridge\b/,
      type: 'personal_access_token'
    }
    return db.oauthAccessTokens.countDocuments(query)
  },

  async createToken(user_id) {
    const token = PAT_PREFIX + _generateToken(PAT_LENGTH)
    const createdAt = new Date()
    const expiresAt = new Date(createdAt)
    expiresAt.setFullYear(expiresAt.getFullYear() + 1)
    const accessTokenPartial = token.substring(0, 8)

    const result = await db.oauthAccessTokens.insertOne({
      accessToken: _hashToken(token),
      accessTokenPartial,
      user_id,
      type: 'personal_access_token',
      scope: 'git_bridge',
      createdAt,
      expiresAt,
    })

    return {
      _id: result.insertedId,
      accessToken: token,
      accessTokenPartial,
      createdAt,
      expiresAt
    }
  },

  async deleteToken(tokenId, user_id) {
    const query = {
      _id: new ObjectId(tokenId),
      user_id,
    }
    const result = await db.oauthAccessTokens.deleteOne(query)
    return result?.deletedCount || 0
  },

  // content-bridge 2c (plan 09 §4): a scope-aware mirror of `getUserId` so
  // the git-bridge write path (`receive-pack` → snapshot postback) can
  // refuse `federation:`-scoped export PATs (read-only) WITHOUT importing
  // the federation module — the marker is the token's scope string
  // (`federation:git_bridge`, minted by B's export-project S2S). The
  // git-bridge auth regex `/\bgit_bridge\b/` matches both `git_bridge`
  // (user PATs) and `federation:git_bridge` (export PATs) because `:` is a
  // non-word boundary, so the write path must distinguish by the `federation:`
  // prefix itself.
  async getUserIdAndScope(token) {
    if (!token?.startsWith(PAT_PREFIX)) return null

    const now = new Date()
    const objToken = await db.oauthAccessTokens.findOne(
      {
        accessToken: _hashToken(token),
        type: 'personal_access_token',
        scope: /\bgit_bridge\b/,
        expiresAt: { $gt: now }
      }, { projection: { user_id: 1, scope: 1 } }
    )

    if (!objToken?.user_id) return null

// does the user still exists and not deleted?
// tokens of a deleted user are not deleted until user expires
    const user = await db.users.findOne(
      { _id: new ObjectId(objToken.user_id) },
      { projection: { _id: 1 } }
    )

    if (!user) return null

    // non-blocking
    db.oauthAccessTokens.updateOne(
      { _id: objToken._id },
      { $set: { lastUsedAt: now } }
    ).catch(err =>
      logger.error({ err }, 'Failed to update lastUsedAt')
    )

    return { userId: objToken.user_id, scope: objToken.scope }
  },

  async getUserId(token) {
    const info = await this.getUserIdAndScope(token)
    return info ? info.userId : null
  },
}

export default GitBridgePATManager
