// B-side content bridge v2: export-project (plan 09 §2, SESSION 11 LOCKED).
//
// A asks B: "project <B-local id> belongs to a user of yours who has a
// LIVE consent grant to me (home A's client) — mint a short-lived
// READ-ONLY git PAT for it and return it".
//
// The user binding is B's CONSENT GRANT (09 §2.1: "the export succeeds
// iff the project owner has a live consent grant to home A's client"),
// NOT the S2S assertion (server identity only, OIDF 1.0).
//
// Handler ordering (LOCKED):
//   1 settings gate      → 200 envelope `export-disabled`
//   2 payload sanity     → 200 envelope `project-not-owned` (malformed)
//   3 project lookup     → missing → `project-not-owned`
//   4 owner B-native     → mirror row / suspended / missing → `project-not-owned`
//   5 consent grant      → no live (owner, home A client) grant → `export-no-consent`
//   6 PAT mint           → fresh raw token per request (the raw value is
//                          NEVER persisted — sha256 in `oauthAccessTokens`;
//                          re-export = fresh raw token + ledger upsert, so
//                          idempotency is on the grant row, not the token)
//   7 ledger upsert      → `federationExportGrants` row (status 'exported')
//       TTL              → min(request, grant remaining,
//                            Settings.federation.export.maxExportTtlSeconds)
//
// Business refusals are 200 + in-band envelope (LOCKED SESSION 11 — plan
// 09 "401s" phrasing is code-taxonomy shorthand). Peer-level refusals
// (`peer-not-approved` / `peer-unknown`) and 429 rate-limit are the
// S2sRouter ③/⑤ layer.
//
// Response (LOCKED, SESSION 11): `{ ok: true, payload: { git_url, pat,
//   expires_at } }` — snake_case keys (plan 09 §2 `gitUrl` naming is
// superseded by the 2a lock; the 2b wizard reads these).
//
// Audit: the S2sRouter ⑦ writes `federation_export_granted/denied`
// (redacted — `scope` constant + hashed assertion only; NEVER the PAT
// value/length/expiry, plan 09 §3 + HANDOFF SESSION 11 "Redact" item).
import crypto from 'node:crypto'
import logger from '@overleaf/logger'
import Settings from '@overleaf/settings'

import { Project } from '../../../../app/src/models/Project.mjs'
import { User } from '../../../../app/src/models/User.mjs'
import { db } from '../../../../app/src/infrastructure/mongodb.mjs'
import RedisWrapper from '../../../../app/src/infrastructure/RedisWrapper.mjs'

import { FederationExportGrant } from '../../app/models/FederationExportGrant.mjs'
import { federationClientId } from '../../oidc/clients.mjs'
import { grantDocKey, findByAccountAndClient } from '../../oidc/RedisOidcProviderAdapter.mjs'
import { S2S_ERRORS } from '../../oidf/verify.mjs'

// scope marker (plan 09 §3): the git-bridge matcher /\bgit_bridge\b/
// still passes (": " is a non-word boundary), 2c's 403 guard keys off the
// `federation:` prefix.
export const EXPORT_SCOPE = 'federation:git_bridge'

const PAT_PREFIX = 'olp_'
const PAT_LENGTH = 36
const PAT_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

function _hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex')
}

function _generateToken() {
  let token = ''
  for (let i = 0; i < PAT_LENGTH; i++) {
    token += PAT_CHARS[crypto.randomInt(PAT_CHARS.length)]
  }
  return PAT_PREFIX + token
}

// `https://<B-host>/git/<projectId>` (plan 09 §2; host = full
// Settings.siteUrl host INCLUDING port — the git-bridge mount is a
// real URL, not the origin FQDN).
function gitUrlFor(projectId) {
  const siteUrl = new URL(Settings.siteUrl)
  return `https://${siteUrl.host}/git/${projectId}`
}

/**
 * B-side export-project (09 §2). See the file header for the ordering.
 *
 * @param {object} args
 * @param {object} args.body the S2S wire envelope (verified by the router)
 * @param {string} args.callerOrigin the wire's `from` (home A origin)
 * @param {object} args.peer the approved caller peer row
 * @returns {Promise<{ok: boolean, code?: string, detail?: string, payload?: object}>}
 */
export default async function exportProject({ body, callerOrigin }) {
  // 1 settings gate.
  if (!Settings.federation?.export?.enabled) {
    return { ok: false, code: S2S_ERRORS.EXPORT_DISABLED, detail: 'export disabled' }
  }

  const projectId = body?.payload?.projectId
  if (typeof projectId !== 'string' || projectId.length === 0) {
    return { ok: false, code: S2S_ERRORS.PROJECT_NOT_OWNED, detail: 'malformed projectId' }
  }

  // 3 project lookup (CastError on a bad id → not-found refusal).
  const project = await Project.findOne({ _id: projectId })
    .select('owner_ref')
    .lean()
    .catch(() => null)
  if (!project || !project.owner_ref) {
    return { ok: false, code: S2S_ERRORS.PROJECT_NOT_OWNED, detail: 'project not found' }
  }

  // 4 owner B-native (mirror rows are home-side, 04 §1 — they cannot own
  //   on B; a suspended owner cannot export).
  const owner = await User.findOne({ _id: project.owner_ref })
    .select('_id federation suspended')
    .lean()
    .catch(() => null)
  if (!owner || owner.suspended || owner.federation) {
    return { ok: false, code: S2S_ERRORS.PROJECT_NOT_OWNED, detail: 'owner missing/mirror/suspended' }
  }

  // 5 consent-grant binding (09 §2.1).
  const redis = await RedisWrapper.client('federation')
  const clientId = federationClientId(callerOrigin)
  const grantId = await findByAccountAndClient(redis, String(owner._id), clientId).catch(() => null)
  if (!grantId) {
    return { ok: false, code: S2S_ERRORS.EXPORT_NO_CONSENT, detail: 'no live consent grant' }
  }

  // TTL = min(request, grant remaining, maxExportTtlSeconds) (09 §3/§5;
  // SESSION 11 "TTL = min(request ttl, grant remaining ttl, max)").
  // Soft degrade: unknown grant remaining → max cap.
  const maxTtl = Settings.federation.export.maxExportTtlSeconds || 86400
  const nowSec = Math.floor(Date.now() / 1000)
  const requestedExp = typeof body.payload.expiresAt === 'number' ? body.payload.expiresAt : null
  let ttl = requestedExp != null ? requestedExp - nowSec : maxTtl
  const grantTtlMs = await redis
    .pttl(grantDocKey(grantId))
    .catch(() => -1)
  if (grantTtlMs > 0) {
    ttl = Math.min(ttl, Math.floor(grantTtlMs / 1000))
  }
  ttl = Math.max(Math.min(ttl, maxTtl), 1)

  // 6 PAT mint (fresh raw token per request — the raw value is never
  //   persisted; sha256 only). scope = EXPORT_SCOPE (git-bridge matcher
  //   /\bgit_bridge\b/ passes; 2c receive-pack guard keys off
  //   `federation:` prefix → read-only).
  const raw = _generateToken()
  const expiresAt = new Date(nowSec * 1000 + ttl * 1000)
  const insert = await db.oauthAccessTokens.insertOne({
    accessToken: _hashToken(raw),
    accessTokenPartial: raw.substring(0, 8),
    user_id: String(owner._id),
    type: 'personal_access_token',
    scope: EXPORT_SCOPE,
    createdAt: new Date(nowSec * 1000),
    expiresAt,
  })

  // 7 ledger row (upsert on (owner, project, home) — the idempotent
  //   re-export: fresh raw PAT + the same grant row, refreshed).
  await FederationExportGrant.updateOne(
    { owner: owner._id, projectId, homeOrigin: callerOrigin },
    {
      $set: {
        patHashPrefix: raw.substring(0, 8),
        patId: String(insert.insertedId),
        scope: EXPORT_SCOPE,
        expiresAt,
        status: 'exported',
      },
      $setOnInsert: { homeOrigin: callerOrigin, createdAt: new Date() },
    },
  ).catch(error => {
    // Ledger failure must not break a legitimate export (the PAT is
    // valid + short-lived); 2c's sweep is best-effort on top of it.
    logger.warn({ error, projectId }, 'federation export: ledger upsert failed')
  })

  return {
    ok: true,
    payload: {
      git_url: gitUrlFor(projectId),
      pat: raw,
      expires_at: nowSec + ttl,
    },
  }
}
