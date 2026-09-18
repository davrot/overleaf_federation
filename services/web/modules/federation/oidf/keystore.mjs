// Federation OIDF keystore (02 §5): a `FederationKeyProvider`
// implementation over Mongoose.
//
// npm @oidfed/core v1.0.0 interface (verified `static-key-provider.ts`):
//
//   export interface FederationKeyProvider {
//     getFederationKeySet(): Promise<FederationKeySet>
//   }
//
//   export interface FederationKeyLifecycleProvider extends FederationKeyProvider {
//     publishKey(key): Promise<FederationKey>
//     switchActiveKey(kid, options?): Promise<FederationKey>
//     revokeKey(kid, reason?): Promise<FederationKey>
//   }
//
// `FederationKeySet` is a SINGLE object — `{ signer: JwkSigner, publicJwk: JWK }`
// (verified empirically from `MemoryFederationKeyProvider.fromJWK` and
// `createFederationSigningKey`). It is NOT a `{ signer, jwks }` pair.
// `signEntityConfiguration({ signer, jwks, ... })` takes the signer +
// the `jwks` object (with `keys: [...]`) separately — so the caller
// builds `jwks: { keys: [ publicJwk ] }` from the returned `publicJwk`.
//
// Two key sets (purpose field, 02 §5 table):
//   'federation' — signs leaf Entity Configurations + client assertions;
//                  public halves are pinned by peers (TOFU, 02 §3).
//                  Full lifecycle, `FederationKeyLifecycleProvider`.
//   'oidc'       — signs id_tokens/tokens for oidc-provider
//                  (`jwks` config in 05 §8.6; kid-duality with the
//                  federation key, 05 §8.8). We bootstrap + persist; the
//                  provider does NOT rotate on its own (v1: admin-button
//                  rotation, 07 §2).
//
// State machine for `purpose: 'federation'` (02 §5):
//   published -> active -> retiring -> revoked
//     published : public half served (leaf `jwks`), not signing yet.
//     active    : the single signing key.
//     retiring  : public half still served; no longer signs (grace window).
//     revoked   : no longer served anywhere.
//
import { generateSigningKey, createFederationSigningKey } from '@oidfed/core'
import Settings from '@overleaf/settings'
import logger from '@overleaf/logger'

import FederationKey from '../app/models/FederationKey.mjs'

const PURPOSE = {
  FEDERATION: 'federation',
  OIDC: 'oidc',
}

// Leaf EC TTL (02 §2): the self-signed statement A's admin pins carries
// `exp = now + ttlSeconds`; default per @oidfed/core (DEFAULT_ENTITY_STATEMENT_TTL_SECONDS).
// 48h is short enough for the grace sweep to matter, long enough to
// survive rotation tests.
const LEAF_TTL_SECONDS = 48 * 3600

// `getFederationKeySet` is a hot path (every client-assertion fetch on
// the OP side, every leaf fetch on the SP side). Cache in memory;
// rotate/revoke paths invalidate.
// Shape: { [purpose]: { signer, publicJwk, keys: [publicJwks] } }
const cache = new Map()

function nowSeconds() {
  return Math.floor(Date.now() / 1000)
}

async function _activeKeyDoc(purpose) {
  return await FederationKey.findOne({
    purpose,
    state: 'active',
  }).lean()
}

// All non-revoked public JWKs (published + active + retiring). This is
// what `getFederationKeySet`'s return value serves (02 §5: "published
// keys are served").
async function _publicJwks(purpose) {
  const keys = await FederationKey.find({
    purpose,
    state: { $ne: 'revoked' },
  })
    .sort({ publishedAt: 1 })
    .lean()
    .then(rows => rows.map(r => r.publicKey))
  return { keys }
}

async function _federationKeySet() {
  const purpose = PURPOSE.FEDERATION
  if (cache.has(purpose)) return cache.get(purpose)
  const active = await _activeKeyDoc(purpose)
  if (!active) {
    throw new Error(
      'No active federation signing key (bootstrap has not been run)',
    )
  }
  const fedKey = createFederationSigningKey(active.privateKey)
  const set = {
    signer: fedKey.signer,
    publicJwk: fedKey.publicJwk,
    keys: (await _publicJwks(purpose)).keys,
  }
  cache.set(purpose, set)
  return set
}

/**
 * Bootstrap both key sets if empty. Called from `index.mjs` `start()`
 * (07 §2, before listen). Idempotent per purpose.
 *
 * For 'oidc' we generate + persist so a fresh instance has a valid
 * OIDC signing key on boot; the `FederationKeyLifecycleProvider` only
 * applies to the federation key set (a leaf EC can't be signed by the
 * OIDC key; different lifecycles, 02 §5).
 * */
export async function ensureBootstrapped() {
  const now = nowSeconds()
  for (const purpose of [PURPOSE.FEDERATION, PURPOSE.OIDC]) {
    const active = await _activeKeyDoc(purpose)
    if (active) continue
    const generated = await generateSigningKey('ES256')
    const { publicKey, privateKey } = generated
    const doc = await FederationKey.create({
      purpose,
      kid: publicKey.kid,
      algorithm: 'ES256',
      publicKey,
      privateKey,
      state: 'active',
      expiresAt: now + LEAF_TTL_SECONDS,
      publishedAt: now,
      stateChangedAt: now,
    })
    logger.info(
      { purpose, kid: doc.kid },
      'federation keystore: bootstrap generated signing key',
    )
    cache.delete(purpose)
  }
  return true
}

/**
 * `FederationKeyLifecycleProvider`, federation purpose (02 §5). The
 * returned object is passed to `signEntityConfiguration` etc.
 *
 * The OIDC purpose keys are managed separately (05 §8.6); they are NOT
 * a `FederationKeyLifecycleProvider` (they have no `authorityHints`,
 * no leaf, no EC — oidc-provider is the sole consumer).
 * */
export function createKeyProvider() {
  return {
    // === `FederationKeyProvider` ===
    async getFederationKeySet() {
      return await _federationKeySet()
    },

    // === `FederationKeyLifecycleProvider` ===

    // Publish a new key (admin rotation, P1 §7). The key is persisted in
    // `published` state — served by `getFederationKeySet` immediately
    // (so peers pin the new key), not yet signing.
    async publishKey(key) {
      const now = nowSeconds()
      const publicJwk = key.publicJwk || key.publicKey || key
      const privateKey = key.privateKey || key
      const existing = await FederationKey.findOne({
        purpose: PURPOSE.FEDERATION,
        kid: publicJwk.kid,
      })
      if (existing) {
        throw new Error(
          `federation key ${publicJwk.kid} already exists (${existing.state})`,
        )
      }
      const doc = await FederationKey.create({
        purpose: PURPOSE.FEDERATION,
        kid: publicJwk.kid,
        algorithm: 'ES256',
        publicKey: publicJwk,
        privateKey,
        state: 'published',
        expiresAt: now + LEAF_TTL_SECONDS,
        publishedAt: now,
        stateChangedAt: now,
      })
      cache.delete(PURPOSE.FEDERATION)
      return _toLifecycleKey(doc)
    },

    // Make a `published` key the current signer; old active key moves to
    // `retiring` (public half still served, 02 §5 grace window).
    async switchActiveKey(kid) {
      const now = nowSeconds()
      const active = await _activeKeyDoc(PURPOSE.FEDERATION)
      if (active && active.kid !== kid) {
        await FederationKey.updateOne(
          { purpose: PURPOSE.FEDERATION, state: 'active' },
          { state: 'retiring', stateChangedAt: now },
        )
      }
      const res = await FederationKey.updateOne(
        { purpose: PURPOSE.FEDERATION, kid },
        { state: 'active', stateChangedAt: now },
      )
      if (res.modifiedCount === 0) {
        throw new Error(`no key ${kid} to activate (must be in 'published')`)
      }
      cache.delete(PURPOSE.FEDERATION)
      const doc = await FederationKey.findOne({
        purpose: PURPOSE.FEDERATION,
        kid,
      }).lean()
      return _toLifecycleKey(doc)
    },

    // Move a key to `revoked` (admin, or grace sweep). Once revoked the
    // key is no longer served in `jwks` (02 §5).
    async revokeKey(kid, reason) {
      const now = nowSeconds()
      const res = await FederationKey.updateOne(
        { purpose: PURPOSE.FEDERATION, kid },
        {
          state: 'revoked',
          revokedAt: now,
          revokeReason: reason || null,
          stateChangedAt: now,
        },
      )
      if (res.modifiedCount === 0) {
        throw new Error(`no key ${kid} to revoke`)
      }
      cache.delete(PURPOSE.FEDERATION)
      const doc = await FederationKey.findOne({
        purpose: PURPOSE.FEDERATION,
        kid,
      }).lean()
      return _toLifecycleKey(doc)
    },
  }
}

function _toLifecycleKey(doc) {
  if (!doc) {
    throw new Error('internal: expected key doc to be present')
  }
  return {
    kid: doc.kid,
    state: doc.state,
    publishedAt: doc.publishedAt,
    expiresAt: doc.expiresAt,
  }
}

/**
 * GET /federation/federation-keys payload (02 §5, 04 §4). Shape per
 * `HistoricalKeysPayloadSchema` (verified npm v1.0.0, `federation-keys.ts`):
 *
 *   {
 *     iss: <issuer>,
 *     iat: <now>,
 *     keys: [ { kty, kid, use?, alg?, exp, iat?, nbf?, revoked? } ]
 *   }
 *
 * We serve `keys: []` when none exist (schema is valid with empty array).
 * All non-revoked keys are served (`published` + `active` + `retiring`);
 * the grace sweep (below) moves `retiring` keys to `revoked` after the
 * window.
 * */
export async function historicalKeySetPayload(entityId) {
  const now = nowSeconds()
  const keys = await FederationKey.find({
    purpose: PURPOSE.FEDERATION,
    state: { $ne: 'revoked' },
  })
    .sort({ publishedAt: 1 })
    .lean()
  return {
    iss: entityId,
    iat: now,
    keys: keys.map(k => ({
      kty: k.publicKey.kty,
      kid: k.kid,
      ...(k.publicKey.alg ? { alg: k.publicKey.alg } : {}),
      ...(k.publicKey.use ? { use: k.publicKey.use } : {}),
      exp: k.expiresAt,
      ...(k.publishedAt ? { iat: k.publishedAt } : {}),
    })),
  }
}

/**
 * Grace sweep (07 §2, start()): move `retiring` keys past their window to
 * `revoked`. Called once per boot.
 * */
export async function retireExpiredKeys() {
  const now = nowSeconds()
  const cutoff =
    now - (Settings.federation?.keyRotationGraceDays ?? 14) * 3600 * 24
  const expired = await FederationKey.find({
    purpose: PURPOSE.FEDERATION,
    state: 'retiring',
    stateChangedAt: { $lt: cutoff },
  }).lean()
  for (const doc of expired) {
    await FederationKey.updateOne(
      { _id: doc._id },
      {
        state: 'revoked',
        revokedAt: now,
        revokeReason: 'grace sweep',
        stateChangedAt: now,
      },
    )
    logger.info({ kid: doc.kid }, 'federation keystore: grace sweep revoked key')
  }
  cache.delete(PURPOSE.FEDERATION)
  return expired.length
}

/**
 * jwks payload for the LEAF EC (02 §2, pinned by peer). Serves
 * published + active + retiring public halves — never `revoked`.
 * This is the JWK set a peer pins on first trust establishment.
 * */
export async function leafJwksPayload() {
  return await _publicJwks(PURPOSE.FEDERATION)
}

/**
 * OIDC-provider `jwks` config (05 §8.6). Returns a SINGLE private JWK
 * (with `d`); `oidc-provider` requires ALL keys to be private (kid
 * duality, 05 §8.8). For a boot-time rebuild after rotation we return
 * every non-revoked OIDC key so the provider serves its full public
 * halves (clients may have pinned different kids).
 *
 * NOTE: oidc-provider does NOT rotate for us in v1; admin rotation
 * (P1 §7) swaps the doc in the DB and re-builds the provider.
 * */
export async function oidcSigningKeys() {
  const keys = await FederationKey.find({
    purpose: PURPOSE.OIDC,
    state: { $ne: 'revoked' },
  })
    .sort({ publishedAt: 1 })
    .lean()
  return keys.map(k => k.privateKey)
}

/**
 * Admin-facing listing for the settings screen (07 §2). Public-halves
 * only (05 §1.1 privacy note for `Federation.keyRotation`).
 * */
export async function listPublicKeys() {
  const keys = await FederationKey.find({
    purpose: PURPOSE.FEDERATION,
  })
    .sort({ publishedAt: 1 })
    .lean()
  return keys.map(k => ({
    kid: k.kid,
    state: k.state,
    publishedAt: k.publishedAt,
    stateChangedAt: k.stateChangedAt,
  }))
}

// --- Testing: clear the in-memory signer cache between tests ---
export function _clearKeySetCache() {
  cache.clear()
}
