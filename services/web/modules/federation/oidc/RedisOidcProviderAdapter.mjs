/**
 * RedisOidcProviderAdapter — oidc-provider v9 7-method adapter, Redis-backed.
 *
 * Grounded contract (plan 05 §8.2, all verified against
 * `node_modules/oidc-provider` v9.12.2 source):
 *
 *   - `lib/helpers/initialize_adapter.js`: `adapter` is either a
 *     constructor or a **factory function** `(modelName) => instance`.
 *   - `lib/models/base_model.js:19-31`: per-model adapter cache; the
 *     factory is called **without `new`**, so a plain function is safe.
 *   - `lib/adapters/memory_adapter.js` (the reference shape) is the
 *     authority for the 7 methods and for what `find(id)` must return:
 *     the **stored payload object itself** (not a wrapped doc). It is
 *     passed straight into `opaque.verify(provider, stored)` and the
 *     model is instantiated from it.
 *
 * Key layout (04 §5, 05 §8.2, 06 §178):
 *
 *   federation:oidc:<model>:<id>      -> JSON payload doc
 *   federation:oidc:sub:<uid>         -> Session id (the `sessionUid` sub-index)
 *   federation:oidc:usercode:<code>   -> DeviceCode id (CIBA; disabled but
 *                                        cheap to keep)
 *   federation:oidc:grant:<grantId>   -> SET of doc keys holding grantId
 *   federation:oidc:client:<clientId> -> SET of doc keys minted for one
 *                                        client (04 §5 `killOutstandingCodes`
 *                                        sweep index — token docs only, see
 *                                        `revokeClientCodes`)
 *   federation:oidc:account:<accountId>:<clientId>
 *                             -> SET of grant-doc keys (content-bridge
 *                                v2 plan 09 §2.1 — secondary index for
 *                                `findByAccountAndClient`). Written SADD on
 *                                Grant-model upsert, SREM on Grant destroy
 *                                (cascade lives in `destroy`, the single
 *                                grant-doc removal path; the index is NOT
 *                                in the `grant:`-sweep set because a Grant
 *                                is not `grantable`). Stale members from
 *                                TTL expiry are skipped by
 *                                `findByAccountAndClient` (pttl < 0).
 *
 * `upsert(id, payload, expiresIn)` is the ONLY persistence point
 * (base_model.js save()), per model (AuthorizationCode: 120 s, Grant:
 * 30 d, Interaction: 600 s, ... — 05 §8.6 `ttl`). SECONDS. `expiresIn`
 * may be undefined for default-ttl Grants; we then omit the EX arg.
 *
 * `consume(id)` mirrors memory_adapter.js `consume`: sets
 * `payload.consumed = epochTime()` (seconds) on the stored doc and
 * re-sets it — the row is NOT deleted (revocation cascade still needs
 * it, 02 §7.5). Single-use is then enforced by the model's
 * `isValid`/`isExpired` + `consumed` flag.
 */

// Exact set from lib/adapters/memory_adapter.js `grantable`.
const GRANTABLE = new Set([
  'AccessToken',
  'AuthorizationCode',
  'RefreshToken',
  'DeviceCode',
  'BackchannelAuthenticationRequest',
  'PreAuthorizedCode',
])

export function accountIndexKey(accountId, clientId) {
  return `federation:oidc:account:${accountId}:${clientId}`
}

/**
 * The Grant model doc key in Redis (`federation:oidc:Grant:<jti>`)
 * (09 §2.1 TTL clamp + 2a export's grant-remaining read use this).
 * @param {string} grantId the grant jti
 * @returns {string} the redis doc key
 */
export function grantDocKey(grantId) {
  return `federation:oidc:Grant:${grantId}`
}

/**
 * Content-bridge v2 (plan 09 §2.1): return the live consent grant jti
 * for (accountId, clientId), or null. Scans the account-key SET, resolves
 * each member doc, and returns the first LIVE (pttl ≥ 0) doc whose payload
 * still holds the same (accountId, clientId) pair. v1 consent dedup: the
 * first live grant wins; multi-consent dedup is v2.2+. Never throws —
 * a Redis/parse error is a soft no-consent (the export path re-checks
 * the grant via `provider.Grant` load, so a stale index degrades to a
 * fresh consent, mirroring v1 `findExistingGrant` behavior).
 *
 * @param {object} r redis client (injected / from `getClient`)
 * @param {string} accountId B-side user id (string)
 * @param {string} clientId `urn:overleaf-federation:client:<origin>`
 * @returns {Promise<string|null>} the grant jti, or null
 */
export async function findByAccountAndClient(r, accountId, clientId) {
  const key = accountIndexKey(accountId, clientId)
  const members = await r.smembers(key)
  for (const memberKey of members) {
    const raw = await r.get(memberKey)
    if (raw == null) continue
    const ttl = await r.pttl(memberKey)
    if (ttl < 0) continue // expired by TTL
    let payload
    try {
      payload = JSON.parse(raw)
    } catch {
      continue
    }
    if (payload.accountId !== accountId) continue
    if (payload.clientId !== clientId) continue
    return payload.jti
  }
  return null
}

/**
 * Build the adapter factory. With no argument the Redis client is
 * obtained lazily from `RedisWrapper.client('federation')`; tests can
 * inject a fake via `_makeTestFactory(fakeClient)`.
 *
 * @param {object} [redisClient] — optional injected ioredis client
 * @returns {(modelName: string) => Promise<object>|object} adapter factory
 */
export default function createAdapter(redisClient) {
  const getClient = redisClient != null
    ? async () => redisClient
    : () => import('../../../app/src/infrastructure/RedisWrapper.mjs')
      .then(({ default: RedisWrapper }) => RedisWrapper.client('federation'))
  return (modelName) => createAdapterInstance(modelName, getClient)
}

/**
 * Kill every outstanding token doc minted for one client (04 §5
 * `killOutstandingCodes`, 03 §4.3 "optionally invalidates outstanding
 * codes", 06 §178/§179 the hostile residual).
 *
 * Index scope (verified against oidc-provider 9.12.2 source):
 *   - `lib/models/base_token.js IN_PAYLOAD` includes `clientId`, and
 *     `lib/models/payload.js pickPayload` persists it — EVERY
 *     BaseToken-derived doc (AuthorizationCode, AccessToken, Grant, …)
 *     carries the minting client id as a payload value.
 *   - The index is gated on GRANTABLE (token models), NOT on `clientId`
 *     presence: `Grant extends BaseToken` and has `clientId`, yet a
 *     consent Grant must not be swept (06 §174 consent is per-origin;
 *     revocation affects NEW grants, not the consent record).
 *   - Session/Interaction extend BaseModel (no `clientId` payload) and
 *     never enter the index → `destroy` leaves `federation:oidc:sub:<uid>`
 *     alone (code payloads also carry `sessionUid`, not `uid`) → 06 §178
 *     "not over-cross": A's admin does not log out B's users.
 *
 * Idempotent: an empty/absent index returns 0; a doc already expired by
 * TTL is a no-op del. The sweep is the only writer of the index outcome
 * (membership is also trimmed by `destroy` on every normal expiration,
 * so the steady-state set is small).
 *
 * @param {string} clientId — `urn:overleaf-federation:client:<origin>`
 *   (use `clients.mjs` `federationClientId`; this function does no
 *   origin guessing — the caller owns the convention)
 * @param {object} [redisClient] — optional injected ioredis client
 *   (default: `RedisWrapper.client('federation')`, lazy)
 * @returns {Promise<number>} number of docs destroyed
 */
export async function revokeClientCodes(clientId, redisClient) {
  const getClient = redisClient != null
    ? async () => redisClient
    : () => import('../../../app/src/infrastructure/RedisWrapper.mjs')
      .then(({ default: RedisWrapper }) => RedisWrapper.client('federation'))
  const r = await getClient()
  const setKey = `federation:oidc:client:${clientId}`
  const members = await r.smembers(setKey)
  for (const memberKey of members) {
    // Member is a doc key: federation:oidc:<Model>:<id>. Docs that
    // expired by TTL leave stale members — `destroy` on a missing doc is
    // a no-op del, the srem below drops the membership, and real Redis
    // reclaims the SET on its last member anyway.
    const m = /^federation:oidc:([^:]+):(.+)$/.exec(memberKey)
    if (!m) {
      await r.srem(setKey, memberKey)
      continue
    }
    const [, modelName, id] = m
    await createAdapterInstance(modelName, getClient).destroy(id)
  }
  await r.del(setKey)
  return members.length
}

/**
 * A single adapter instance for one model. `getClient` is
 * `() => Promise<ioredis>` so the factory itself is synchronous
 * (base_model.js:26 calls it plain, then awaits the methods).
 */
function createAdapterInstance(modelName, getClient) {
  return {
    modelName,

    async find(id) {
      const raw = await (await getClient()).get(docKey(modelName, id))
      return raw == null ? undefined : JSON.parse(raw)
    },

    /**
     * Session-only sub-index (memory_adapter `sessionUid:<uid>`)
     * `lib/models/session.js:37-46` does `verify(stored)` on what we
     * return, so we resolve the doc key via find().
     */
    async findByUid(uid) {
      const id = await (await getClient()).get(`federation:oidc:sub:${uid}`)
      return id == null ? undefined : await this.find(id)
    },

    /**
     * CIBA user-code lookup (lib/models/device_code.js:6). CIBA is
     * disabled (05 §8.6 features), but v9 still routes DeviceCode here;
     * unknown codes return undefined as expected.
     */
    async findByUserCode(userCode) {
      const id = await (await getClient()).get(`federation:oidc:usercode:${userCode}`)
      return id == null ? undefined : await this.find(id)
    },

    async upsert(id, payload, expiresIn) {
      const r = await getClient()
      const key = docKey(modelName, id)
      const args = expiresIn != null ? [key, JSON.stringify(payload), 'EX', expiresIn] : [key, JSON.stringify(payload)]
      await r.set(...args)
      if (modelName === 'Session' && payload.uid != null) {
        const subArgs = expiresIn != null
          ? [`federation:oidc:sub:${payload.uid}`, id, 'EX', expiresIn]
          : [`federation:oidc:sub:${payload.uid}`, id]
        await r.set(...subArgs)
      }
      if (payload.userCode != null) {
        const args2 = expiresIn != null
          ? [`federation:oidc:usercode:${payload.userCode}`, id, 'EX', expiresIn]
          : [`federation:oidc:usercode:${payload.userCode}`, id]
        await r.set(...args2)
      }
      if (GRANTABLE.has(modelName) && payload.grantId) {
        await r.sadd(`federation:oidc:grant:${payload.grantId}`, key)
      }
      // Account secondary index (content-bridge v2, plan 09 §2.1). A
      // Grant doc is the consent record and the single owner of an
      // (account, client) pair; token docs (GRANTABLE) are NOT grant
      // owners and never enter this set. `findByAccountAndClient` gates
      // on the doc pttl, so stale TTL members are skipped, not errors.
      if (modelName === 'Grant' && payload.accountId != null && payload.clientId != null) {
        const acctKey = accountIndexKey(payload.accountId, payload.clientId)
        await r.sadd(acctKey, key)
      }
      // Client sweep index (04 §5 `killOutstandingCodes`): TOKEN docs
      // (GRANTABLE models) persist a `clientId` payload (BaseToken
      // IN_PAYLOAD) and are recorded under the minting client (see
      // `revokeClientCodes`). Gated on the model list, NOT on
      // `clientId` presence: `Grant` extends BaseToken in v9 and carries
      // `clientId` too, but a consent Grant is NOT swept (06 §174).
      // No EX on the SET: real Redis reclaims a SET on its last member,
      // and stale members are harmless (the sweep no-ops on expired
      // docs).
      if (GRANTABLE.has(modelName) && typeof payload.clientId === 'string') {
        await r.sadd(`federation:oidc:client:${payload.clientId}`, key)
      }
      return id
    },

    /**
     * Revocation cascade (lib/models/*.js `revokeByGrantId`): drop
     * every grantable doc holding this grantId. Mirrors
     * memory_adapter `revokeByGrantId` (iterate members, delete
     * docs + secondary indexes, delete the index).
     */
    async revokeByGrantId(grantId) {
      const r = await getClient()
      const setKey = `federation:oidc:grant:${grantId}`
      const members = await r.smembers(setKey)
      for (const memberKey of members) {
        const raw = await r.get(memberKey)
        if (raw == null) continue
        const payload = JSON.parse(raw)
        if (payload.uid != null) await r.del(`federation:oidc:sub:${payload.uid}`)
        if (payload.userCode != null) await r.del(`federation:oidc:usercode:${payload.userCode}`)
        // Client sweep index: `revokeByGrantId` bypasses `destroy`, so
        // drop the doc from the minting client's set here (and del the
        // set when empty, mirroring the fake-Redis behavior in `destroy`).
        if (GRANTABLE.has(modelName) && typeof payload.clientId === 'string') {
          const clientSet = `federation:oidc:client:${payload.clientId}`
          await r.srem(clientSet, memberKey)
          const remainingClients = await r.scard(clientSet)
          if (remainingClients === 0) {
            await r.del(clientSet)
          }
        }
        await r.del(memberKey)
      }
      await r.del(setKey)
    },

    async destroy(id) {
      const r = await getClient()
      const key = docKey(modelName, id)
      const raw = await r.get(key)
      await r.del(key)
      if (raw != null) {
        const payload = JSON.parse(raw)
        if (payload.uid != null) await r.del(`federation:oidc:sub:${payload.uid}`)
        if (payload.userCode != null) await r.del(`federation:oidc:usercode:${payload.userCode}`)
        // Account secondary index cascade (content-bridge v2): a Grant
        // doc is the single owner of its (account, client) pair. SREM
        // from the pair's SET when the grant doc is removed. Non-Grant
        // models never entered the set (upsert gate), so no-op.
        if (modelName === 'Grant' && payload.accountId != null && payload.clientId != null) {
          const acctKey = accountIndexKey(payload.accountId, payload.clientId)
          await r.srem(acctKey, key)
          const remainingAcct = await r.scard(acctKey)
          if (remainingAcct === 0) {
            await r.del(acctKey)
          }
        }
        if (GRANTABLE.has(modelName) && payload.grantId) {
          await r.srem(`federation:oidc:grant:${payload.grantId}`, key)
          const remaining = await r.scard(`federation:oidc:grant:${payload.grantId}`)
          if (remaining === 0) {
            await r.del(`federation:oidc:grant:${payload.grantId}`)
          }
        }
        // Client sweep index: drop this doc from the minting client's
        // set. GRANTABLE gate (a Grant still holds `clientId` in its
        // payload and must never be touched here — it was never in the
        // index), mirroring `revokeByGrantId` above.
        if (GRANTABLE.has(modelName) && typeof payload.clientId === 'string') {
          const clientSet = `federation:oidc:client:${payload.clientId}`
          await r.srem(clientSet, key)
          const remaining = await r.scard(clientSet)
          if (remaining === 0) {
            // Real Redis deletes a SET that becomes empty via SREM; the
            // fake test clients do not — mirror the grant-SET cleanup
            // above.
            await r.del(clientSet)
          }
        }
      }
    },

    /**
     * Single-use flag (memory_adapter `consume`):
     *   payload.consumed = epochTime()
     * The doc is re-set with its remaining TTL; it is NOT deleted.
     */
    async consume(id) {
      const r = await getClient()
      const key = docKey(modelName, id)
      const raw = await r.get(key)
      if (raw == null) return
      const payload = JSON.parse(raw)
      payload.consumed = Math.floor(Date.now() / 1000)
      const ttl = await r.pttl(key)
      const args = ttl > 0 ? [key, JSON.stringify(payload), 'PX', ttl] : [key, JSON.stringify(payload)]
      await r.set(...args)
    },
  }
}

function docKey(modelName, id) {
  return `federation:oidc:${modelName}:${id}`
}

/**
 * Test helper: build a factory around an injected fake redis client
 * (the same shape `RedisWrapper.client()` returns).
 */
export function _makeTestFactory(fakeClient) {
  return (modelName) => createAdapterInstance(modelName, async () => fakeClient)
}
