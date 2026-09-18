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
 * Key layout (04 §5, 05 §8.2):
 *
 *   federation:oidc:<model>:<id>      -> JSON payload doc
 *   federation:oidc:sub:<uid>         -> Session id (the `sessionUid` sub-index)
 *   federation:oidc:usercode:<code>   -> DeviceCode id (CIBA; disabled but
 *                                        cheap to keep)
 *   federation:oidc:grant:<grantId>   -> SET of doc keys holding grantId
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
        if (GRANTABLE.has(modelName) && payload.grantId) {
          await r.srem(`federation:oidc:grant:${payload.grantId}`, key)
          const remaining = await r.scard(`federation:oidc:grant:${payload.grantId}`)
          if (remaining === 0) {
            await r.del(`federation:oidc:grant:${payload.grantId}`)
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
