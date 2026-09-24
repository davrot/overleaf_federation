/**
 * live-smoke-b.mjs — the B (home, OP-side) express instance for the
 * two-real-origins live smoke (plan 09 2d). Spawned by
 * live-two-origin.mjs (driver, origin alpha) with env.
 *
 * B is REAL end to end (the point of 2d — no vi.mock layer here):
 *   - oidc-provider v9 OP (/federation/oidc auth/token/jwks/resume)
 *   - the interaction bridge (consent render + the REAL Grant mint on
 *     consent — the 2a consent-grant binding the export depends on)
 *   - S2sRouter (assertion verify vs the pinned alpha anchor, replay,
 *     rate-limit, export-project + revoke actions — 2a/2c, incl. the
 *     2c export sweep on the revoked transition)
 *   - git-bridge REST (GitBridgeRouter: ensureTokenProjectAccess read +
 *     the 2c write 403 guard + PAT mgmt)
 * The ONLY fake: the login session (this process plays "B is logged in
 * as the B-native owner" — the SESSION 10 fake-login pattern; the owner
 * row is REAL in the shared Mongo).
 *
 * Shared infra (one docker pair, per-goal "shared real Mongo/Redis"):
 *   - Mongo db (shared; driver seeds users/projects/peers/keystore)
 *   - Redis (shared; oidc-provider adapter docs incl. the (owner,
 *     alpha-client) consent grant + S2S dedup/rate-limit)
 * The driver bootstraps the keystore once (shared db) before spawn, so
 * BOTH origins sign with the pinned shared ES256 key (the v1 single-
 * origin smoke has the same single-keystore property).
 *
 * Protocol: prints `READY_B <port>` once listening; the driver maps
 * `https://beta.example` → that port. Stays up until the driver kills it.
 */
process.env.MONGO_CONNECTION_STRING ??= 'mongodb://127.0.0.1:27107/fedsmoke2'
process.env.REDIS_HOST ??= '127.0.0.1'
process.env.REDIS_PORT ??= '6380'
process.env.PUBLIC_URL ??= 'https://beta.example'
process.env.SESSION_SECRET ??= 'fed-live-smoke-2025-0000000000000000000000'

import http from 'node:http'
import express from 'express'
import pug from 'pug'

const Settings = (await import('@overleaf/settings')).default
Settings.federation.enabled = true
// content-bridge v2 (2a) — B is the RECEIVING export-project origin:
// allow the S2S mint (settings gate) + the 2c sweep on the revoked
// transition. A (the driver) sets its own export.enabled separately if
// it needs to RECEIVE (it does not in this smoke — A is RP-only).
Settings.federation.export.enabled = true
Settings.federation.export.sweepOnRevoke = true

const MongooseInfra = (await import('../../../../app/src/infrastructure/Mongoose.mjs'))
  .default
const mongoose = MongooseInfra.default ?? MongooseInfra
await mongoose.connectionPromise

const { ensureBootstrapped } = await import('../../oidf/keystore.mjs')
const S2sRouter = (await import('../../s2s/S2sRouter.mjs')).default
const { mountBridge } = await import('../../oidc/bridge.mjs')
const CallbackRouter = (await import('../../rp/CallbackRouter.mjs')).default
const { getOidcProvider } = await import('../../oidc/createProvider.mjs')
const GitBridgeRouter = (await import('../../../git-bridge/app/src/GitBridgeRouter.mjs'))
  .default
const { User } = await import('../../../../app/src/models/User.mjs')

// Keystore is shared (driver bootstrapped; idempotent no-op here).
await ensureBootstrapped()

// The B-native owner this instance plays "logged in as" — REAL row
// (driver seeded) by email. Must exist before listen.
const owner = await User.findOne({ email: 'owner@beta.example' }).lean()
if (!owner) {
  console.error('live-smoke-b: owner@beta.example not seeded (driver must seed first)')
  process.exit(2)
}

// ── express (mount order per index.mjs: S2S → bridge → callback → OP;
//    git-bridge REST on its own routers, no path collision) ──────────────
const app = express()
app.use(express.json())
app.use((req, res, next) => {
  req.headers.host = 'beta.example'
  next()
})
// Fake login: the visitor on B is the B-native owner (2d precondition).
app.use((req, res, next) => {
  req.session = req.session ?? {}
  req.session.user = req.session.user ?? { _id: String(owner._id), userId: String(owner._id) }
  next()
})
// Consent view (bridge res.render's the absolute template path).
app.use((req, res, next) => {
  res.render = (view, locals) =>
    new Promise((resolve, reject) => {
      pug.renderFile(view, locals || {}, (err, html) => {
        if (err) return reject(err)
        res.status(res.statusCode || 200).send(html)
        resolve()
      })
    })
  next()
})

S2sRouter.apply(app)
mountBridge(app)
CallbackRouter.apply(app)
app.use('/federation/oidc', async (req, res, next) => {
  try {
    const provider = await getOidcProvider()
    await provider.callback()(req, res, next)
  } catch (err) {
    next(err)
  }
})

// git-bridge REST (read middleware + the 2c write guard + PAT mgmt).
const privateApiRouter = express.Router()
const publicApiRouter = express.Router()
const webRouterStub = express.Router()
GitBridgeRouter.apply(webRouterStub, privateApiRouter, publicApiRouter)
app.use(privateApiRouter)
app.use(publicApiRouter)

const server = http.createServer(app)
await new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server)))
console.log(`READY_B ${server.address().port}`)
