// federation WebModule — overleaf-cep OIDF identity federation (05 §1).
//
// WebModule contract (types/web-module.ts): `nonCsrfRouter`, `router`,
// `appMiddleware`, and `start` are ALL optional. This module wires:
//
//   nonCsrfRouter:
//     ① S2S endpoint (always mounted; peers get `federation-off` 200
//        when the master toggle is off)
//     ② bridge (interaction redirect, before the terminal OIDC mount)
//     ③ terminal OIDC mount (`/federation/oidc`)
//   router:
//     ④ invite endpoints (preview + authorize)
//     ⑤ admin endpoints (`/admin/federation/*`)
//   appMiddleware: leaf EC + federation-keys (app-level, needs
//     req.hostname)
//   start: keystore bootstrap + grace sweep
//
// MOUNT ORDER (05 §1.1): bridge (non-csrf explicit routes) must come
// BEFORE `webRouter.use('/federation/oidc', provider.callback())` (the
// catch-all 404) so GETs for `/federation/oidc/interact/:uid` never
// reach the oidc-provider middleware stack.
//
// CSRF (03 §2, 05 §1): S2S and bridge are non-csrf (they're not browser
// form posts, they're machine assertions and op-redirects). The terminal
// OP mount is also non-csrf (oidc-provider handles its own csrf). Admin
// + invite endpoints ride `router` (the csr-applied web router).
//
// The callback landing (`/federation/oidc/rp/callback`) is also
// non-csrf (it's a browser redirect landing, not a form post) and must
// be mounted BEFORE the terminal provider catch-all.

import logger from '@overleaf/logger'
import Settings from '@overleaf/settings'

import S2sRouter from './s2s/S2sRouter.mjs'
import { mountBridge } from './oidc/bridge.mjs'
import { getOidcProvider } from './oidc/createProvider.mjs'
import CallbackRouter from './rp/CallbackRouter.mjs'
import { leafHandler } from './oidf/leaf.mjs'
import FederatedInviteRouter from './invite/FederatedInviteRouter.mjs'
import FederatedAdminRouter from './admin/AdminRouter.mjs'
import {
  ensureBootstrapped,
  retireExpiredKeys,
  listPublicKeys,
  leafJwksPayload,
} from './oidf/keystore.mjs'
import ProjectCreationGuard from './app/ProjectCreationGuard.mjs'

export default {
  nonCsrfRouter: {
    apply(webRouter) {
      // ① S2S (always mounted; peers get `federation-off` 200 when off).
      S2sRouter.apply(webRouter)

      if (!Settings.federation?.enabled) return

      // ② bridge (interaction, 05 §1.1: before the terminal OP catch-all).
      mountBridge(webRouter)

      // ③ A-side OIDC callback landing (browser redirect landing, non-
      //    csrf). Must precede the terminal OIDC mount (its catch-all
      //    404 would swallow `/federation/oidc/rp/callback`).
      CallbackRouter.apply(webRouter)

      // ④ terminal OP mount (lazy; oidc-provider v9.12.2 router is
      //    express-compatible).
      webRouter.use('/federation/oidc', async (req, res, next) => {
        try {
          const provider = await getOidcProvider()
          await provider.callback()(req, res, next)
        } catch (error) {
          logger.error({ error }, 'federation: op mount failed')
          next(error)
        }
      })

      logger.debug({}, 'federation: nonCsrfRouter mounted (s2s + bridge + callback + op)')
    },
  },

  router: {
    /**
     * @param {import('express').Router} webRouter
     * @param {import('express').Router} _privateApiRouter
     * @param {import('express').Router} _publicApiRouter
     */
    apply(webRouter, _privateApiRouter, _publicApiRouter) {
      if (!Settings.federation?.enabled) return

      // ④ A-side invite endpoints (preview + authorize, plan 07 §P1).
      FederatedInviteRouter.apply(webRouter)

      // ⑤ Admin routes (PEER pin/approve/deny/revoke, key rotate, audit).
      FederatedAdminRouter.apply(webRouter)

      // ⑥ Partner-side project-creation gate (01 §3.4, 05 §7
      //    allowFederatedProjectCreate, default OFF): mirrors only
      //    create when the partner admin enabled it. Mounted BEFORE
      //    core `POST /project/new` (Router.initialize registers it
      //    after this apply call). Idempotent (applyRouter runs x3).
      ProjectCreationGuard(webRouter)
    },
  },

  appMiddleware(app) {
    if (!Settings.federation?.enabled) return

    // The OIDF wire path is FIXED by the specification (not this repo's
    // kebab URL rule) — disabled for that literal only.
    // eslint-disable-next-line @overleaf/prefer-kebab-url
    app.get('/.well-known/openid-federation', (req, res, next) => {
      leafHandler(req, res, next)
    })

    // Public federation key listing (05 §1.1 discovery). The leaf EC
    // already publishes `jwks`, but this endpoint lets an admin's browser
    // fetch just the key set without parsing the signed EC.
    app.get('/federation/federation-keys', async (req, res, next) => {
      try {
        const jwks = await leafJwksPayload()
        const keys = await listPublicKeys()
        return res.json({ kid: keys.map((k) => k.kid), jwks })
      } catch (error) {
        logger.error({ error }, 'federation: federation-keys failed')
        next(error)
      }
    })
  },

  // ⑤ Boot-time: keystore bootstrap (04 §2) + grace sweep (07 §2, start()).
  async start() {
    if (!Settings.federation?.enabled) return

    try {
      await ensureBootstrapped()
      await retireExpiredKeys()
      logger.info({}, 'federation: keystore bootstrapped + sweep ran')
    } catch (error) {
      logger.error({ error }, 'federation: keystore bootstrap failed')
      throw error
    }
  },
}
