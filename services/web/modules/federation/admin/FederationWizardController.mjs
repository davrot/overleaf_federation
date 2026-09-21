// Federation admin dashboard + readiness wizard (0fa0f9f3, plan 07 §P3).
//
// View layer only: this controller adds
//   (a) GET /admin/federation           — the dashboard page (pug)
//   (b) GET /admin/federation/wizard    — readiness probe (JSON), powers
//                                          the step-by-step configuration
//                                          wizard rendered by the page
// It does NOT re-expose or modify any existing admin REST endpoint
// (peer pin/approve/deny/revoke, keys, trust anchors, audit) — the
// dashboard's fetch panels on the page drive the existing routes under
// `/admin/federation/*` (FederationAdminController, 11 routes).
//
// Wizard steps (what a first-time admin does, plan 07):
//   1. module-enabled        Settings.federation.enabled (master on/off)
//   2. identity-key          the module has an active federation key
//                            (bootstrapped at first `start()`, plan 07 §2)
//   3. first-peer-approved   at least one approved peer (TOFU pin, 02 §3)
//   4. leaf-published        this instance serves its own OIDF leaf
//                            (`/.well-known/openid-federation`, loopback
//                            probe — the leaf middleware mount, 05 §1.1)
//   5. s2s-proven            a recent federation audit row exists (pin/
//                            approve or an S2S receipt, 04 §8)
//
// All five probes are READ-ONLY and cheap; they run in parallel
// (Promise.all) and never mutate state. Step 4's probe is a bounded
// loopback fetch of this instance's own leaf (5 s, `redirect: 'manual'`,
// 06 §7) — never of a peer.

import Path from 'node:path'
import { fileURLToPath } from 'node:url'

import logger from '@overleaf/logger'
import Settings from '@overleaf/settings'

import { FederationPeer } from '../app/models/FederationPeer.mjs'
import { FederationKey } from '../app/models/FederationKey.mjs'
import { ProjectAuditLogEntry } from '../../../app/src/models/ProjectAuditLogEntry.mjs'

const __dirname = Path.dirname(fileURLToPath(import.meta.url))

// Bounded loopback probe (06 §7: no unbounded fetches in admin paths).
const LEAF_LOOPBACK_TIMEOUT_MS = 5000

// "Recent" for step 5 (04 §8 audit rows are the proof-of-life signal).
const S2S_RECENT_WINDOW_MS = 3600 * 1000

// Step 4: is this instance serving its own signed OIDF leaf?
async function probeOwnLeaf() {
  try {
    const leafUrl = `${Settings.siteUrl}/.well-known/openid-federation`
    const resp = await fetch(leafUrl, {
      headers: { Accept: 'application/entity-statement+jwt' },
      signal: AbortSignal.timeout(LEAF_LOOPBACK_TIMEOUT_MS),
      redirect: 'manual',
    })
    if (resp.status !== 200) {
      return {
        done: false,
        detail: `self leaf endpoint HTTP ${resp.status} (expected 200 signed EC)`,
      }
    }
    const body = (await resp.text()).trim()
    const parts = body.split('.')
    const isJwt = parts.length === 3 && parts.every((p) => p.length > 0)
    return isJwt
      ? { done: true, detail: 'self leaf served (HTTP 200, three-part signed EC)' }
      : { done: false, detail: 'self leaf responded but is not a three-part EC' }
  } catch (error) {
    logger.warn({ error }, 'federation: wizard leaf probe failed')
    return {
      done: false,
      detail: `self leaf probe failed: ${error.message} — is federation.enabled on and the leaf middleware mounted?`,
    }
  }
}

export const getFederationWizardStatus = async () => {
  const federationSettings = Settings.federation ?? {}
  const [federationKeys, approvedPeers, recentAuditRows] = await Promise.all([
    // `purpose: 'federation'` + `state: 'active'` — the model field is
    // `state`, not `status` (02 §5 keystore states; the leaf signs with
    // this key).
    FederationKey.find({ purpose: 'federation', state: 'active' })
      .sort({ publishedAt: -1 })
      .limit(1)
      .lean(),
    // Approved peer (04 §5 status vocabulary, `status` is right here).
    FederationPeer.find({ status: 'approved' })
      .sort({ approvedAt: -1 })
      .limit(1)
      .lean(),
    // 04 §8: `federated_*` / `federation_*` operation rows.
    ProjectAuditLogEntry.find({
      operation: { $regex: '^(federation_|federated_)' },
    })
      .sort({ timestamp: -1 })
      .limit(1)
      .lean(),
  ])

  const leaf = await probeOwnLeaf()

  const steps = [
    {
      name: 'module-enabled',
      label: 'Federation module enabled',
      done: federationSettings.enabled === true,
      detail:
        federationSettings.enabled === true
          ? '`federation.enabled` is `true`'
          : 'set `federation.enabled: true` in `config/settings.local.js` and restart `web` — this gates every other step',
    },
    {
      name: 'identity-key',
      label: 'Federation signing key active',
      done: federationKeys.length > 0,
      detail:
        federationKeys.length > 0
          ? `active federation key ${federationKeys[0].kid} (02 §5)`
          : 'no active federation key — the keystore bootstraps one at first `start()` (plan 07 §2); rotate one via the Keys panel',
    },
    {
      name: 'first-peer-approved',
      label: 'First peer approved',
      done: approvedPeers.length > 0,
      detail:
        approvedPeers.length > 0
          ? `${approvedPeers[0].origin} approved (02 §3 TOFU pin)`
          : 'pin a peer (Peers panel) and approve it — pairwise TOFU (02 §3)',
    },
    {
      name: 'leaf-published',
      label: 'OIDF leaf published (this instance)',
      done: leaf.done,
      detail: leaf.detail,
    },
    {
      name: 's2s-proven',
      label: 'S2S dance proven (recent federation audit)',
      done:
        recentAuditRows.length > 0 &&
        Date.now() -
          (recentAuditRows[0]?.timestamp
            ? new Date(recentAuditRows[0].timestamp).getTime()
            : 0) <
          S2S_RECENT_WINDOW_MS,
      detail:
        recentAuditRows.length > 0
          ? `last federation audit row: ${recentAuditRows[0].operation}`
          : 'no recent federation activity — pin/approve a peer or send a test invite',
    },
  ]

  return {
    ok: steps.every((s) => s.done),
    steps,
    settings: {
      enabled: federationSettings.enabled === true,
      requireAdminApproval:
        federationSettings.requireAdminApproval !== false,
      allowFederatedProjectCreate:
        federationSettings.allowFederatedProjectCreate === true,
      keyRotationGraceDays: federationSettings.keyRotationGraceDays ?? 14,
      s2sFetchTimeoutMs:
        federationSettings.s2sFetchTimeoutMs ?? 10_000,
    },
  }
}


export default {
  // GET /admin/federation — the dashboard page.
  federationAdminPage(req, res) {
    res.render(Path.resolve(__dirname, '../app/views/federation'), {
      title: 'Federation',
      siteName: Settings.siteName,
      csrfToken: res.locals?.csrfToken,
      settings: {
        enabled: Settings.federation?.enabled === true,
        requireAdminApproval:
          Settings.federation?.requireAdminApproval !== false,
        allowFederatedProjectCreate:
          Settings.federation?.allowFederatedProjectCreate === true,
        keyRotationGraceDays: Settings.federation?.keyRotationGraceDays ?? 14,
      s2sFetchTimeoutMs:
        Settings.federation?.s2sFetchTimeoutMs ?? 10_000,
      },
    })
  },

  // GET /admin/federation/wizard — readiness probe (JSON).
  federationWizard: (req, res, next) =>
    getFederationWizardStatus()
      .then(status => res.json(status))
      .catch(next),

}
