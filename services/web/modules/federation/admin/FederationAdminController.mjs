// Site-admin surface for federation (P1, plan 07 §P1; pin flow per
// plan 02 §3, pair-wise TOFU).
//
// Routes live under `/admin/federation` and ride the CSR webRouter
// (session + CSRF, plan 07: the admin is a human in a browser).
// Guard: `AuthorizationMiddleware.ensureUserIsSiteAdmin` (this fork's
// site-admin check; CE has no PermissionsService).
//
// Peer lifecycle (04 §5):
//   pin      POST /admin/federation/peers          { origin, direction?, displayName? }
//            TOFU (02 §3): fetch `https://<origin>/.well-known/openid-federation`,
//            decode + schema-validate the EC (NO signature check — the pin
//            IS the trust decision, 06 §2), select the active key,
//            compute its RFC 8037 thumbprint, and write a `pending` row.
//            A pin is a local decision over fetched data: no S2S, no
//            outbound network write.
//   approve  POST /admin/federation/peers/:origin/approve
//   deny     DELETE /admin/federation/peers/:origin
//   revoke   POST /admin/federation/peers/:origin/revoke
//            (03 §4.3: local immediate + best-effort outbound S2S
//            `revoke` — never blocks the admin on a network call)
//
// Keys (02 §5, plan 07 §P1):
//   GET  /admin/federation/keys                  metadata-only listing
//   POST /admin/federation/keys/rotate           { purpose }
//     'federation': generate ES256 → publishKey → switchActiveKey (old key
//       → retiring; the boot-time `retireExpiredKeys` sweep reclaims it
//       after keyRotationGraceDays).
//     'oidc':       501 stub — oidc-provider v9 does not hot-swap `jwks`;
//       OIDC-key rotation is a P2 follow-up (05 §8.6).
//
// Audit readout (04 §8):
//   GET /admin/federation/audit    most recent federation_* rows, capped.
//
// Error shape: `{ message, code? }` + status; `code` is the machine
// reason for the admin UI (mirrors S2S_ERRORS vocabulary where sensible).

import logger from '@overleaf/logger'
import Settings from '@overleaf/settings'

import {
  decodeEntityConfiguration,
  generateSigningKey,
  createFederationSigningKey,
  createTrustAnchorSet,
  discoverEntity,
  jwkThumbprint,
} from '@oidfed/core'
import { expressify } from '@overleaf/promise-utils'
import { FederationKey } from '../app/models/FederationKey.mjs'
import { FederationPeer } from '../app/models/FederationPeer.mjs'
import { FederationTrustAnchor } from '../app/models/FederationTrustAnchor.mjs'
import { _resetProviderMemo } from '../oidc/createProvider.mjs'
import { federationClientId } from '../oidc/clients.mjs'
import { revokeClientCodes } from '../oidc/RedisOidcProviderAdapter.mjs'
import { buildS2sRequest } from '../oidf/ClientAssertionClient.mjs'
import { createKeyProvider } from '../oidf/keystore.mjs'
import { audit, AUDIT_TYPES } from '../util/Audit.mjs'
import { ProjectAuditLogEntry } from '../../../app/src/models/ProjectAuditLogEntry.mjs'

export const DIRECTIONS = ['outbound', 'inbound', 'both']

// Outbound hardening (06 §7): pin-time leaf fetch + revoke S2S cap at
// one knob (federation.s2sFetchTimeoutMs, shipped 10 s); admin UIs
// never block longer than that.
const ADMIN_OUTBOUND_FETCH_TIMEOUT_MS =
  Settings.federation?.s2sFetchTimeoutMs ?? 10000

// Bare FQDN (the FederationPeer.origin + S2S wire `from` convention,
// 03 §2). Ports/schemes rejected at the source: the entity id is always
// `https://<host>` without a port (02 §5).
const BARE_FQDN_RE =
  /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/i

async function listPeers(req, res) {
  const peers = await FederationPeer.find({})
    .sort({ federatedAt: -1 })
    .select('-registration') // institutional-mode field (P3), not shown
    .lean()
  return res.json({
    peers: peers.map((peer) => ({
      origin: peer.origin,
      displayName: peer.displayName || null,
      entityId: peer.entityId || null,
      mode: peer.mode,
      direction: peer.direction,
      status: peer.status,
      kid: peer.kid || null,
      thumbprint: peer.thumbprint || null,
      federatedAt: peer.federatedAt,
      approvedAt: peer.approvedAt || null,
    })),
  })
}

/**
 * pin (02 §3 pair-wise TOFU). Fetches the peer's self-signed leaf EC,
 * validates its shape (NO signature check — the pin IS the trust
 * decision; verifying its own sig against its own jwks proves nothing
 * against a MITM on this fetch, 06 §2), selects the active key, and
 * writes the `pending` row with its RFC 8037 thumbprint.
 */
async function handlePin(req, res) {
  const { origin: rawOrigin, direction, displayName } = req.body ?? {}

  if (typeof rawOrigin !== 'string' || rawOrigin.trim().length === 0) {
    return res
      .status(400)
      .json({ message: 'origin required', code: 'missing-origin' })
  }
  const origin = rawOrigin.trim().toLowerCase()
  if (!BARE_FQDN_RE.test(origin)) {
    return res
      .status(400)
      .json({ message: 'origin must be a bare FQDN (no scheme, no port)', code: 'invalid-origin' })
  }
  if (
    displayName !== undefined &&
    (typeof displayName !== 'string' || displayName.length === 0)
  ) {
    return res
      .status(400)
      .json({ message: 'displayName must be a non-empty string', code: 'invalid-display-name' })
  }
  const dir = direction ?? 'both'
  if (!DIRECTIONS.includes(dir)) {
    return res
      .status(400)
      .json({ message: 'direction must be one of: outbound, inbound, both', code: 'invalid-direction' })
  }

  const existing = await FederationPeer.findOne({ origin }).lean()
  if (existing) {
    return res
      .status(409)
      .json({ message: `peer ${origin} already exists (${existing.status})`, code: 'peer-exists' })
  }

  // TOFU fetch (02 §3): HTTPS, constructed from the validated FQDN
  // (no user-controlled URL, 06 §2). `redirect: 'manual'` (FINDINGS
  // bug-hunt LOW): a 3xx hop means the returned EC is NOT anchored to
  // this host, so the pin would be to a different EC than the origin
  // names. We refuse rather than follow; peers are expected to serve
  // the leaf at the canonical origin (02 §5).
  const leafUrl = `https://${origin}/.well-known/openid-federation`
  let ec
  try {
    const resp = await fetch(leafUrl, {
      headers: { Accept: 'application/entity-statement+jwt' },
      signal: AbortSignal.timeout(ADMIN_OUTBOUND_FETCH_TIMEOUT_MS),
      redirect: 'manual',
    })
    const status = resp.status
    if (status >= 300 && status < 400) {
      logger.warn({ leafUrl, status }, 'federation: pin leaf fetch returned a redirect (refused)')
      return res
        .status(502)
        .json({
          message: `peer leaf returned an HTTP ${status} redirect; expected the entity configuration at the canonical origin`,
          code: 'peer-unreachable',
        })
    }
    if (!resp.ok) {
      logger.warn({ leafUrl, status: resp.status }, 'federation: pin leaf fetch not ok')
      return res
        .status(404)
        .json({ message: `peer leaf returned HTTP ${resp.status}`, code: 'peer-unknown' })
    }
    ec = (await resp.text()).trim()
  } catch (error) {
    logger.warn({ error, leafUrl }, 'federation: pin leaf fetch failed')
    return res
      .status(502)
      .json({ message: `peer fetch failed: ${error.message}`, code: 'peer-unreachable' })
  }

  // Decode + schema-validate (npm @oidfed/core v1.0.0 result shape is
  // `{ ok: true, value }` / `{ ok: false, error }`, NOT `isOk`/`err` —
  // verified against dist). `typ` header MUST be `entity-statement+jwt`.
  const decoded = decodeEntityConfiguration(ec)
  if (!decoded.ok) {
    const reason =
      (decoded.error &&
        (decoded.error.description || decoded.error.message)) ||
      'invalid entity configuration'
    logger.warn({ leafUrl, reason }, 'federation: pin EC invalid')
    return res
      .status(400)
      .json({ message: `peer entity configuration is invalid: ${reason}`, code: 'invalid-ec' })
  }
  const statement = decoded.value
  const payload = statement.payload
  const header = statement.header

  // iss/sub must name this origin (02 §5: entity id = `https://<FQDN>`,
  // port stripped).
  const expectedEntityId = `https://${origin}`
  if (payload.iss !== expectedEntityId || payload.sub !== expectedEntityId) {
    logger.warn(
      { leafUrl, iss: payload.iss, sub: payload.sub },
      'federation: pin EC iss/sub mismatch',
    )
    return res
      .status(400)
      .json({ message: `leaf entity configuration is not for ${origin}`, code: 'invalid-ec' })
  }

  // Institutional path (02 §3/§4, 07 §P3): if the leaf carries
  // `authority_hints`, resolve the OIDF chain up through the configured
  // institutional trust anchors at PIN TIME. Runtime S2S verification
  // stays depth-1 (the peer's own active key, selected below) — the
  // institutional walk is a trust decision over the fetched chain, and
  // the anchor we store is still the leaf's active self-key (02 §6: "the
  // leaf's authority_hints walk up through institutional TA/IA
  // statements — same resolve path"). Without institutional anchors we
  // cannot verify such a leaf, so the pin is refused.
  const authorityHints = Array.isArray(payload.authority_hints)
    ? payload.authority_hints
      .filter((h) => typeof h === 'string' && h.length > 0)
      : []
  let mode = 'pairwise'
  let registration
  if (authorityHints.length > 0) {
    const tAs = await FederationTrustAnchor.find({}).lean()
    if (tAs.length === 0) {
      logger.warn(
        { expectedEntityId },
        'federation: pin has authority_hints but no institutional trust anchors are configured',
      )
      return res.status(400).json({
        message:
          'peer is an institutional leaf (authority_hints present) but this instance has no institutional trust anchors configured',
        code: 'institutional-anchor-missing',
      })
    }
    let discovery
    try {
      const taSet = createTrustAnchorSet(tAs.map((ta) => ({
        entityId: ta.entityId,
        jwks: ta.jwks,
      })))
      discovery = await discoverEntity(expectedEntityId, taSet, {
        httpTimeoutMs: ADMIN_OUTBOUND_FETCH_TIMEOUT_MS,
        maxChainDepth: 10,
      })
    } catch (error) {
      logger.warn({ error, expectedEntityId }, 'federation: institutional chain discovery failed')
      return res
        .status(400)
        .json({ message: `institutional chain resolve failed: ${error.message}`, code: 'institutional-chain-failed' })
    }
    if (!discovery.ok) {
      logger.warn(
        { expectedEntityId, error: discovery.error },
        'federation: institutional chain did not resolve to a configured TA',
      )
      return res.status(400).json({
        message: `institutional chain did not resolve to a configured trust anchor: ${discovery.error?.description || discovery.error?.message || 'trust-chain-invalid'}`,
        code: 'institutional-chain-untrusted',
      })
    }
    // Resolved: the chain terminates at one of our configured TAs. The
    // registration subdoc is audit/replay (04 §2: "the anchor pin itself
    // is ground truth") — the anchor we verify against is still the
    // leaf's active self-key, selected just below.
    mode = 'institutional'
    registration = {
      clientId: `urn:overleaf-federation:client:${origin}`,
      expiresAt: discovery.value.trustChain.expiresAt,
      trustChainExpiresAt: discovery.value.trustChain.expiresAt,
    }
  }

  // Active key selection: prefer the EC header kid, fall back to the sole
  // key when there is exactly one.
  const keys = (payload.jwks?.keys ?? []).filter((k) => k && typeof k === 'object')
  const headerKid = typeof header?.kid === 'string' ? header.kid : undefined
  const candidate =
    (headerKid ? keys.find((k) => k?.kid === headerKid) : undefined) ??
    (keys.length === 1 ? keys[0] : undefined)
  if (
    !candidate ||
    candidate.kty !== 'EC' ||
    candidate.crv !== 'P-256' ||
    typeof candidate.kid !== 'string' ||
    candidate.kid.length === 0
  ) {
    logger.warn(
      { leafUrl, keyCount: keys.length },
      'federation: pin no usable P-256 key',
    )
    return res
      .status(400)
      .json({
        message: `leaf does not carry a P-256 ES256 signing key (${headerKid ? `kid ${headerKid} not found` : `no single key among ${keys.length} keys`})`,
        code: 'no-pinnable-key',
      })
  }

  const thumbprint = await jwkThumbprint(candidate)

  // B-side approval queue (04 §2.1, 05 §7 `requireAdminApproval`, default
  // ON v1): gates whether a received pin lands `pending` (admin must
  // click approve) or straight-to-`approved`. When the flag is OFF the
  // pin's TOFU admin action (fetch + click-verify the thumbprint) IS the
  // approval, so the row skips the queue. Grant minting is refused for a
  // non-approved peer REGARDLESS of this flag (S2sRouter ③ `peer-not-approved`
  // + `clients[]` reconstructed only from `approved`, 05 §8.8) — the flag
  // only controls the queue, never the refusal.
  const requireApproval = Settings.federation?.requireAdminApproval !== false
  const initialStatus = requireApproval ? 'pending' : 'approved'

  const peer = await FederationPeer.create({
    origin,
    displayName:
      typeof displayName === 'string' && displayName.length > 0 ? displayName : null,
    entityId: expectedEntityId,
    mode,
    ...(registration ? { registration } : {}),
    anchorJwks: JSON.stringify(candidate),
    kid: candidate.kid,
    thumbprint,
    direction: dir,
    status: initialStatus,
    ...(initialStatus === 'approved' ? { approvedAt: new Date() } : {}),
  })

  // Audit (04 §8): `federation_peer_registered` (per-direction pin) +
  // `federation_trust_anchor_pinned` (TOFU admin action). Both fire on
  // a successful pin.
  await audit({
    operation: AUDIT_TYPES.peerRegistered,
    projectId: null,
    meta: { origin, direction: dir },
    req,
  })
  await audit({
    operation: AUDIT_TYPES.trustAnchorPinned,
    projectId: null,
    // 04 §8: the anchor thumbprint is allow-listed meta (not the JWK).
    meta: { origin, direction: dir, anchorThumbprint: thumbprint },
    req,
  })

  if (initialStatus === 'approved') {
    // Immediate approval (flag OFF): mirror the approve endpoint's side
    // effects — clients[] snapshot rebuild (05 §8.3) + approval audit row.
    try {
      _resetProviderMemo()
    } catch (error) {
      logger.warn({ error }, 'federation: provider memo reset failed on immediate-approve')
    }
    await audit({ operation: AUDIT_TYPES.peerApproved, projectId: null, meta: { origin }, req })
  }

  logger.info(
    { origin, thumbprint, mode, initialStatus },
    `federation: admin pinned peer (${initialStatus})`,
  )
  return res.status(201).json({
    origin: peer.origin,
    status: peer.status,
    mode,
    kid: peer.kid,
    thumbprint: peer.thumbprint,
    ...(initialStatus === 'approved' ? { approvedAt: peer.approvedAt } : {}),
  })
}

async function handleApprove(req, res) {
  const { origin } = req.params
  // No `.lean()` here: we need a hydrated doc (`.save()`).
  const peer = await FederationPeer.findOne({ origin })
  if (!peer) {
    return res.status(404).json({ message: `peer ${origin} not found`, code: 'peer-unknown' })
  }
  if (peer.status !== 'pending') {
    return res
      .status(409)
      .json({ message: `peer ${origin} is ${peer.status}, not pending`, code: 'peer-not-pending' })
  }

  peer.status = 'approved'
  peer.approvedAt = new Date()
  await peer.save()

  // 05 §8.3: clients[] is a boot-time snapshot from approved peers. The
  // v1 rebuild path is lazy: invalidate the memoized provider so the
  // NEXT oidc-provider request re-constructs with this peer's client in
  // clients[].
  try {
    _resetProviderMemo()
  } catch (error) {
    logger.warn({ error }, 'federation: provider memo reset failed')
  }

  await audit({ operation: AUDIT_TYPES.peerApproved, projectId: null, meta: { origin }, req })

  return res.json({ origin: peer.origin, status: peer.status, approvedAt: peer.approvedAt })
}

// deny: delete the `pending` row (pair-wise has no other side effect:
// no trust anchor was established — the pin row was the only artifact).
async function handleDeny(req, res) {
  const { origin } = req.params
  const peer = await FederationPeer.findOne({ origin }).lean()
  if (!peer) {
    return res.status(404).json({ message: `peer ${origin} not found`, code: 'peer-unknown' })
  }
  if (peer.status !== 'pending') {
    return res
      .status(409)
      .json({ message: `peer ${origin} is ${peer.status}, not pending`, code: 'peer-not-pending' })
  }
  await FederationPeer.deleteOne({ origin })
  await audit({
    operation: AUDIT_TYPES.peerDenied,
    projectId: null,
    meta: { origin, direction: peer.direction },
    req,
  })
  return res.status(204).send('')
}

// Revoke (03 §4.3, 04 §5): local immediate; outbound S2S `revoke`
// BEST-EFFORT (admin actions never block on a network call). Idempotent
// (a second revoke of an already-`revoked` row returns 200 with the
// same `revocation` field, no double audit row).
async function handleRevoke(req, res) {
  const { origin } = req.params
  // No `.lean()` here: we need a hydrated doc (`.save()`).
  const peer = await FederationPeer.findOne({ origin })
  if (!peer) {
    return res.status(404).json({ message: `peer ${origin} not found`, code: 'peer-unknown' })
  }

  const already = peer.status === 'revoked'
  let peerNotified = already
  if (!already) {
    peer.status = 'revoked'
    await peer.save()

    // 03 §4.3: the outbound S2S `revoke` payload targets
    // `this-connection` (the sender's row). Never awaited for success.
    try {
      const { headers, body } = await buildS2sRequest(
        peer.origin,
        'revoke',
        { origin: 'this-connection' },
      )
      const resp = await fetch(`https://${peer.origin}/federation/s2s`, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(ADMIN_OUTBOUND_FETCH_TIMEOUT_MS),
        redirect: 'manual',
      })
      // 06 §8: a redirect response is not a successful notification.
      peerNotified = resp.ok
    } catch (error) {
      logger.warn({ error, origin: peer.origin }, 'federation: outbound revoke failed')
    }

    // 05 §8.3 / 04 §5: a revoked peer must stop minting grants.
    // Invalidate the memoized provider (clients[] snapshot) so the
    // transition takes effect without a restart.
    try {
      _resetProviderMemo()
    } catch (error) {
      logger.warn({ error, origin }, 'federation: provider memo reset failed after revoke')
    }

    // 04 §5 / 06 §179: `killOutstandingCodes` (peer toggle, default off)
    // — sweep this peer's outstanding auth/token docs. Best-effort (a
    // failure never blocks the local revocation; the memo reset above
    // already stops NEW minting, and single-use 120 s codes bound the
    // residual otherwise).
    if (peer.killOutstandingCodes === true) {
      try {
        await revokeClientCodes(federationClientId(peer.origin))
      } catch (error) {
        logger.warn({ error, origin: peer.origin }, 'federation: code sweep after revoke failed')
      }
    }

    await audit({
      operation: AUDIT_TYPES.peerRevoked,
      projectId: null,
      meta: { origin, direction: peer.direction },
      req,
    })
  }

  return res.json({
    origin: peer.origin,
    status: peer.status,
    revocation: peerNotified ? 'peer-notified' : 'local-only',
  })
}

// Key rotation (02 §5, plan 07 §P1). `federation`: generate ES256,
// publish, activate (old key → retiring; the boot-time `retireExpiredKeys`
// sweep reclaims after keyRotationGraceDays). `oidc`: 501 stub (v9 does
// not hot-swap jwks; 05 §8.6).
async function handleRotate(req, res) {
  const { purpose } = req.body ?? {}
  if (purpose === 'oidc') {
    return res
      .status(501)
      .json({
        message:
          'oidc key rotation is not supported in v1 (oidc-provider does not hot-swap jwks)',
        code: 'not-supported',
      })
  }
  if (purpose !== 'federation') {
    return res
      .status(400)
      .json({ message: 'purpose must be "federation" ("oidc" is a 501 stub)', code: 'invalid-purpose' })
  }

  const generated = await generateSigningKey('ES256')
  const signingKey = createFederationSigningKey(generated.privateKey)
  const provider = createKeyProvider()

  // publish: persist as `published`, served immediately (leaf jwks +
  // historical endpoint), not yet signing.
  await provider.publishKey({
    signer: signingKey.signer,
    publicJwk: signingKey.publicJwk,
    privateKey: generated.privateKey,
  })
  const newKid =
    signingKey.publicJwk?.kid || generated.publicKey?.kid

  // activate: old active key → retiring (grace window), new key signs.
  await provider.switchActiveKey(newKid)

  await audit({
    operation: AUDIT_TYPES.keyRotated,
    projectId: null,
    meta: { kid: newKid, reason: 'admin-rotate' },
    req,
  })
  logger.info({ kid: newKid }, 'federation: admin rotated federation key')
  return res.json({ purpose, kid: newKid, state: 'active' })
}

// Metadata-only listing (02 §5: "public halves only — no private
// material"; kid/algorithm/state/expiry only, no JWK bodies).
async function handleListKeys(req, res) {
  const keys = await FederationKey.find({})
    .sort({ purpose: 1, publishedAt: 1 })
    .select('purpose kid state algorithm publishedAt stateChangedAt expiresAt')
    .lean()
  return res.json({
    keys: keys.map((k) => ({
      purpose: k.purpose,
      kid: k.kid,
      state: k.state,
      algorithm: k.algorithm,
      publishedAt: k.publishedAt,
      stateChangedAt: k.stateChangedAt,
      expiresAt: k.expiresAt,
    })),
  })
}

// Audit readout (04 §8): the `federated_*` / `federation_*` rows,
// newest first, capped (the query is index-friendly: operation is a
// prefix match on a small field).
async function handleAuditList(req, res) {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200)
  const rows = await ProjectAuditLogEntry.find({
    operation: { $regex: '^(federated_|federation_)' },
  })
    .sort({ timestamp: -1 })
    .limit(limit)
    .lean()
  return res.json({
    entries: rows.map((row) => ({
      id: row._id,
      projectId: row.projectId || null,
      operation: row.operation,
      initiatorId: row.initiatorId || null,
      ipAddress: row.ipAddress || null,
      timestamp: row.timestamp,
      info: row.info ?? {},
    })),
  })
}

// Institutional trust anchor management (02 §3, 07 §P3). The TA row is
// the "known-good institutional root": TOFU — the admin pastes the TA's
// entity id + published JWK set after comparing against the institution's
// independent publication (thumbprint shown in the listing; 02 §5
// "public halves only"). Pinned TAs feed `handlePin`'s institutional
// chain resolve and `createTrustAnchorSetForInstance` (04 §2 additive).
async function listTrustAnchors(req, res) {
  const tAs = await FederationTrustAnchor.find({}).sort({ pinnedAt: 1 }).lean()
  const entries = []
  for (const ta of tAs) {
    const keys = Array.isArray(ta.jwks?.keys) ? ta.jwks.keys : []
    const thumbprints = []
    for (const key of keys) {
      try {
        thumbprints.push(await jwkThumbprint(key))
      } catch {
        thumbprints.push(null)
      }
    }
    entries.push({
      entityId: ta.entityId,
      displayName: ta.displayName || null,
      keyKids: keys.map((k) => k?.kid).filter(Boolean),
      thumbprints,
      pinnedAt: ta.pinnedAt,
    })
  }
  return res.json({ trustAnchors: entries })
}

// Pin one institutional TA: validate the entity id (must be an https:
// OIDF entity id), require a JWK set with only public keys, store the
// row + audit (federation_trust_anchor_pinned, 04 §8).
async function handlePinTrustAnchor(req, res) {
  const { entityId, displayName, jwks } = req.body ?? {}
  if (typeof entityId !== 'string' || entityId.trim().length === 0) {
    return res
      .status(400)
      .json({ message: 'entityId required', code: 'missing-entity-id' })
  }
  const trimmed = entityId.trim()
  let parsed
  try {
    parsed = new URL(trimmed)
  } catch {
    return res
      .status(400)
      .json({ message: 'entityId must be an OIDF entity id (https://<FQDN>)', code: 'invalid-entity-id' })
  }
  if (parsed.protocol !== 'https:') {
    return res
      .status(400)
      .json({ message: 'entityId must use https:', code: 'invalid-entity-id' })
  }
  if (
    !jwks ||
    typeof jwks !== 'object' ||
    !Array.isArray(jwks.keys) ||
    jwks.keys.length === 0
  ) {
    return res
      .status(400)
      .json({ message: 'jwks must be a JWK set with a non-empty keys array', code: 'missing-jwks' })
  }
  for (const key of jwks.keys) {
    if (!key || typeof key !== 'object') continue
    if (key.d !== undefined) {
      return res
        .status(400)
        .json({ message: 'private key material (d) is not accepted', code: 'private-key-rejected' })
    }
  }
  const existing = await FederationTrustAnchor.findOne({ entityId: trimmed }).lean()
  if (existing) {
    return res
      .status(409)
      .json({ message: `trust anchor ${trimmed} already exists`, code: 'anchor-exists' })
  }
  await FederationTrustAnchor.create({
    entityId: trimmed,
    displayName:
      typeof displayName === 'string' && displayName.length > 0 ? displayName : null,
    jwks,
  })
  await audit({
    operation: AUDIT_TYPES.trustAnchorPinned,
    projectId: null,
    meta: { origin: trimmed, direction: 'institutional' },
    req,
  })
  logger.info({ entityId: trimmed }, 'federation: admin pinned institutional trust anchor')
  return res.status(201).json({ entityId: trimmed, status: 'pinned' })
}

// Delete one institutional TA. Approved peers that were resolved
// against it are NOT auto-revoked (04 §5: revocation is an explicit
// per-peer admin act).
async function handleDeleteTrustAnchor(req, res) {
  const { entityId } = req.params
  const ta = await FederationTrustAnchor.findOne({ entityId }).lean()
  if (!ta) {
    return res
      .status(404)
      .json({ message: `trust anchor ${entityId} not found`, code: 'anchor-unknown' })
  }
  await FederationTrustAnchor.deleteOne({ entityId })
  await audit({
    operation: AUDIT_TYPES.trustRevoked,
    projectId: null,
    meta: { origin: entityId, direction: 'institutional' },
    req,
  })
  logger.info({ entityId }, 'federation: admin deleted institutional trust anchor')
  return res.status(204).send('')
}

export const FederatedAdminController = {
  listPeers: expressify(listPeers),
  handlePin: expressify(handlePin),
  handleApprove: expressify(handleApprove),
  handleDeny: expressify(handleDeny),
  handleRevoke: expressify(handleRevoke),
  handleRotate: expressify(handleRotate),
  listKeys: expressify(handleListKeys),
  auditList: expressify(handleAuditList),
  listTrustAnchors: expressify(listTrustAnchors),
  handlePinTrustAnchor: expressify(handlePinTrustAnchor),
  handleDeleteTrustAnchor: expressify(handleDeleteTrustAnchor),
}

export default FederatedAdminController
