# util/ — shared helpers

| File | Role |
|---|---|
| `Anchor.mjs` | Identity-anchor helpers (plan 01 §3.1). `parseAnchor` (display string → `{localName, origin}`, split on last colon), `formatAnchor`, `validateAnchor`, `hashInviteeEmail`, `saltedLocalNameHash` (Redis cache key — never store raw localName in keys), `resolveAnchorUser`. |
| `Redact.mjs` | PII/JWK redaction for logs + audit. `CLAIM_LOG_ALLOWLIST` (wire claims that may be logged), `redact`, `publicJwks` (public halves only), `assertionMeta`. |
| `Audit.mjs` | `audit({ operation, projectId, meta, req })` — writes to `ProjectAuditLogEntry` with the module's `federation_*`/`federated_*` operations. `AUDIT_TYPES` is the closed set; all meta is redacted through `Redact.mjs`. |
| `RateLimitStore.mjs` | Redis-backed budgets (plan 03 §5). `checkRateLimit` (per `from`, S2S 30/120s), plus the 60s invite-preview cache (`getCachedInvite`/`setCachedInvite`) keyed by (peer origin, salted localName). `RATE_LIMITS` is the tunable map; `_setRateLimitRedisClientForTest` injects in tests. |

### Notes
- These are the only cross-cutting files; no DB connection here beyond
  `RateLimitStore` (Redis) and `Audit` (Mongoose through the logged
  `ProjectAuditLogEntry` write).
- Redis key prefixes: `federation:ratelimit:*`, `federation:invite-cache:*`,
  `federation:replay:*` (in `oidf/verify.mjs`).
