# Two-real-origins (A≠B) live smoke — content-bridge 2d (plan 09)

The closure check for content-bridge v2 (Goal step 4 of 4): the export
wizard → S2S `export-project` → minted PAT → live git-bridge REST checks
(read passes, **write gets 403** with the export PAT, 2c guard) → S2S
rate limit → S2S revoke → export sweep → dead PAT 401s, with A and B on
**two real origins** (two node processes on one shared real Mongo + one
real Redis).

## Files

- `live-two-origin.mjs` — the DRIVER (origin A = `alpha.example`, the RP).
  Owns the shared Mongo (drop + reseed) and Redis (`flushall`), bootstraps
  the keystore once, spawns the B child, rewrites `fetch(https://<origin>)`
  to the live local ports, mounts its own express (fake login = carol@alpha,
  S2S + callback routers + OIDC provider), and runs the 7 scenarios with a
  PASS/FAIL matrix + exit code.
- `live-smoke-b.mjs` — the B CHILD (origin B = `beta.example`, the home OP).
  Real express mount (S2S + bridge + callback + OP) + the git-bridge REST
  surface (`GitBridgeRouter`: read middleware + the 2c write 403 guard +
  `GET /oauth/token/info`). Fake login = the B-native owner. Prints
  `READY_B <port>` once listening; stays up until the driver SIGTERMs it.

Both are the v1 `tools/live-smoke.mjs` stub layer (documented in the v1
live-smoke header): real Mongo/Redis/express/oidc-provider v9/jose; fake
only per-process login sessions + the 4 app-subsystem seams
(CollaboratorsGetter ×2, CollaboratorsHandler.addUserIdToProject,
UserSessionsManager.trackSession).

## Run

Prereq: docker containers
- `mongodb://127.0.0.1:27107` (db `fedsmoke2`) — `fed-smoke-mongo`
- `redis://127.0.0.1:6380` — `fed-smoke-redis`

```
git clone/ensure containers up; then from services/web/:
timeout 240 node modules/federation/tools/two-origin/live-two-origin.mjs
```

Exit 0 = ALL PASS; non-zero prints the failing checks. Env defaults are
baked into the driver (both origins, both ports, session secret) — no
flags, no external config.

## Scenarios (7)

1. **v1 identity dance (cross-origin) → mirror + consent grant** — A's
   handleAuthorize (302 to B auth URL, alpha client, S256 PKCE) → the full
   OIDC dance at B's OP (login + consent, real oidc-provider v9) → A's
   callback (302 → `/project/<projA>`) with mirror row, grant applied,
   session tracked, `federation_session_issued` audit, and the live
   consent-grant account index (the 2a binding).
2. **export wizard (2b) → S2S export-project (2a) → PAT** — A-side
   `handleExport` (fake req/res) → B mints the `olp_…`
   `federation:git_bridge` PAT (sha256-only doc + `olp_` 8-char partial),
   ledger row `status:'exported'`, PAT rendered into the result view once
   (never persisted raw), `federation_export_requested` audit.
3. **live git-bridge REST (the 2d signature)** — export PAT:
   `GET /api/v0/docs/<id>` reaches the controller (400 = absent
   project-history sidecar; auth passed), `POST /api/v0/docs/<id>/snapshots`
   → **403** (the 2c guard refuses the `federation:`-scoped token before
   any oracle), `GET /oauth/token/info` → 200; a NORMAL `git_bridge` PAT
   passes the guard (500, same sidecar) → proving the guard is scope-keyed.
4. **S2S export-project rate limit** — 10 mints land (fresh PATs,
   idempotent ledger), the 11th → **429 + `Allow-Retry-After`**
   (`{ok:false, code:'rate-limited'}`).
5. **S2S revoke (A→B)** — B marks the alpha peer revoked; the 2c export
   sweep deletes the minted PAT (scope-guarded) + ledger `status:'revoked'`
   + redacted `federation_export_swept` audit.
6. **post-revoke dead PAT** — swept PAT → 401 on everything
   (token/info, read, write); wizard → 502
   (`peer-not-approved`); `federation_export_denied` audit.
7. **post-revoke S2S** — 401 `peer-not-approved` at the pre-lookup.

## Known simplifications (documented, same class as the v1 smoke)

- **Shared keystore**: the driver bootstraps the keystore once on the
  shared db, so both origins pin the SAME ES256 key (the v1 single-origin
  smoke has the same property). Real deployments pin distinct per-origin
  keys; the wire (sign/verify vs pinned anchor) is otherwise identical.
- **Fake logins**: carol@alpha on A, owner@beta on B (the SESSION 10
  fake-login pattern; the user rows are REAL in the shared Mongo).
- **One process per origin** (not two hosts): the origins differ by
  `Settings.siteUrl`/`Settings` per-process origin (the v1 "one OP per
  process" property — the module is a per-origin singleton).
