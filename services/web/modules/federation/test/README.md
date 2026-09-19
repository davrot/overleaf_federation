# test/ — module tests

Vitest, driven by `vitest.config.js` scope (pattern `modules/*/test/**/*.test.mjs`).
Run:

```bash
cd services/web
../../node_modules/.bin/vitest run -c vitest.config.js 'federation'
```

| File | What |
|---|---|
| `unit/oidf/keystore.test.mjs` | Key bootstrap, rotation grace, retirement, active-key selection (12 cases) |
| `unit/rp/State.test.mjs` | PKCE state mint/verify/tamper/consume (10 cases) |
| `unit/rp/CodeExchange.test.mjs` | Code-exchange fetch + timeout + error shape (7 cases) |
| `unit/admin/FederationAdminController.test.mjs` | Pin (pairwise TOFU + institutional guard + institutional happy path), approve, deny, revoke, key-rotate, TA pin/delete, audit list (21 cases) |
| `unit/invite/FederatedInviteController.test.mjs` | Preview, authorize, grant (12 cases) |
| `unit/s2s/S2sRouter.test.mjs` | Inbound S2sRouter ordering off→envelope→peer→verify→rate-limit→dispatch→audit→respond (14 cases) |

### Conventions for authoring tests here
- Tests are in `test/unit/<area>/...`; they import via relative paths
  (`../../../...` up from the file).
- `vi.mock` is the primary isolation tool — no DB, no Redis, no network:
  - Models: `vi.mock('../../../app/models/FederationPeer.mjs', ...)` (return
    thenable + `.lean()` chainable for both `await` and `.lean()` uses).
  - `@oidfed/core`: `vi.importActual('@oidfed/core')` to spread the *real*
    signer/keygen primitives, override only the function under test
    (`discoverEntity`, `verifyClientAssertion`).
  - Outbound `fetch` (for leaf-EC / well-known pulls) is stubbed as
    `globalThis.fetch`.
- **Do NOT** `vi.mock` `oidf/keystore.mjs` in S2S tests unless the router
  needs it — the router path does not re-import keystore; the keystore import
  is what forces Mongoose.connect at module load, so it is mocked in
  `S2sRouter.test.mjs`.
