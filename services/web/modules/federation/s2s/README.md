# s2s/ — inbound S2S endpoint

`POST /federation/s2s`: the peer-to-peer OIDF **client-assertion** transport.
One endpoint, dispatched by `payload` action. (Outbound construction lives in
`oidf/ClientAssertionClient.mjs`.)

### Envelope (plan 03)
```http
POST /federation/s2s
client_assertion: <JWT>                     # OIDF client assertion (aud=<our origin>)
{ "action": "invited" | "authorize-invite" | "revoke",
  "from": "<peer origin>", "to": "<our origin>", "ts": <unix>, "payload": {...} }
```

### Ordering — `S2sRouter._handleS2sRequest(req, res)`
1. **federation off** → 403 (`federation-off`)
2. **envelope shape** → 400 (`bad-envelope`)
3. **peer lookup** (approved) → 401 (`peer-unknown` / `peer-not-approved`)
4. **client-assertion verify** (depth-1, replay-guarded) → 401 (machine codes in
   `oidf/verify.mjs` `S2S_ERRORS`)
5. **rate limit** (Redis `federation:ratelimit:*`, per `from`) → 429
6. **dispatch** action → `{ ok, payload?, code? }`
7. **audit** (redacted)
8. **respond**

### Actions (`actions/`)
Each `default` exports a handler `(ctx) => Promise<{ ok, payload?, code? }>`:
- `invited` — invited-side: cache/preview an invite for `localName@origin`.
- `authorize-invite` — approve (peer-side): provision mirror, grant on the
  project, return the `rpRedirectUrl` A needs to finish the login.
- `revoke` — trust revoked (inbound).

### Testing
`test/unit/s2s/S2sRouter.test.mjs` (14 cases, fake req/res + real
`S2sRouter._handleS2sRequest`, `vi.mock` on the leaf/client-assertion modules so
no DB/network is touched).
