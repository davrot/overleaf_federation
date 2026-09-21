# Frontend invite preview — seam for the host app's collaborators UI
## (v2 follow-on, TODO-45cb2ea7)

The federation module is router-only (no webpack entry; its one
server-rendered view is `app/views/federation.pug`). The invite preview
hook and the "invite a federated user" collaborator form therefore belong to
the host `app/src/Features/Collaborators` frontend, **not** to this module.
This file is the seam.

The admin-UI half of TODO-45cb2ea7 is **done** (step 7, `0fa0f9f3`):
`GET /admin/federation` renders a pug dashboard with peer / key / anchor /
audit panels + a 5-step readiness wizard (see `admin/README.md` §Admin
dashboard, ADMIN-GUIDE.md §1.5).

---

## What the backend already provides (no new work required)

| Endpoint | Method | Caller contract |
|---|---|---|
| `/api/federation/invite/preview` | `GET` | `?anchor=<localName>:<origin>` (3-part anchor, 04 §3.3). Always 200: `{ approved: true, displayName: '<name on B>' }`, `{ approved: false, displayName: null }` (a valid not-found preview — HANDOFF decision 5), or `{ approved: false, displayName: null, degraded: true }` (the S2S `invited` probe itself failed; 05 §4.1 — degrade, don't block). 60 s caller-side Redis cache (`invite:preview:*`, 04 §6). |
| `/api/federation/invite/authorize` | `POST` | Body `{ projectId, anchor, privileges }` (privileges: `readOnly` \| `readAndWrite` \| `review`). Success: **302 redirect** to B's OIDC authorization endpoint (PKCE + signed `state` + `nonce` + S256 challenge — 05 §3.1). CSRF: standard session cookie + `_csrf`; form must be same-origin. |

The anchor is the **exact** `localName:origin` string the user typed (03 §3,
"anchors: literal strings, no case/percent folding"). The backend `parseAnchor`
rejects anything else with 400 — don't re-derive, don't case-fold, don't strip.

## What the host-app hook must do

1. **Debounce** preview fetches ≥ 500 ms (the backend also caches 60 s, so
   one S2S round-trip per 60 s window maximum).
2. Render one row for the fuzzy match:
   - `approved: true` → show `displayName` + origin badge.
   - `approved: false, !degraded` → show the anchor verbatim with a "may not
     exist" hint; **the send is still offered**.
   - `degraded: true` → same, plus "confirmation pending".
3. `authorize` must be a **`<form method='POST'>`** to
   `/api/federation/invite/authorize` (form-encoded body with `_csrf`), **not**
   a `fetch` — the success path is a cross-origin 302 to B's authorization
   endpoint; a `fetch` can't follow it (opaque redirect, no cookies).
4. After B's flow completes, the user lands back on A's `/federation/oidc/rp/callback`,
   `rp/CallbackRouter` validates the code + PKCE, upserts
   `User { federation: { origin, localName, homeDisplayName } }`, and
   `res.redirect(url)`s to `/project/<projectId>` (01 §5, 04 §3.2). No extra
   frontend UI is required on A past the standard "project added" affordance
   — the federated grant path and the mirror-grant path converge on the same
   `ProjectMembership` row.

## Failure shapes the hook must understand

From `FederatedInviteController.mjs` (read this before writing UI):

- `400 { message }` — missing/invalid `projectId`/`anchor`/`privileges`.
- `403 { message: 'viewer does not have collaborator permission' }` —
  the caller is not a collaborator of `projectId` (03 §4.1 step 1a, local
  check, no S2S).
- `403 { message: 'invitee refused or not found on home instance', code }` —
  B-side business refusal, `code` ∈ `invitee-unknown` | `invitee-disabled` |
  `peer-not-found` (whichever S2S `authorize-invite` returned).
- `502 { message: 'peer refused or unreachable' }` — S2S wire failure:
  assertion-level 401 from B, envelope 429, network error, or the wire is
  refused by peer. **Not** a refusal — surface "could not reach the peer"
  and let the user retry.
- Peer-gate shape — `gateAnchor` (shared by both endpoints) returns:
  - `400` — invalid anchor string (`parseAnchor` rejected it);
  - `404 { message: 'peer not approved for this origin' }` — no approved peer
    row for that origin;
  - `403 { message: 'peer <origin> is not approved for outbound invites' }`
    — direction is `inbound` (we don't initiate toward inbound-only peers).

Preview-only degraded shape (HTTP 200, not an error): `{ approved: false,
displayName: null, degraded: true }` — the 60 s cache and the S2S `invited`
probe are best-effort; a degraded preview never blocks the send (05 §4.1:
"preview failure is NOT a refusal"; "the invite is savable without it").

## What this is *not* (scope lock)

Not a new module, not a new webpack entry, not a new view. The host-app
change is: `app/src/Features/Collaborators` adds a "federate this anchor"
affordance that calls the two endpoints above. The `overleaf-cep`
integration (04 §3.8, the collaboration API re-exposing the same two
endpoints) is explicitly out of v1 scope (00 §9).
