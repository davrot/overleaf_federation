# invite/ — federated invite (owner / project side)

Where a project owner on this instance (acting as **RP/partner**, "A") invites a
user whose home is a peer (B, "home/OP").

> Flow authority: plan 01 §5. This surface is the *owner-side* initiation.

### Files
| File | Role |
|---|---|
| `FederatedInviteRouter.mjs` | Owner-facing routes: preview + authorize (login-guarded). |
| `FederatedInviteController.mjs` | `FEDERATED_PRIVILEGES`, `callPeer(peerOrigin, action, payload)` (outbound S2S, 10s cap), `_handlePreview`, `_handleAuthorize`. |

### Invite flow (01 §5)
```
owner on A opens project, invites <localName>:<origin=B>
  1) A: local collaborator check (owner/collaborator allowed, 403 otherwise)
  2) A→B S2S `invited` (soft preview, cached 60s) — "does that login live on B?"
  3) A: S2S `authorize-invite` to B (home oracle) — B returns claim allow-list
       { approved, displayName, institution }; business refusal is a 200 envelope
       with code `invitee-unknown` / `invitee-disabled`, NOT a 401
  4) A: upsert ProjectInvite.federated + mint signed PKCE state
  5) A: 302 the owner's/invitee's browser to B's OIDC authorization endpoint
       (public client + PKCE)
  6) B: authenticate the home user, consent, issue code → 302 to A callback
  7) A: rp/CallbackRouter → rp/CodeExchange → mirror provision + grant + login
```

### Notes
- Anchor serialization is `localName:origin` (split on the **last** colon) per
  plan 01 §3.1. `util/Anchor.mjs` provides `parseAnchor` / `validateAnchor`.
- Mirror grant path: `CollaboratorsHandler.promises.addUserIdToProject`
  (with `addingUserId = null`; this fork has no `PermissionsService`).
- Mirror login path: `UserSessionsManager.trackSession` (light user; mirrors
  never run through the password/passport path because `hashPassword` is
  `undefined` and mirror rows carry `email: ''`).
- Audit: owner action `federated_invite_authorized`.
