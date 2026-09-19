# app/views/ — module views

- `consent.pug` — B-side OIDC consent page rendered by `oidc/bridge.mjs` when
  the `openid-claims` interaction needs the user's consent (federated mirror
  sessions are auto-approved in `bridge.mjs` and never render this page).
  Server-renders the claim allow-list and the requesting origin.
