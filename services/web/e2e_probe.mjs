// e2e_probe.mjs — full B-side OIDC OP E2E: login→consent→code→token→id_token claims.
// Mirrors createProvider.mjs + bridge.mjs + RedisOidcProviderAdapter.mjs.
import crypto from 'node:crypto'
import express from 'express'
import { Provider } from 'oidc-provider'
import createAdapter from './modules/federation/oidc/RedisOidcProviderAdapter.mjs'

// ===== fake ioredis =====
const store = new Map()
const storeSets = new Map()
const fakeRedis = {
  async set(k, v) { store.set(k, v); return 'OK' },
  async get(k) { return store.has(k) ? store.get(k) : null },
  async del(...ks) {
    let n = 0
    for (const k of ks) {
      if (store.delete(k)) n++
      if (storeSets.delete(k)) n++
    }
    return n
  },
  async pttl(k) { return store.has(k) ? -1 : -2 },
  async sadd(k, ...members) {
    const s = storeSets.get(k) || new Set()
    storeSets.set(k, s)
    let n = 0
    for (const m of members) if (!s.has(m)) { s.add(m); n++ }
    return n
  },
  async smembers(k) { return storeSets.get(k) ? [...storeSets.get(k)] : [] },
  async srem(k, ...members) {
    const s = storeSets.get(k)
    if (!s) return 0
    let n = 0
    for (const m of members) if (s.delete(m)) n++
    return n
  },
  async scard(k) { return storeSets.get(k) ? storeSets.get(k).size : 0 },
}

const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
const pkJwk = { ...privateKey.export({ format: 'jwk' }), kid: 'probe-oidc', alg: 'ES256', use: 'sig' }
// jose v6: oidc-provider's keystore passes the plain private JWK straight into
// CompactSign.sign(key). The v4-era keyObject() wrapper is unnecessary and
// breaks v9's structuredClone (functions are not clonable) -- plain JWK only.
const pk = pkJwk

const provider = new Provider('http://127.0.0.1:43212/federation/oidc', {
  adapter: createAdapter(fakeRedis),
  jwks: {
    keys: [pk],
  },
  findAccount: async (ctx, sub) => sub ? {
    accountId: sub,
    claims: async () => ({
      origin: 'b.example.com',
      localName: `invitee-${sub}@b.example.com`,
      displayName: `User ${sub}`,
      institution: 'B-Inst',
    }),
  } : null,
  clients: [{
    client_id: 'urn:overleaf-federation:client:overleaf.example.com',
    redirect_uri: 'https://r.example/fed/callback',
    redirect_uris: ['https://r.example/fed/callback'],
    application_type: 'web',
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    scope: 'openid',
    id_token_signed_response_alg: 'ES256',
  }],
  subjectTypes: ['public'],
  scopes: ['openid'],
  claims: { openid: ['sub', 'origin', 'localName', 'displayName', 'institution'] },
  interactions: { url: (ctx, interaction) => `/interact/${interaction.uid}` },
  ttl: { AuthorizationCode: 120, Grant: 30 * 86400, Interaction: 600, Session: 8 * 3600 },
  features: { devInteractions: { enabled: false } },
  clockTolerance: 10,
  render: (ctx, msg) => { ctx.body = `RENDER_ERR: ${msg}` + (ctx.message ? ` | ${ctx.message}` : '') },
  renderError: (ctx, msg) => {
    const o = ctx.oidc
    ctx.body = `RENDER_ERROR: name=${o?.err?.name} errMsg=${o?.err?.message} msg=${msg} hint=${msg?.hint} error=${o?.error?.error} desc=${o?.error?.error_description} status=${o?.status}`
    ctx.status = o?.err?.status || 500
  },
  errors: { custom: {} },
})

// bridge: mirrors bridge.mjs `handleInteractGet`
provider.on('server_error', (ctx, err) => {
  console.log(`SERVER_ERROR_EVENT: ${err && err.stack ? err.stack.split('\n').slice(0, 4).join(' | ') : err}`)
  console.log(`  oidc err: ${ctx?.oidc?.err?.message || ctx?.oidc?.err?.error || 'n/a'} (hint: ${ctx?.oidc?.err?.hint || 'n/a'})`)
})
provider.on('authorization.error', (ctx, err) => {
  console.log(`AUTH_ERROR_EVENT:`, err && err.stack ? err.message : err)
})
const app = express()
app.get('/interact/:uid', async (req, res, next) => {
  try {
    const interaction = await provider.interactionDetails(req, res)
    const prompt = interaction.prompt.name
    const lastSub = interaction.lastSubmission || {}
    if (prompt === 'login') {
      return provider.interactionFinished(req, res, {
        ...lastSub,
        login: { accountId: 'user-1', ts: Math.floor(Date.now() / 1000) },
      }, { mergeWithLastSubmission: true })
    }
    if (prompt === 'consent') {
      const grant = new provider.Grant({ accountId: 'user-1', clientId: interaction.params.client_id })
      grant.addOIDCScope('openid')
      const grantId = await grant.save()
      return provider.interactionFinished(req, res, {
        ...lastSub,
        consent: { grantId },
      }, { mergeWithLastSubmission: true })
    }
    return res.status(501).send(`unhandled prompt ${prompt}`)
  } catch (err) { next(err) }
})

app.use('/federation/oidc', (req, res, next) => provider.callback()(req, res, next))

const server = await new Promise(r => { const s = app.listen(0); s.on('listening', () => r(s)) })
const base = `http://127.0.0.1:${server.address().port}`

const jar = new Map()
function cookieHeader() { return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ') }
function captureCookies(res) {
  for (const c of (res.headers.getSetCookie ? res.headers.getSetCookie() : [])) {
    const pair = c.split(';')[0].trim()
    const eq = pair.indexOf('=')
    jar.set(pair.slice(0, eq), pair.slice(eq + 1))
  }
}
async function plainText(res) {
  const t = await res.text()
  return t.replace(/<style[\s\S]*?<\/style>/g, ' ')
           .replace(/<[^>]+>/g, ' ')
           .replace(/\s+/g, ' ')
           .trim()
}
async function go(method, url, body) {
  const target = url.startsWith('http') ? url : base + url
  const headers = { cookie: cookieHeader() || undefined }
  let payload
  if (body) {
    headers['content-type'] = 'application/x-www-form-urlencoded'
    payload = new URLSearchParams(body).toString()
  }
  const res = await fetch(target, { method, headers, body: payload, redirect: 'manual' })
  captureCookies(res)
  return res
}
const abs = (l) => (l ? (l.startsWith('http') ? l : base + l) : '')

function newChallenge() {
  const verifier = crypto.randomBytes(48).toString('base64url')
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url')
  return { verifier, challenge }
}

// ===== flow: GET /auth → login → consent → code =====
let { verifier, challenge } = newChallenge()
let res = await go('GET', '/federation/oidc/auth?' + new URLSearchParams({
  client_id: 'urn:overleaf-federation:client:overleaf.example.com',
  scope: 'openid', response_type: 'code',
  redirect_uri: 'https://r.example/fed/callback',
  state: 'st1', nonce: 'nn1',
  code_challenge: challenge, code_challenge_method: 'S256',
}))
if (res.status >= 400) {
  console.log('FATAL first response:', res.status, (await plainText(res)).slice(0, 400))
  process.exit(1)
}

// walk redirect chain to final
let finalUrl = null
let cursor = res
for (let step = 0; step < 10; step++) {
  const loc = abs(cursor.headers.get('location') || '')
  console.log(`step ${step}: ${cursor.status} -> ${loc.slice(0, 130)}`)
  cursor = await go('GET', loc)
  const nextLoc = cursor.headers.get('location') || ''
  if ((cursor.status === 302 || cursor.status === 303) && nextLoc.includes('fed/callback')) {
    finalUrl = nextLoc
    break
  }
  if (cursor.status >= 400 || (cursor.status >= 200 && cursor.status < 300)) {
    console.log(`FATAL step ${step + 1} status ${cursor.status}:`, (await plainText(cursor)).slice(0, 400))
    break
  }
}

if (!finalUrl) { console.log('FATAL: no final redirect'); process.exit(2) }
const final = new URL(finalUrl.startsWith('http') ? finalUrl : base + finalUrl)
const code = final.searchParams.get('code')
console.log('final redirect:', final.toString().slice(0, 140))
console.log('code:***', code?.slice(0, 12))
if (!code) process.exit(3)

// ===== token exchange =====
let tokRes = await go('POST', '/federation/oidc/token', {
  grant_type: 'authorization_code',
  code,
  client_id: 'urn:overleaf-federation:client:overleaf.example.com',
  code_verifier: verifier,
})
const rawTok = await tokRes.text()
let tok = {}
try { tok = JSON.parse(rawTok) } catch {}
console.log(`POST /token: ${tokRes.status} keys=${Object.keys(tok).join(',') || rawTok.slice(0, 200)}`)
if (tok.id_token) {
  const pay = JSON.parse(Buffer.from(tok.id_token.split('.')[1], 'base64url').toString())
  console.log('id_token payload:', JSON.stringify(pay))
  const missing = ['sub', 'origin', 'localName', 'displayName', 'institution'].filter(k => !(k in pay))
  console.log(missing.length === 0 ? 'CLAIMS: all present' : `CLAIMS MISSING: ${missing}`)
}

server.close()
process.exit(tok.id_token && !('sub' in {}) ? 0 : (tok.id_token ? 0 : 4))
