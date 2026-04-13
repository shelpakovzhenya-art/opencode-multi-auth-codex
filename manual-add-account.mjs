import http from 'node:http'
import * as url from 'node:url'
import { createAuthorizationFlow } from './dist/auth.js'
import { addAccount } from './dist/store.js'
import {
  decodeJwtPayload,
  getAccountIdFromClaims,
  getEmailFromClaims,
  getExpiryFromClaims
} from './dist/codex-auth.js'

const OPENAI_ISSUER = 'https://auth.openai.com'
const TOKEN_URL = `${OPENAI_ISSUER}/oauth/token`
const CLIENT_ID = 'app_EMoamEEZ73f0CkXaXp7hrann'

const alias = process.argv[2]
const port = Number(process.argv[3] || '1456')

if (!alias) {
  console.error('Usage: node manual-add-account.mjs <alias> [port]')
  process.exit(1)
}

if (Number.isNaN(port) || port < 1 || port > 65535) {
  console.error(`Invalid port: ${process.argv[3]}`)
  process.exit(1)
}

const flow = await createAuthorizationFlow(port)

const server = http.createServer(async (req, res) => {
  if (!req.url?.startsWith('/auth/callback')) {
    res.writeHead(404)
    res.end('Not found')
    return
  }

  const parsedUrl = url.parse(req.url, true)
  const code = parsedUrl.query.code
  const returnedState = parsedUrl.query.state

  if (typeof code !== 'string' || !code) {
    res.writeHead(400)
    res.end('No authorization code received')
    server.close()
    process.exit(1)
  }

  if (typeof returnedState === 'string' && returnedState !== flow.state) {
    res.writeHead(400)
    res.end('Invalid state')
    server.close()
    process.exit(1)
  }

  try {
    const tokenRes = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: CLIENT_ID,
        code,
        code_verifier: flow.pkce.verifier,
        redirect_uri: flow.redirectUri
      })
    })

    if (!tokenRes.ok) {
      throw new Error(`Token exchange failed: ${tokenRes.status}`)
    }

    const tokens = await tokenRes.json()
    if (!tokens.refresh_token) {
      throw new Error('Token exchange did not return a refresh_token')
    }

    const now = Date.now()
    const accessClaims = decodeJwtPayload(tokens.access_token)
    const idClaims = tokens.id_token ? decodeJwtPayload(tokens.id_token) : null
    const expiresAt =
      getExpiryFromClaims(accessClaims) ||
      getExpiryFromClaims(idClaims) ||
      now + tokens.expires_in * 1000

    let email = getEmailFromClaims(idClaims) || getEmailFromClaims(accessClaims)
    try {
      const userRes = await fetch(`${OPENAI_ISSUER}/userinfo`, {
        headers: { Authorization: `Bearer ${tokens.access_token}` }
      })
      if (userRes.ok) {
        const user = await userRes.json()
        email = user.email || email
      }
    } catch {
      // user info is non-critical
    }

    const accountId =
      getAccountIdFromClaims(idClaims) ||
      getAccountIdFromClaims(accessClaims)

    const store = addAccount(alias, {
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      idToken: tokens.id_token,
      accountId,
      expiresAt,
      email,
      lastRefresh: new Date(now).toISOString(),
      lastSeenAt: now,
      source: 'opencode',
      authInvalid: false,
      authInvalidatedAt: undefined
    })

    const account = store.accounts[alias]

    res.writeHead(200, { 'Content-Type': 'text/html' })
    res.end(`
      <html>
        <body style="font-family: system-ui; padding: 40px; text-align: center;">
          <h1>Account "${alias}" authenticated!</h1>
          <p>${email || 'Unknown email'}</p>
          <p>You can close this window.</p>
        </body>
      </html>
    `)

    console.log(`\nAccount "${alias}" added successfully!`)
    console.log(`Email: ${account.email || 'unknown'}`)

    server.close(() => process.exit(0))
  } catch (err) {
    res.writeHead(500)
    res.end('Authentication failed')
    console.error(`Failed to add account: ${err}`)
    server.close(() => process.exit(1))
  }
})

server.listen(port, '127.0.0.1', () => {
  console.log(`\n[multi-auth] Login for account "${alias}"`)
  console.log('[multi-auth] Open this URL in your browser:\n')
  console.log(`  ${flow.url}\n`)
  console.log(`[multi-auth] Waiting for callback on port ${port}...`)
})

server.on('error', err => {
  console.error(`Failed to start callback server on port ${port}: ${err}`)
  process.exit(1)
})

setTimeout(() => {
  console.error('Failed to add account: Error: Login timeout - no callback received')
  server.close(() => process.exit(1))
}, 5 * 60 * 1000)
