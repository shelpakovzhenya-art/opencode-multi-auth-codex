import * as fs from 'node:fs'
import * as net from 'node:net'
import * as os from 'node:os'
import * as path from 'node:path'
import type * as http from 'node:http'
import { once } from 'node:events'
import type { AccountCredentials } from '../../src/types.js'

const SANDBOX_ROOT = path.join(os.tmpdir(), 'oma-web-integration-sandbox')
const STORE_FILE = path.join(SANDBOX_ROOT, 'accounts.json')
const AUTH_FILE = path.join(SANDBOX_ROOT, 'auth.json')
const OPENCODE_AUTH_FILE = path.join(SANDBOX_ROOT, 'opencode-auth.json')
const originalEnv = process.env

let startWebConsole: typeof import('../../src/web.js').startWebConsole
let getCodexAuthPath: typeof import('../../src/codex-auth.js').getCodexAuthPath
let writeCodexAuthForAlias: typeof import('../../src/codex-auth.js').writeCodexAuthForAlias
let loadStore: typeof import('../../src/store.js').loadStore
let saveStore: typeof import('../../src/store.js').saveStore

function createAccount(alias: string, overrides: Partial<AccountCredentials> = {}): AccountCredentials {
  return {
    alias,
    accessToken: `access-${alias}`,
    refreshToken: `refresh-${alias}`,
    idToken: `id-${alias}`,
    expiresAt: Date.now() + 60 * 60 * 1000,
    usageCount: 0,
    enabled: true,
    ...overrides
  }
}

async function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer()
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      if (!address || typeof address === 'string') {
        reject(new Error('Failed to resolve free port'))
        return
      }
      const port = address.port
      server.close((err) => {
        if (err) {
          reject(err)
          return
        }
        resolve(port)
      })
    })
    server.on('error', reject)
  })
}

async function closeServer(server: http.Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((err) => {
      if (err) {
        reject(err)
        return
      }
      resolve()
    })
  })
}

beforeAll(async () => {
  if (fs.existsSync(SANDBOX_ROOT)) {
    fs.rmSync(SANDBOX_ROOT, { recursive: true, force: true })
  }
  fs.mkdirSync(SANDBOX_ROOT, { recursive: true })
  fs.writeFileSync(AUTH_FILE, JSON.stringify({ OPENAI_API_KEY: null, tokens: {} }, null, 2))
  fs.writeFileSync(OPENCODE_AUTH_FILE, JSON.stringify({}, null, 2))

  process.env = {
    ...originalEnv,
    OPENCODE_MULTI_AUTH_STORE_DIR: SANDBOX_ROOT,
    OPENCODE_MULTI_AUTH_STORE_FILE: STORE_FILE,
    OPENCODE_MULTI_AUTH_CODEX_AUTH_FILE: AUTH_FILE,
    OPENCODE_MULTI_AUTH_OPENCODE_AUTH_FILE: OPENCODE_AUTH_FILE
  }

  ;({ startWebConsole } = await import('../../src/web.js'))
  ;({ getCodexAuthPath, writeCodexAuthForAlias } = await import('../../src/codex-auth.js'))
  ;({ loadStore, saveStore } = await import('../../src/store.js'))
})

afterAll(() => {
  try {
    if (getCodexAuthPath) {
      fs.unwatchFile(getCodexAuthPath())
    }
  } catch {
    // ignore
  }
  process.env = originalEnv
  if (fs.existsSync(SANDBOX_ROOT)) {
    fs.rmSync(SANDBOX_ROOT, { recursive: true, force: true })
  }
})

describe('web server hardening', () => {
  it('rejects non-loopback host binding', () => {
    expect(() => startWebConsole({ host: '0.0.0.0', port: 4120 })).toThrow(/LOCALHOST_ONLY|localhost/i)
  })

  it('returns 400 for invalid JSON and keeps server alive', async () => {
    const port = await getFreePort()
    const server = startWebConsole({ host: '127.0.0.1', port })

    try {
      await once(server, 'listening')

      const invalidResponse = await fetch(`http://127.0.0.1:${port}/api/switch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{bad json'
      })

      expect(invalidResponse.status).toBe(400)
      const invalidPayload = (await invalidResponse.json()) as { code?: string }
      expect(invalidPayload.code).toBe('INVALID_JSON')

      const healthyResponse = await fetch(`http://127.0.0.1:${port}/api/switch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}'
      })

      expect(healthyResponse.status).toBe(400)
    } finally {
      await closeServer(server)
      fs.unwatchFile(getCodexAuthPath())
    }
  })

  it('reports active route separately from auth.json without rewriting auth.json', async () => {
    const now = Date.now()
    const store = loadStore()
    store.accounts.alpha = createAccount('alpha', {
      rateLimitedUntil: now + 60 * 60 * 1000,
      rateLimits: {
        weekly: { limit: 100, remaining: 0, resetAt: now + 60 * 60 * 1000, updatedAt: now }
      }
    })
    store.accounts.beta = createAccount('beta', {
      rateLimits: {
        weekly: { limit: 100, remaining: 85, resetAt: now + 60 * 60 * 1000, updatedAt: now }
      }
    })
    saveStore(store)
    writeCodexAuthForAlias('alpha', { setActive: false })

    const port = await getFreePort()
    const server = startWebConsole({ host: '127.0.0.1', port })

    try {
      await once(server, 'listening')

      const updatedStore = loadStore()
      updatedStore.activeAlias = 'beta'
      saveStore(updatedStore)

      const response = await fetch(`http://127.0.0.1:${port}/api/state`)
      expect(response.status).toBe(200)

      const payload = await response.json() as {
        currentAlias?: string | null
        activeAlias?: string | null
        onDeviceAlias?: string | null
      }
      expect(payload.currentAlias).toBe('beta')
      expect(payload.activeAlias).toBe('beta')
      expect(payload.onDeviceAlias).toBe('alpha')

      const auth = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf-8')) as {
        tokens?: { access_token?: string }
      }
      expect(auth.tokens?.access_token).toBe('access-alpha')
    } finally {
      await closeServer(server)
      fs.unwatchFile(getCodexAuthPath())
    }
  })

  it('reports the current OpenCode session separately from active route and auth.json', async () => {
    const store = loadStore()
    store.accounts.alpha = createAccount('alpha')
    store.accounts.beta = createAccount('beta', {
      accountId: 'beta-account',
      email: 'beta@example.com'
    })
    store.activeAlias = 'alpha'
    saveStore(store)

    writeCodexAuthForAlias('alpha', { setActive: false })
    fs.writeFileSync(OPENCODE_AUTH_FILE, JSON.stringify({
      openai: {
        type: 'oauth',
        access: 'access-beta',
        refresh: 'refresh-beta',
        expires: Date.now() + 60_000,
        accountId: 'beta-account'
      }
    }, null, 2))

    const port = await getFreePort()
    const server = startWebConsole({ host: '127.0.0.1', port })

    try {
      await once(server, 'listening')

      const response = await fetch(`http://127.0.0.1:${port}/api/state`)
      expect(response.status).toBe(200)

      const payload = await response.json() as {
        currentAlias?: string | null
        openCodeAlias?: string | null
        activeAlias?: string | null
        onDeviceAlias?: string | null
      }

      expect(payload.currentAlias).toBe('beta')
      expect(payload.openCodeAlias).toBe('beta')
      expect(payload.activeAlias).toBe('alpha')
      expect(payload.onDeviceAlias).toBe('alpha')
    } finally {
      await closeServer(server)
      fs.unwatchFile(getCodexAuthPath())
    }
  })
})
