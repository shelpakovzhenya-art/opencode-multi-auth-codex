import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { jest } from '@jest/globals'
import { loadStore, saveStore } from '../../src/store.js'
import type { AccountCredentials } from '../../src/types.js'

const TEST_DIR = path.join(os.tmpdir(), `oma-codex-auth-test-${Date.now()}`)
const TEST_STORE_FILE = path.join(TEST_DIR, 'accounts.json')
const TEST_AUTH_FILE = path.join(TEST_DIR, 'auth.json')
const originalEnv = process.env

let syncCodexAuthToAvailableAlias: typeof import('../../src/codex-auth.js').syncCodexAuthToAvailableAlias
let writeCodexAuthForAlias: typeof import('../../src/codex-auth.js').writeCodexAuthForAlias
let loadCodexAuthFile: typeof import('../../src/codex-auth.js').loadCodexAuthFile

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

describe('codex auth auto-selection', () => {
  beforeEach(async () => {
    process.env = {
      ...originalEnv,
      OPENCODE_MULTI_AUTH_STORE_DIR: TEST_DIR,
      OPENCODE_MULTI_AUTH_STORE_FILE: TEST_STORE_FILE,
      OPENCODE_MULTI_AUTH_CODEX_AUTH_FILE: TEST_AUTH_FILE
    }

    if (fs.existsSync(TEST_DIR)) {
      fs.rmSync(TEST_DIR, { recursive: true, force: true })
    }
    fs.mkdirSync(TEST_DIR, { recursive: true })

    jest.resetModules()
    const mod = await import('../../src/codex-auth.js')
    syncCodexAuthToAvailableAlias = mod.syncCodexAuthToAvailableAlias
    writeCodexAuthForAlias = mod.writeCodexAuthForAlias
    loadCodexAuthFile = mod.loadCodexAuthFile
  })

  afterEach(() => {
    process.env = originalEnv
    if (fs.existsSync(TEST_DIR)) {
      fs.rmSync(TEST_DIR, { recursive: true, force: true })
    }
  })

  it('switches auth.json away from a blocked current alias', () => {
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
        weekly: { limit: 100, remaining: 82, resetAt: now + 60 * 60 * 1000, updatedAt: now },
        fiveHour: { limit: 100, remaining: 65, resetAt: now + 30 * 60 * 1000, updatedAt: now }
      }
    })
    store.activeAlias = 'alpha'
    saveStore(store)

    writeCodexAuthForAlias('alpha')

    const result = syncCodexAuthToAvailableAlias()

    expect(result).toEqual({ alias: 'beta', updated: true })
    expect(loadCodexAuthFile()?.tokens.access_token).toBe('access-beta')
    expect(loadStore().activeAlias).toBe('alpha')
  })

  it('keeps the current auth.json alias when it is still available', () => {
    const now = Date.now()
    const store = loadStore()
    store.accounts.alpha = createAccount('alpha', {
      rateLimits: {
        weekly: { limit: 100, remaining: 40, resetAt: now + 60 * 60 * 1000, updatedAt: now }
      }
    })
    store.accounts.beta = createAccount('beta', {
      rateLimits: {
        weekly: { limit: 100, remaining: 95, resetAt: now + 60 * 60 * 1000, updatedAt: now }
      }
    })
    saveStore(store)

    writeCodexAuthForAlias('alpha')

    const result = syncCodexAuthToAvailableAlias()

    expect(result).toEqual({ alias: 'alpha', updated: false })
    expect(loadCodexAuthFile()?.tokens.access_token).toBe('access-alpha')
  })

  it('prefers an account with known remaining limits on cold start', () => {
    const now = Date.now()
    const store = loadStore()
    store.accounts.alpha = createAccount('alpha')
    store.accounts.beta = createAccount('beta', {
      rateLimits: {
        weekly: { limit: 100, remaining: 91, resetAt: now + 60 * 60 * 1000, updatedAt: now }
      }
    })
    store.accounts.gamma = createAccount('gamma', {
      rateLimits: {
        weekly: { limit: 100, remaining: 35, resetAt: now + 60 * 60 * 1000, updatedAt: now }
      }
    })
    saveStore(store)

    const result = syncCodexAuthToAvailableAlias()

    expect(result).toEqual({ alias: 'beta', updated: true })
    expect(loadCodexAuthFile()?.tokens.access_token).toBe('access-beta')
  })
})
