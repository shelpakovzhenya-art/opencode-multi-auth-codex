import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import { addAccount, loadStore, setActiveAlias, updateAccount } from './store.js'
import type { AccountCredentials } from './types.js'

export interface CodexAuthTokens {
  id_token: string
  access_token: string
  refresh_token: string
  account_id?: string
}

export interface CodexAuthFile {
  OPENAI_API_KEY: string | null
  tokens: CodexAuthTokens
  last_refresh?: string
}

interface CodexAuthWriteOptions {
  setActive?: boolean
}

const CODEX_AUTH_FILE_ENV = 'OPENCODE_MULTI_AUTH_CODEX_AUTH_FILE'

function getCodexAuthFilePath(): string {
  const override = process.env[CODEX_AUTH_FILE_ENV]
  if (override && override.trim()) return path.resolve(override.trim())
  const CODEX_DIR = path.join(os.homedir(), '.codex')
  return path.join(CODEX_DIR, 'auth.json')
}

const CODEX_DIR = path.join(os.homedir(), '.codex')
const CODEX_AUTH_FILE = getCodexAuthFilePath()

let lastFingerprint: string | null = null
let lastAuthError: string | null = null

export function getCodexAuthPath(): string {
  return CODEX_AUTH_FILE
}

function ensureDir(): void {
  if (!fs.existsSync(CODEX_DIR)) {
    fs.mkdirSync(CODEX_DIR, { recursive: true, mode: 0o700 })
  }
}

export function loadCodexAuthFile(): CodexAuthFile | null {
  lastAuthError = null
  if (!fs.existsSync(CODEX_AUTH_FILE)) return null
  try {
    const raw = fs.readFileSync(CODEX_AUTH_FILE, 'utf-8')
    return JSON.parse(raw) as CodexAuthFile
  } catch (err) {
    lastAuthError = 'Failed to parse codex auth.json'
    console.error('[multi-auth] Failed to parse codex auth.json:', err)
    return null
  }
}

export function writeCodexAuthFile(auth: CodexAuthFile): void {
  ensureDir()
  fs.writeFileSync(CODEX_AUTH_FILE, JSON.stringify(auth, null, 2), {
    mode: 0o600
  })
}

export function decodeJwtPayload(token: string): Record<string, any> | null {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const padded = payload.padEnd(payload.length + ((4 - (payload.length % 4)) % 4), '=')
    const decoded = Buffer.from(padded, 'base64').toString('utf-8')
    return JSON.parse(decoded) as Record<string, any>
  } catch {
    return null
  }
}

export function getEmailFromClaims(claims: Record<string, any> | null): string | undefined {
  if (!claims) return undefined
  if (typeof claims.email === 'string') return claims.email
  const profile = claims['https://api.openai.com/profile'] as { email?: string } | undefined
  if (profile?.email) return profile.email
  return undefined
}

export function getAccountIdFromClaims(claims: Record<string, any> | null): string | undefined {
  if (!claims) return undefined
  const auth = claims['https://api.openai.com/auth'] as { chatgpt_account_id?: string } | undefined
  return auth?.chatgpt_account_id
}

export function getExpiryFromClaims(claims: Record<string, any> | null): number | undefined {
  if (!claims) return undefined
  const exp = claims.exp
  if (typeof exp === 'number') return exp * 1000
  return undefined
}

function fingerprintTokens(tokens: CodexAuthTokens): string {
  return `${tokens.access_token}:${tokens.refresh_token}:${tokens.id_token}`
}

function hasWritableCodexTokens(account: AccountCredentials | undefined): account is AccountCredentials {
  return Boolean(account?.accessToken && account.refreshToken && account.idToken)
}

function remainingPercent(window?: { remaining?: number; limit?: number }): number {
  if (!window || typeof window.remaining !== 'number') return -1
  if (typeof window.limit === 'number' && window.limit > 0) {
    return Math.round((window.remaining / window.limit) * 100)
  }
  if (window.remaining >= 0 && window.remaining <= 100) {
    return window.remaining
  }
  return -1
}

function isWindowExhausted(window: { remaining?: number; resetAt?: number } | undefined, now: number): boolean {
  if (!window || typeof window.remaining !== 'number' || window.remaining > 0) {
    return false
  }
  return window.resetAt === undefined || window.resetAt > now
}

function isAccountAvailableForCodexAuth(account: AccountCredentials | undefined, now: number): boolean {
  if (!hasWritableCodexTokens(account)) return false
  if (account.enabled === false || account.authInvalid) return false
  if (account.rateLimitedUntil && account.rateLimitedUntil > now) return false
  if (account.modelUnsupportedUntil && account.modelUnsupportedUntil > now) return false
  if (account.workspaceDeactivatedUntil && account.workspaceDeactivatedUntil > now) return false
  if (isWindowExhausted(account.rateLimits?.fiveHour, now)) return false
  if (isWindowExhausted(account.rateLimits?.weekly, now)) return false
  return true
}

function compareAvailableAccounts(a: AccountCredentials, b: AccountCredentials): number {
  const aWeeklyPercent = remainingPercent(a.rateLimits?.weekly)
  const bWeeklyPercent = remainingPercent(b.rateLimits?.weekly)
  if (aWeeklyPercent !== bWeeklyPercent) return bWeeklyPercent - aWeeklyPercent

  const aWeeklyRemaining = typeof a.rateLimits?.weekly?.remaining === 'number' ? a.rateLimits.weekly.remaining : -1
  const bWeeklyRemaining = typeof b.rateLimits?.weekly?.remaining === 'number' ? b.rateLimits.weekly.remaining : -1
  if (aWeeklyRemaining !== bWeeklyRemaining) return bWeeklyRemaining - aWeeklyRemaining

  const aFiveHourPercent = remainingPercent(a.rateLimits?.fiveHour)
  const bFiveHourPercent = remainingPercent(b.rateLimits?.fiveHour)
  if (aFiveHourPercent !== bFiveHourPercent) return bFiveHourPercent - aFiveHourPercent

  const aLastUsed = typeof a.lastUsed === 'number' ? a.lastUsed : 0
  const bLastUsed = typeof b.lastUsed === 'number' ? b.lastUsed : 0
  if (aLastUsed !== bLastUsed) return aLastUsed - bLastUsed

  return a.alias.localeCompare(b.alias)
}

function buildAlias(email: string | undefined, accountId: string | undefined, store: ReturnType<typeof loadStore>): string {
  const base = email?.split('@')[0] || accountId?.slice(0, 8) || `account-${Date.now()}`
  const existing = new Set(Object.keys(store.accounts))
  let candidate = base || `account-${Date.now()}`
  let suffix = 1
  while (existing.has(candidate)) {
    candidate = `${base}-${suffix}`
    suffix += 1
  }
  return candidate
}

function findMatchingAlias(
  tokens: CodexAuthTokens,
  accountId: string | undefined,
  email: string | undefined,
  store: ReturnType<typeof loadStore>
): string | null {
  for (const account of Object.values(store.accounts)) {
    if (accountId && account.accountId === accountId) return account.alias
    if (account.accessToken === tokens.access_token) return account.alias
    if (account.refreshToken === tokens.refresh_token) return account.alias
    if (account.idToken === tokens.id_token) return account.alias
    if (email && account.email === email) return account.alias
  }
  return null
}

function getAliasFromCodexAuthFile(store: ReturnType<typeof loadStore>): string | null {
  const auth = loadCodexAuthFile()
  if (!auth?.tokens?.access_token || !auth.tokens.refresh_token || !auth.tokens.id_token) {
    return null
  }

  const accessClaims = decodeJwtPayload(auth.tokens.access_token)
  const idClaims = decodeJwtPayload(auth.tokens.id_token)
  const email = getEmailFromClaims(idClaims) || getEmailFromClaims(accessClaims)
  const accountId =
    auth.tokens.account_id ||
    getAccountIdFromClaims(idClaims) ||
    getAccountIdFromClaims(accessClaims)

  return findMatchingAlias(auth.tokens, accountId, email, store)
}

export function getCodexAuthAlias(store: ReturnType<typeof loadStore> = loadStore()): string | null {
  return getAliasFromCodexAuthFile(store)
}

export function getPreferredCodexAuthAlias(preferredAlias?: string): string | null {
  const store = loadStore()
  const now = Date.now()

  if (preferredAlias) {
    const preferred = store.accounts[preferredAlias]
    if (isAccountAvailableForCodexAuth(preferred, now)) {
      return preferredAlias
    }
  }

  const candidates = Object.values(store.accounts)
    .filter((account) => isAccountAvailableForCodexAuth(account, now))
    .sort(compareAvailableAccounts)

  return candidates[0]?.alias || null
}

export function syncCodexAuthFile(): { alias: string | null; added: boolean; updated: boolean } {
  const auth = loadCodexAuthFile()
  if (!auth?.tokens?.access_token || !auth.tokens.refresh_token || !auth.tokens.id_token) {
    return { alias: null, added: false, updated: false }
  }

  const fingerprint = fingerprintTokens(auth.tokens)

  const accessClaims = decodeJwtPayload(auth.tokens.access_token)
  const idClaims = decodeJwtPayload(auth.tokens.id_token)
  const email = getEmailFromClaims(idClaims) || getEmailFromClaims(accessClaims)
  const accountId = auth.tokens.account_id || getAccountIdFromClaims(idClaims) || getAccountIdFromClaims(accessClaims)
  const expiresAt = getExpiryFromClaims(accessClaims) || getExpiryFromClaims(idClaims) || Date.now()

  const store = loadStore()
  const now = Date.now()
  const alias = findMatchingAlias(auth.tokens, accountId, email, store)
  if (lastFingerprint === fingerprint && alias) {
    return { alias, added: false, updated: false }
  }
  lastFingerprint = fingerprint
  const update: Partial<AccountCredentials> = {
    accessToken: auth.tokens.access_token,
    refreshToken: auth.tokens.refresh_token,
    idToken: auth.tokens.id_token,
    accountId,
    expiresAt,
    email,
    lastRefresh: auth.last_refresh,
    lastSeenAt: now,
    source: 'codex'
  }

  if (alias) {
    updateAccount(alias, update)
    setActiveAlias(alias)
    return { alias, added: false, updated: true }
  }

  const newAlias = buildAlias(email, accountId, store)
  addAccount(newAlias, update as Omit<AccountCredentials, 'alias' | 'usageCount'>)
  setActiveAlias(newAlias)
  return { alias: newAlias, added: true, updated: true }
}

export function getCodexAuthStatus(): { error: string | null } {
  return { error: lastAuthError }
}

export function writeCodexAuthForAlias(alias: string, options: CodexAuthWriteOptions = {}): void {
  const store = loadStore()
  const account = store.accounts[alias]

  if (!account) {
    throw new Error(`Unknown alias: ${alias}`)
  }
  if (!account.accessToken || !account.refreshToken || !account.idToken) {
    throw new Error('Missing token data for alias')
  }

  const current = loadCodexAuthFile()
  const auth: CodexAuthFile = {
    OPENAI_API_KEY: current?.OPENAI_API_KEY ?? null,
    tokens: {
      id_token: account.idToken,
      access_token: account.accessToken,
      refresh_token: account.refreshToken,
      account_id: account.accountId
    },
    last_refresh: new Date().toISOString()
  }

  writeCodexAuthFile(auth)
  if (options.setActive !== false) {
    setActiveAlias(alias)
  }
  updateAccount(alias, {
    lastRefresh: auth.last_refresh,
    lastSeenAt: Date.now(),
    source: 'codex'
  })
}

export function syncCodexAuthToAvailableAlias(preferredAlias?: string): { alias: string | null; updated: boolean } {
  const store = loadStore()
  const now = Date.now()
  const currentAlias = getAliasFromCodexAuthFile(store)

  if (currentAlias && isAccountAvailableForCodexAuth(store.accounts[currentAlias], now)) {
    return { alias: currentAlias, updated: false }
  }

  const targetAlias = getPreferredCodexAuthAlias(preferredAlias)
  if (!targetAlias) {
    return { alias: currentAlias, updated: false }
  }

  if (currentAlias === targetAlias) {
    return { alias: targetAlias, updated: false }
  }

  writeCodexAuthForAlias(targetAlias, { setActive: false })
  return { alias: targetAlias, updated: true }
}
