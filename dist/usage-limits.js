import { getBlockingRateLimitResetAt, hasMeaningfulRateLimits } from './rate-limits.js';
const DEFAULT_USAGE_BASE_URL = 'https://chatgpt.com/backend-api';
const USAGE_BASE_URL_ENV = 'OPENCODE_MULTI_AUTH_USAGE_BASE_URL';
const USAGE_TIMEOUT_MS_ENV = 'OPENCODE_MULTI_AUTH_USAGE_TIMEOUT_MS';
const DEFAULT_USAGE_TIMEOUT_MS = 15_000;
function getUsageBaseUrl() {
    const override = process.env[USAGE_BASE_URL_ENV]?.trim();
    const baseUrl = override || DEFAULT_USAGE_BASE_URL;
    return baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;
}
function getUsageTimeoutMs() {
    const raw = process.env[USAGE_TIMEOUT_MS_ENV];
    const parsed = raw ? Number(raw) : NaN;
    if (Number.isFinite(parsed) && parsed > 0) {
        return parsed;
    }
    return DEFAULT_USAGE_TIMEOUT_MS;
}
function mapWindow(window, now) {
    if (!window)
        return undefined;
    const usedPercent = typeof window.used_percent === 'number' ? window.used_percent : undefined;
    const resetAt = typeof window.reset_at === 'number'
        ? window.reset_at * 1000
        : typeof window.reset_after_seconds === 'number'
            ? now + window.reset_after_seconds * 1000
            : undefined;
    if (usedPercent === undefined && resetAt === undefined) {
        return undefined;
    }
    return {
        limit: 100,
        remaining: typeof usedPercent === 'number' ? Math.max(0, 100 - usedPercent) : undefined,
        resetAt,
        updatedAt: now
    };
}
function pickRateLimitDetails(payload) {
    if (payload.rate_limit)
        return payload.rate_limit;
    const additional = Array.isArray(payload.additional_rate_limits) ? payload.additional_rate_limits : [];
    const preferred = additional.find((entry) => {
        const feature = entry.metered_feature?.trim().toLowerCase();
        const limitName = entry.limit_name?.trim().toLowerCase();
        return feature === 'codex' || limitName === 'codex';
    });
    if (preferred?.rate_limit)
        return preferred.rate_limit;
    return additional.find((entry) => entry.rate_limit)?.rate_limit || null;
}
export async function fetchUsageRateLimitsForAccount(account) {
    const token = account.accessToken?.trim();
    if (!token) {
        return {
            source: 'usage-api',
            error: 'Missing access token'
        };
    }
    const url = `${getUsageBaseUrl()}/wham/usage`;
    const headers = {
        Authorization: `Bearer ${token}`,
        'User-Agent': 'codex-cli'
    };
    if (account.accountId) {
        headers['ChatGPT-Account-Id'] = account.accountId;
    }
    let res;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), getUsageTimeoutMs());
    try {
        res = await fetch(url, { method: 'GET', headers, signal: controller.signal });
    }
    catch (err) {
        return {
            source: 'usage-api',
            error: `Usage API request failed: ${err}`
        };
    }
    finally {
        clearTimeout(timeout);
    }
    let rawText = '';
    try {
        rawText = await res.text();
    }
    catch {
        rawText = '';
    }
    if (!res.ok) {
        const trimmed = rawText.trim();
        return {
            source: 'usage-api',
            error: `Usage API returned ${res.status}${trimmed ? `: ${trimmed.slice(0, 280)}` : ''}`
        };
    }
    let payload;
    try {
        payload = JSON.parse(rawText);
    }
    catch (err) {
        return {
            source: 'usage-api',
            error: `Usage API returned invalid JSON: ${err}`
        };
    }
    const now = Date.now();
    const details = pickRateLimitDetails(payload);
    const rateLimits = {
        fiveHour: mapWindow(details?.primary_window, now),
        weekly: mapWindow(details?.secondary_window, now)
    };
    if (!hasMeaningfulRateLimits(rateLimits)) {
        return {
            source: 'usage-api',
            planType: payload.plan_type,
            error: 'Usage API response contained no usable rate limit windows'
        };
    }
    const rateLimitedUntil = details?.limit_reached || details?.allowed === false
        ? getBlockingRateLimitResetAt(rateLimits, now)
        : undefined;
    return {
        source: 'usage-api',
        planType: payload.plan_type,
        rateLimits,
        rateLimitedUntil
    };
}
//# sourceMappingURL=usage-limits.js.map