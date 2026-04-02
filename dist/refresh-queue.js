import { refreshRateLimitsForAccount } from './limits-refresh.js';
import { updateAccount } from './store.js';
import { logError, logInfo, logWarn } from './logger.js';
let queueState = null;
let stopRequested = false;
export function getRefreshQueueState() {
    return queueState;
}
export function stopRefreshQueue() {
    stopRequested = true;
    if (queueState) {
        queueState.stopRequested = true;
    }
}
async function runQueue(targets) {
    if (!queueState)
        return;
    for (const account of targets) {
        if (!queueState)
            return;
        if (stopRequested) {
            updateAccount(account.alias, { limitStatus: 'stopped', limitError: 'Stopped by user' });
            queueState.results.push({ alias: account.alias, updated: false, error: 'Stopped' });
            queueState.completed += 1;
            continue;
        }
        queueState.currentAlias = account.alias;
        let result;
        try {
            result = await refreshRateLimitsForAccount(account);
        }
        catch (err) {
            const errorText = `Refresh queue failed for ${account.alias}: ${err}`;
            logError(errorText);
            updateAccount(account.alias, { limitStatus: 'error', limitError: errorText, lastLimitErrorAt: Date.now() });
            result = { alias: account.alias, updated: false, error: errorText };
        }
        queueState.results.push(result);
        queueState.completed += 1;
        if (result.error) {
            queueState.errors += 1;
        }
    }
    queueState.running = false;
    queueState.finishedAt = Date.now();
    queueState.currentAlias = undefined;
    queueState.stopped = stopRequested;
    queueState.stopRequested = stopRequested;
    if (stopRequested) {
        logWarn('Limit refresh queue stopped by user');
    }
    else {
        logInfo('Limit refresh queue completed');
    }
    stopRequested = false;
}
export function startRefreshQueue(accounts, alias) {
    if (queueState?.running) {
        return queueState;
    }
    const targets = alias ? accounts.filter((acc) => acc.alias === alias) : accounts;
    const startedAt = Date.now();
    queueState = {
        running: true,
        startedAt,
        total: targets.length,
        completed: 0,
        errors: 0,
        stopRequested: false,
        stopped: false,
        results: []
    };
    stopRequested = false;
    if (targets.length === 0) {
        queueState.running = false;
        queueState.finishedAt = Date.now();
        logWarn('Limit refresh queue requested with no targets');
        return queueState;
    }
    for (const account of targets) {
        updateAccount(account.alias, { limitStatus: 'queued', limitError: undefined });
    }
    logInfo(`Limit refresh queue started (${targets.length} accounts)`);
    void runQueue(targets);
    return queueState;
}
//# sourceMappingURL=refresh-queue.js.map