import type { Auth } from '@opencode-ai/sdk';
import { loadStore } from './store.js';
export declare function getOpenCodeAuthAlias(store?: ReturnType<typeof loadStore>): string | null;
export declare function syncAuthFromOpenCode(getAuth: () => Promise<Auth>): Promise<void>;
//# sourceMappingURL=auth-sync.d.ts.map