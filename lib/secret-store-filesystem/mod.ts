// Secret store — filesystem-backed JSON persistence.
// Universal fallback. Works on all platforms with no dependencies.
// Implements KeychainStore from app-attest-abc.

import type { StructuredLoggerInterface } from "@publicdomainrelay/logger";
import type { KeychainStore } from "@publicdomainrelay/app-attest-abc";

// ===========================================================================
// Factory config
// ===========================================================================

export interface FilesystemSecretStoreOpts {
  storageDir?: string;
  logger?: StructuredLoggerInterface;
}

/** HOME-relative default for any CLI path option left unset. */
export function defaultHomeDir(): string {
  return Deno.env.get("HOME") ?? "/tmp";
}

// ===========================================================================
// Core store — synchronously flushed JSON map
// ===========================================================================

class FileStore {
  private store: Map<string, string>;
  private storePath: string;
  private logger?: StructuredLoggerInterface;

  constructor(storageDir: string, logger?: StructuredLoggerInterface) {
    this.logger = logger;
    Deno.mkdirSync(storageDir, { recursive: true });
    this.storePath = `${storageDir}/keystore.json`;
    this.store = new Map();
    try {
      const raw = Deno.readTextFileSync(this.storePath);
      const parsed = JSON.parse(raw);
      for (const [k, v] of Object.entries(parsed)) {
        if (typeof v === "string") this.store.set(k, v);
      }
      logger?.info("keystore loaded", { path: this.storePath, keys: this.store.size });
    } catch {
      logger?.info("keystore fresh start", { path: this.storePath });
    }
  }

  private flush(): void {
    const obj: Record<string, string> = {};
    for (const [k, v] of this.store) obj[k] = v;
    try { Deno.writeTextFileSync(this.storePath, JSON.stringify(obj)); }
    catch (e) { this.logger?.warn("keystore flush failed", { error: String(e) }); }
  }

  get(key: string): string | null { return this.store.get(key) ?? null; }
  set(key: string, value: string): void { this.store.set(key, value); this.flush(); }
  delete(key: string): boolean { const had = this.store.delete(key); if (had) this.flush(); return had; }
}

// ===========================================================================
// KeychainStore factory
// ===========================================================================

export function createFilesystemKeychainStore(opts: FilesystemSecretStoreOpts = {}): KeychainStore {
  const storageDir = opts.storageDir ?? `${defaultHomeDir()}/.pdr-keys`;
  const logger = opts.logger;
  const store = new FileStore(storageDir, logger);

  return {
    async save(key: string, value: string): Promise<boolean> {
      store.set(key, value);
      return true;
    },
    load(key: string): string | null {
      return store.get(key);
    },
    delete(key: string): boolean {
      return store.delete(key);
    },
  };
}

/** Check if filesystem store is available — always true. */
export function isFilesystemStoreAvailable(): boolean {
  return true;
}
