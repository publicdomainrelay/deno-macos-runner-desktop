// Secret store chain — tries multiple KeychainStore backends in priority order.
// First available backend wins. Falls through to next if probe fails.
//
// Priority: darwin keychain → gnome-keyring → filesystem (always last, always available)

import type { StructuredLoggerInterface } from "@publicdomainrelay/logger";
import type { KeychainStore } from "@publicdomainrelay/app-attest-abc";

// ===========================================================================
// Backend descriptor
// ===========================================================================

export interface SecretStoreBackend {
  name: string;
  /** Synchronous availability check. True = backend is ready. */
  available: boolean;
  store: KeychainStore;
}

// ===========================================================================
// Factory config
// ===========================================================================

export interface ChainSecretStoreOpts {
  backends: SecretStoreBackend[];
  logger?: StructuredLoggerInterface;
}

// ===========================================================================
// Chain KeychainStore factory
// ===========================================================================

export function createChainKeychainStore(opts: ChainSecretStoreOpts): KeychainStore {
  const { backends, logger } = opts;

  function active(): KeychainStore | null {
    for (const b of backends) {
      if (b.available) return b.store;
    }
    return null;
  }

  function activeName(): string {
    for (const b of backends) {
      if (b.available) return b.name;
    }
    return "none";
  }

  logger?.info("secret store chain initialized", { active: activeName() });

  return {
    async save(key: string, value: string): Promise<boolean> {
      const s = active();
      if (!s) {
        logger?.error("secret store: no backend available for save", { key: key.slice(0, 8) });
        return false;
      }
      return s.save(key, value);
    },

    load(key: string): string | null {
      const s = active();
      if (!s) {
        logger?.error("secret store: no backend available for load", { key: key.slice(0, 8) });
        return null;
      }
      return s.load(key);
    },

    delete(key: string): boolean {
      const s = active();
      if (!s) {
        logger?.error("secret store: no backend available for delete", { key: key.slice(0, 8) });
        return false;
      }
      return s.delete(key);
    },
  };
}

/**
 * Build standard chain for the current platform.
 * Priority: win32 CredMan → gnome-keyring → filesystem
 * (darwin uses app-attest-darwin Keychain directly in hono-macos-runner-desktop;
 *  hono-desktop always uses portable stores even on macOS)
 *
 * Callers pass the platform-specific and fallback stores. The chain
 * resolves the first available one at construction time.
 */
export function buildStandardChain(opts: {
  win32Store?: KeychainStore;
  win32Available?: boolean;
  gnomeStore?: KeychainStore;
  gnomeAvailable?: boolean;
  filesystemStore: KeychainStore;
  logger?: StructuredLoggerInterface;
}): KeychainStore {
  const backends: SecretStoreBackend[] = [];

  if (opts.win32Store && opts.win32Available) {
    backends.push({ name: "win32-credman", available: true, store: opts.win32Store });
  }

  if (opts.gnomeStore && opts.gnomeAvailable) {
    backends.push({ name: "gnome-keyring", available: true, store: opts.gnomeStore });
  }

  // Filesystem is always available as final fallback
  backends.push({ name: "filesystem", available: true, store: opts.filesystemStore });

  return createChainKeychainStore({ backends, logger: opts.logger });
}
