// Device key ABC — pure interfaces for software device keys + secret storage.
// Zero I/O, zero side effects. Imports only from device-key-common (types).

/** Software device key generation. Same surface on every OS. */
export interface DeviceKeyService {
  generateKey(): Promise<string>; // throws DeviceKeyError
}

/** Persistent key-value store for secrets. */
export interface KeychainStore {
  save(key: string, value: string): Promise<boolean>;
  load(key: string): string | null;
  delete(key: string): boolean;
}

// ===========================================================================
// In-memory test double — pure state, zero I/O. Usable in unit tests with
// no mocks or fake timers (satisfies the ABC litmus test).
// ===========================================================================

export function createInMemoryKeychainStore(): KeychainStore {
  const store = new Map<string, string>();
  return {
    async save(key: string, value: string): Promise<boolean> {
      store.set(key, value);
      return true;
    },
    load(key: string): string | null {
      return store.get(key) ?? null;
    },
    delete(key: string): boolean {
      return store.delete(key);
    },
  };
}
