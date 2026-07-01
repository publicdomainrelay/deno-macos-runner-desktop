// App Attest ABC — pure interfaces for DeviceCheck attestation + Keychain.
// Zero I/O, zero side effects. Imports only from app-attest-common (types).

import type { AppAttestError } from "@publicdomainrelay/app-attest-common";

/** Hardware-bound key attestation. Implemented by app-attest-darwin via FFI. */
export interface AppAttestService {
  isSupported(): boolean;
  generateKey(): string; // throws AppAttestError
  attestKey(keyId: string, challengeHash: Uint8Array): Uint8Array; // throws AppAttestError
  generateAssertion(keyId: string, clientDataHash: Uint8Array): Uint8Array; // throws AppAttestError
}

/** macOS Keychain persistence. Implemented by app-attest-darwin via FFI. */
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
