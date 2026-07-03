// Device keys — software ECDSA P-256 via Web Crypto.
// Only key implementation: cross-OS identical surface, no platform attestation.
// No FFI, no Deno.dlopen, no Secure Enclave dependency.
//
// Key storage is injected via the KeychainStore interface. Defaults to
// filesystem if none provided. Callers should wire up the platform chain:
//   win32 CredMan -> gnome-keyring -> filesystem

import type { StructuredLoggerInterface } from "@publicdomainrelay/logger";
import type { DeviceKeyService, KeychainStore } from "@publicdomainrelay/device-key-abc";
import type { OAuthSession } from "@publicdomainrelay/atproto-oauth-common";
import { createFilesystemKeychainStore } from "@publicdomainrelay/secret-store-filesystem";

// ===========================================================================
// Factory config
// ===========================================================================

export interface DeviceKeyWebcryptoOpts {
  /** Storage directory for filesystem fallback. Ignored if keychain is provided. */
  storageDir?: string;
  /** External secret store. Defaults to filesystem JSON store. */
  keychain?: KeychainStore;
  logger?: StructuredLoggerInterface;
}

// ===========================================================================
// DeviceKeyService factory (software keys)
// ===========================================================================

export function createDeviceKeyService(opts: DeviceKeyWebcryptoOpts = {}): DeviceKeyService {
  const store: KeychainStore = opts.keychain ?? createFilesystemKeychainStore({ storageDir: opts.storageDir, logger: opts.logger });
  const logger = opts.logger;

  return {
    async generateKey(): Promise<string> {
      const keyId = `soft-${crypto.randomUUID()}`;
      const keyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"],
      );
      const jwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
      await store.save(`key:${keyId}`, JSON.stringify(jwk));
      logger?.info("software device key generated", { keyId });
      return keyId;
    },
  };
}

// ===========================================================================
// Rich keychain store — wraps raw KeychainStore with session helpers
// ===========================================================================

const KC_SESSION_KEY = "oauth-session";
const KC_DEVICE_KEY_ID = "device-key-id";

export interface RichKeychainStore extends KeychainStore {
  saveSession(session: OAuthSession): Promise<void>;
  loadSession(): Promise<OAuthSession | null>;
  getDeviceKeyId(): string | null;
  saveDeviceKeyId(keyId: string): Promise<boolean>;
}

export function createRichKeychainStore(
  store: KeychainStore,
  opts?: { logger?: StructuredLoggerInterface },
): RichKeychainStore {
  const logger = opts?.logger;

  return {
    save(key: string, value: string): Promise<boolean> {
      return store.save(key, value);
    },

    load(key: string): string | null {
      return store.load(key);
    },

    delete(key: string): boolean {
      return store.delete(key);
    },

    async saveSession(session: OAuthSession): Promise<void> {
      const privJwk = await crypto.subtle.exportKey("jwk", session.dpopKeyPair.privateKey);
      const data = JSON.stringify({
        accessJwt: session.accessJwt,
        refreshJwt: session.refreshJwt,
        did: session.did,
        handle: session.handle,
        pds: session.pds,
        dpopPublicJwk: session.dpopPublicJwk,
        dpopPrivateJwk: privJwk,
      });
      await store.save(KC_SESSION_KEY, data);
      logger?.info("session saved");
    },

    async loadSession(): Promise<OAuthSession | null> {
      try {
        const raw = store.load(KC_SESSION_KEY);
        if (!raw) return null;
        const d = JSON.parse(raw);
        const privateKey = await crypto.subtle.importKey(
          "jwk", d.dpopPrivateJwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"],
        );
        const publicKey = await crypto.subtle.importKey(
          "jwk", d.dpopPublicJwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"],
        );
        return {
          accessJwt: d.accessJwt, refreshJwt: d.refreshJwt,
          did: d.did, handle: d.handle, pds: d.pds,
          dpopKeyPair: { privateKey, publicKey },
          dpopPublicJwk: d.dpopPublicJwk,
        };
      } catch (e) {
        logger?.warn("failed to load session", { error: String(e) });
        return null;
      }
    },

    getDeviceKeyId(): string | null {
      return store.load(KC_DEVICE_KEY_ID);
    },

    async saveDeviceKeyId(keyId: string): Promise<boolean> {
      return store.save(KC_DEVICE_KEY_ID, keyId);
    },
  };
}
