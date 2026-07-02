// macOS App Attest + Keychain via FFI (DeviceCheck DCAppAttestService).
// @ts-nocheck — Deno FFI types (Deno.dlopen, Deno.UnsafePointerView,
// Deno.UnsafePointer) not in stock Deno type declarations.

import type { StructuredLoggerInterface } from "@publicdomainrelay/logger";
import { AppAttestError, encodeCStr, readCStr, allocSizeT, readSizeT } from "@publicdomainrelay/app-attest-common";
import type { AppAttestService, KeychainStore } from "@publicdomainrelay/app-attest-abc";
import type { OAuthSession } from "@publicdomainrelay/atproto-oauth-common";

// ===========================================================================
// Factory config
// ===========================================================================

export interface AppAttestDarwinOpts {
  bridgePath: string;
  logger?: StructuredLoggerInterface;
}

// ===========================================================================
// Internal state
// ===========================================================================

let bridge: Deno.DynamicLibrary<{
  dc_is_supported: { parameters: []; result: "i32" };
  dc_generate_key: { parameters: []; result: "pointer" };
  dc_attest_key: { parameters: ["pointer", "pointer", "usize", "pointer"]; result: "pointer" };
  dc_generate_assertion: { parameters: ["pointer", "pointer", "usize", "pointer"]; result: "pointer" };
  dc_last_error: { parameters: []; result: "pointer" };
  dc_free_string: { parameters: ["pointer"]; result: "void" };
  dc_free_buffer: { parameters: ["pointer"]; result: "void" };
  url_register_handler: { parameters: []; result: "void" };
  url_scheme_pending: { parameters: []; result: "pointer" };
  keychain_save: { parameters: ["pointer", "pointer", "usize"]; result: "i32" };
  keychain_load: { parameters: ["pointer", "pointer"]; result: "pointer" };
  keychain_load_str: { parameters: ["pointer"]; result: "pointer" };
  keychain_delete: { parameters: ["pointer"]; result: "i32" };
}> | null = null;
let bridgeError: string | null = null;

// ===========================================================================
// Lazy bridge loader — dlopen deferred to first use to avoid import-time
// failures when the dylib doesn't exist (tests, dev without bridge).
// ===========================================================================

function resolveBridgePath(bridgePath: string): string {
  const name = "devicecheck_bridge.dylib";
  if (bridgePath) {
    try { Deno.statSync(bridgePath); return bridgePath; } catch { /* fall through */ }
  }
  // In compiled bundle, binary is Contents/MacOS/laufey_webview
  const execDir = Deno.execPath().replace(/\/[^/]+$/, "");
  return `${execDir}/${name}`;
}

function ensureBridge(bridgePath: string, logger?: StructuredLoggerInterface): void {
  if (bridge || bridgeError !== null) return;
  const path = resolveBridgePath(bridgePath);
  logger?.info("Bridge path resolved", { path });
  try {
    bridge = Deno.dlopen(path, {
      dc_is_supported: { parameters: [], result: "i32" },
      dc_generate_key: { parameters: [], result: "pointer" },
      dc_attest_key: { parameters: ["pointer", "pointer", "usize", "pointer"], result: "pointer" },
      dc_generate_assertion: { parameters: ["pointer", "pointer", "usize", "pointer"], result: "pointer" },
      dc_last_error: { parameters: [], result: "pointer" },
      dc_free_string: { parameters: ["pointer"], result: "void" },
      dc_free_buffer: { parameters: ["pointer"], result: "void" },
      url_register_handler: { parameters: [], result: "void" },
      url_scheme_pending: { parameters: [], result: "pointer" },
      keychain_save: { parameters: ["pointer", "pointer", "usize"], result: "i32" },
      keychain_load: { parameters: ["pointer", "pointer"], result: "pointer" },
      keychain_load_str: { parameters: ["pointer"], result: "pointer" },
      keychain_delete: { parameters: ["pointer"], result: "i32" },
    });
    logger?.info("Bridge loaded", { symbols: Object.keys(bridge.symbols) });
  } catch (e) {
    bridgeError = e instanceof Error ? e.message : String(e);
    logger?.error("Failed to load devicecheck_bridge.dylib", { error: bridgeError });
  }
}

function checkBridge(): void {
  if (bridgeError) throw new AppAttestError(`Bridge not loaded: ${bridgeError}`);
}

function getLastError(): string {
  const ptr = bridge!.symbols.dc_last_error();
  if (ptr === null) return "unknown error";
  return readCStr(ptr);
}

// ===========================================================================
// AppAttestService factory
// ===========================================================================

export function createAppAttestService(opts: AppAttestDarwinOpts): AppAttestService {
  const { bridgePath, logger } = opts;
  return {
    isSupported(): boolean {
      try {
        ensureBridge(bridgePath, logger);
      } catch {
        return false;
      }
      if (bridgeError) return false;
      try {
        return bridge!.symbols.dc_is_supported() !== 0;
      } catch (e) {
        logger?.error("isSupported check failed", { error: String(e) });
        return false;
      }
    },

    async generateKey(): Promise<string> {
      ensureBridge(bridgePath, logger);
      checkBridge();
      const keyPtr = bridge!.symbols.dc_generate_key();
      if (keyPtr === null) {
        const err = getLastError();
        logger?.error("generateKey failed", { error: err });
        throw new AppAttestError(err);
      }
      const keyId = readCStr(keyPtr);
      bridge!.symbols.dc_free_string(keyPtr);
      logger?.info("generateKey succeeded", { keyId });
      return keyId;
    },

    async attestKey(keyId: string, challengeHash: Uint8Array): Promise<Uint8Array> {
      ensureBridge(bridgePath, logger);
      checkBridge();
      const keyCStr = encodeCStr(keyId);
      const outLenBuf = allocSizeT();
      const dataPtr = bridge!.symbols.dc_attest_key(
        Deno.UnsafePointer.of(keyCStr),
        Deno.UnsafePointer.of(challengeHash),
        BigInt(challengeHash.length),
        Deno.UnsafePointer.of(outLenBuf),
      );
      if (dataPtr === null) {
        const err = getLastError();
        logger?.error("attestKey failed", { keyId, error: err });
        throw new AppAttestError(err);
      }
      const len = readSizeT(outLenBuf);
      const buf = new Uint8Array(len);
      buf.set(new Uint8Array(Deno.UnsafePointerView.getArrayBuffer(dataPtr, len)));
      bridge!.symbols.dc_free_buffer(dataPtr);
      logger?.info("attestKey succeeded", { keyId, attestationLen: len });
      return buf;
    },

    async generateAssertion(keyId: string, clientDataHash: Uint8Array): Promise<Uint8Array> {
      ensureBridge(bridgePath, logger);
      checkBridge();
      const keyCStr = encodeCStr(keyId);
      const outLenBuf = allocSizeT();
      const dataPtr = bridge!.symbols.dc_generate_assertion(
        Deno.UnsafePointer.of(keyCStr),
        Deno.UnsafePointer.of(clientDataHash),
        BigInt(clientDataHash.length),
        Deno.UnsafePointer.of(outLenBuf),
      );
      if (dataPtr === null) {
        const err = getLastError();
        logger?.error("generateAssertion failed", { keyId, error: err });
        throw new AppAttestError(err);
      }
      const len = readSizeT(outLenBuf);
      const buf = new Uint8Array(len);
      buf.set(new Uint8Array(Deno.UnsafePointerView.getArrayBuffer(dataPtr, len)));
      bridge!.symbols.dc_free_buffer(dataPtr);
      logger?.info("generateAssertion succeeded", { keyId, assertionLen: len });
      return buf;
    },
  };
}

// ===========================================================================
// KeychainStore factory
// ===========================================================================

const KC_SESSION_KEY = "oauth-session";
const KC_DEVICE_KEY_ID = "device-key-id";

export function createKeychainStore(opts: AppAttestDarwinOpts): KeychainStore & {
  saveSession(session: OAuthSession): Promise<void>;
  loadSession(): Promise<OAuthSession | null>;
  getDeviceKeyId(): string | null;
  saveDeviceKeyId(keyId: string): Promise<boolean>;
} {
  const { bridgePath, logger } = opts;

  return {
    async save(key: string, value: string): Promise<boolean> {
      ensureBridge(bridgePath, logger);
      if (!bridge) return false;
      const keyBuf = encodeCStr(key);
      const valBuf = new TextEncoder().encode(value);
      const keyPtr = Deno.UnsafePointer.of(keyBuf);
      const valPtr = Deno.UnsafePointer.of(valBuf);
      return bridge.symbols.keychain_save(keyPtr, valPtr, BigInt(valBuf.byteLength)) === 1;
    },

    load(key: string): string | null {
      ensureBridge(bridgePath, logger);
      if (!bridge) {
        logger?.warn("keychain load skipped, bridge not loaded", { key });
        return null;
      }
      const keyBuf = encodeCStr(key);
      const keyPtr = Deno.UnsafePointer.of(keyBuf);
      const ptr = bridge.symbols.keychain_load_str(keyPtr);
      if (!ptr) {
        logger?.info("keychain load returned no item", { key });
        return null;
      }
      const str = readCStr(ptr);
      bridge.symbols.dc_free_string(ptr);
      return str || null;
    },

    delete(key: string): boolean {
      ensureBridge(bridgePath, logger);
      if (!bridge) return false;
      const keyBuf = encodeCStr(key);
      return bridge.symbols.keychain_delete(Deno.UnsafePointer.of(keyBuf)) === 1;
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
      const ok = await this.save(KC_SESSION_KEY, data);
      logger?.info("session saved to keychain", { ok });
    },

    async loadSession(): Promise<OAuthSession | null> {
      try {
        const raw = this.load(KC_SESSION_KEY);
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
        logger?.warn("failed to load session from keychain", { error: String(e) });
        return null;
      }
    },

    getDeviceKeyId(): string | null {
      ensureBridge(bridgePath, logger);
      if (!bridge) return null;
      return this.load(KC_DEVICE_KEY_ID);
    },

    async saveDeviceKeyId(keyId: string): Promise<boolean> {
      return this.save(KC_DEVICE_KEY_ID, keyId);
    },
  };
}

// ===========================================================================
// URL scheme poller (kAEGetURL Apple Event handler)
// ===========================================================================

export function createUrlSchemePoller(opts: AppAttestDarwinOpts): {
  register(): void;
  poll(): string | null;
} {
  const { bridgePath, logger } = opts;

  return {
    register(): void {
      ensureBridge(bridgePath, logger);
      if (!bridge) return;
      bridge.symbols.url_register_handler();
      logger?.info("URL scheme handler registered");
    },

    poll(): string | null {
      if (!bridge) return null;
      const ptr = bridge.symbols.url_scheme_pending();
      if (!ptr) return null;
      const urlStr = readCStr(ptr);
      bridge.symbols.dc_free_string(ptr);
      return urlStr || null;
    },
  };
}
