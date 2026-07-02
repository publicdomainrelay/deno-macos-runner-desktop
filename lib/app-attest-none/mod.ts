// @ts-nocheck — Web Crypto BufferSource / Uint8Array mismatch in Deno types
// Portable App Attest — software keys via Web Crypto.
// Drop-in replacement for app-attest-darwin for non-Apple platforms.
// No FFI, no Deno.dlopen, no Secure Enclave dependency.
//
// Key storage is injected via the KeychainStore interface. Defaults to
// filesystem if none provided. Callers should wire up the platform chain:
//   darwin keychain → gnome-keyring → filesystem

import type { StructuredLoggerInterface } from "@publicdomainrelay/logger";
import { AppAttestError } from "@publicdomainrelay/app-attest-common";
import type { AppAttestService, KeychainStore } from "@publicdomainrelay/app-attest-abc";
import type { OAuthSession } from "@publicdomainrelay/atproto-oauth-common";
import { createFilesystemKeychainStore } from "@publicdomainrelay/secret-store-filesystem";

// ===========================================================================
// Factory config
// ===========================================================================

export interface AppAttestNoneOpts {
  /** Storage directory for filesystem fallback. Ignored if keychain is provided. */
  storageDir?: string;
  /** External secret store. Defaults to filesystem JSON store. */
  keychain?: KeychainStore;
  logger?: StructuredLoggerInterface;
}

// ===========================================================================
// DER helpers — minimal ASN.1 construction for self-signed X.509 cert
// ===========================================================================

function encodeDERLength(len: number): Uint8Array {
  if (len < 0x80) return new Uint8Array([len]);
  if (len < 0x100) return new Uint8Array([0x81, len]);
  if (len < 0x10000) return new Uint8Array([0x82, (len >> 8) & 0xff, len & 0xff]);
  throw new AppAttestError(`DER length too large: ${len}`);
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function tagged(tag: number, content: Uint8Array): Uint8Array {
  const len = encodeDERLength(content.length);
  return concat(new Uint8Array([tag]), len, content);
}

function makeDERSequence(contents: Uint8Array): Uint8Array {
  return tagged(0x30, contents);
}

function makeDERSet(contents: Uint8Array): Uint8Array {
  return tagged(0x31, contents);
}

function makeDERBitString(bytes: Uint8Array): Uint8Array {
  return concat(new Uint8Array([0x03]), encodeDERLength(bytes.length + 1), new Uint8Array([0]), bytes);
}

function makeDERInteger(value: number): Uint8Array {
  if (value === 0) return new Uint8Array([0x02, 0x01, 0x00]);
  const bytes: number[] = [];
  let v = value >>> 0;
  while (v > 0) { bytes.unshift(v & 0xff); v >>>= 8; }
  if (bytes.length === 0) bytes.push(0);
  if (bytes[0] & 0x80) bytes.unshift(0);
  return concat(new Uint8Array([0x02]), encodeDERLength(bytes.length), new Uint8Array(bytes));
}

function makeDEROID(oid: number[]): Uint8Array {
  const values: number[] = [oid[0] * 40 + oid[1]];
  for (let i = 2; i < oid.length; i++) {
    let v = oid[i];
    if (v < 0x80) { values.push(v); continue; }
    const parts: number[] = [];
    while (v > 0) { parts.unshift(v & 0x7f); v >>>= 7; }
    for (let j = 0; j < parts.length - 1; j++) parts[j] |= 0x80;
    values.push(...parts);
  }
  return concat(new Uint8Array([0x06]), encodeDERLength(values.length), new Uint8Array(values));
}

function makeDERUTCTime(date: Date): Uint8Array {
  const s = date.getUTCFullYear().toString().slice(-2) +
    String(date.getUTCMonth() + 1).padStart(2, "0") +
    String(date.getUTCDate()).padStart(2, "0") +
    String(date.getUTCHours()).padStart(2, "0") +
    String(date.getUTCMinutes()).padStart(2, "0") +
    String(date.getUTCSeconds()).padStart(2, "0") + "Z";
  return concat(new Uint8Array([0x17]), encodeDERLength(s.length), new TextEncoder().encode(s));
}

function makeDERPrintableString(s: string): Uint8Array {
  const bytes = new TextEncoder().encode(s);
  return concat(new Uint8Array([0x13]), encodeDERLength(bytes.length), bytes);
}

const OID_EC_PUBLIC_KEY = makeDEROID([1, 2, 840, 10045, 2, 1]);
const OID_P256 = makeDEROID([1, 2, 840, 10045, 3, 1, 7]);
const OID_ECDSA_SHA256 = makeDEROID([1, 2, 840, 10045, 4, 3, 2]);
const OID_COMMON_NAME = makeDEROID([2, 5, 4, 3]);

function encodeDERIntegerBytes(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length && bytes[start] === 0) start++;
  if (start === bytes.length) return new Uint8Array([0x02, 0x01, 0x00]);
  const trimmed = bytes.slice(start);
  if (trimmed[0] & 0x80) {
    return concat(new Uint8Array([0x02]), encodeDERLength(trimmed.length + 1), new Uint8Array([0]), trimmed);
  }
  return concat(new Uint8Array([0x02]), encodeDERLength(trimmed.length), trimmed);
}

async function buildSelfSignedCert(spki: Uint8Array, privateKey: CryptoKey): Promise<Uint8Array> {
  const now = new Date();
  const notAfter = new Date(now.getTime() + 365 * 24 * 3600 * 1000);

  const serial = makeDERInteger(1);
  const sigAlg = makeDERSequence(concat(OID_ECDSA_SHA256));
  const issuerName = makeDERSequence(
    makeDERSet(makeDERSequence(concat(OID_COMMON_NAME, makeDERPrintableString("pdr-software-key")))),
  );
  const validity = makeDERSequence(concat(makeDERUTCTime(now), makeDERUTCTime(notAfter)));
  const subjectName = makeDERSequence(
    makeDERSet(makeDERSequence(concat(OID_COMMON_NAME, makeDERPrintableString("pdr-software-key")))),
  );

  const spkiAlg = makeDERSequence(concat(OID_EC_PUBLIC_KEY, OID_P256));
  const rawKey = new Uint8Array(await crypto.subtle.exportKey(
    "raw",
    await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, true, []),
  ));
  const pubKeyBits = makeDERBitString(new Uint8Array([0x04, ...rawKey]));
  const spkiSeq = makeDERSequence(concat(spkiAlg, pubKeyBits));

  const tbs = makeDERSequence(concat(serial, sigAlg, issuerName, validity, subjectName, spkiSeq));

  const sig = new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, privateKey, tbs,
  ));
  const r = sig.slice(0, 32);
  const s = sig.slice(32, 64);
  const sigSeq = makeDERSequence(concat(encodeDERIntegerBytes(r), encodeDERIntegerBytes(s)));
  const sigBits = makeDERBitString(sigSeq);

  return makeDERSequence(concat(tbs, sigAlg, sigBits));
}

// ===========================================================================
// CBOR encoder — just enough for attestation object
// ===========================================================================

function encodeCBOR(value: unknown): Uint8Array {
  if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    return concat(new Uint8Array([0x60 | Math.min(bytes.length, 23)]),
      bytes.length >= 24 ? encodeCBORLength(bytes.length) : new Uint8Array(0), bytes);
  }
  if (value instanceof Uint8Array) {
    return concat(new Uint8Array([0x40 | Math.min(value.length, 23)]),
      value.length >= 24 ? encodeCBORLength(value.length) : new Uint8Array(0), value);
  }
  if (Array.isArray(value)) {
    const head = new Uint8Array([0x80 | Math.min(value.length, 23)]);
    const len = value.length >= 24 ? encodeCBORLength(value.length) : new Uint8Array(0);
    const parts = [head, len];
    for (const item of value) parts.push(encodeCBOR(item));
    return concat(...parts);
  }
  if (value instanceof Map) {
    const size = value.size;
    const head = new Uint8Array([0xA0 | Math.min(size, 23)]);
    const len = size >= 24 ? encodeCBORLength(size) : new Uint8Array(0);
    const parts = [head, len];
    for (const [k, v] of value) { parts.push(encodeCBOR(k), encodeCBOR(v)); }
    return concat(...parts);
  }
  throw new AppAttestError(`CBOR: unsupported type ${typeof value}`);
}

function encodeCBORLength(n: number): Uint8Array {
  if (n < 24) return new Uint8Array();
  if (n < 0x100) return new Uint8Array([24, n]);
  if (n < 0x10000) return new Uint8Array([25, (n >> 8) & 0xff, n & 0xff]);
  throw new AppAttestError(`CBOR length too large: ${n}`);
}

// ===========================================================================
// AppAttestService factory (software keys)
// ===========================================================================

export function createAppAttestService(opts: AppAttestNoneOpts = {}): AppAttestService {
  const store: KeychainStore = opts.keychain ?? createFilesystemKeychainStore({ storageDir: opts.storageDir, logger: opts.logger });
  const logger = opts.logger;

  async function loadKeyPair(keyId: string): Promise<CryptoKeyPair> {
    const jwkStr = store.load(`key:${keyId}`);
    if (!jwkStr) throw new AppAttestError(`Key not found: ${keyId}`);
    const jwk = JSON.parse(jwkStr);
    const privateKey = await crypto.subtle.importKey(
      "jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"],
    );
    const { d, ...pubJwk } = jwk;
    pubJwk.key_ops = ["verify"];
    const publicKey = await crypto.subtle.importKey(
      "jwk", pubJwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"],
    );
    return { privateKey, publicKey };
  }

  return {
    isSupported(): boolean {
      return true;
    },

    async generateKey(): Promise<string> {
      const keyId = `soft-${crypto.randomUUID()}`;
      const keyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"],
      );
      const jwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
      await store.save(`key:${keyId}`, JSON.stringify(jwk));

      // Pre-build attestation cert and cache it
      const spki = new Uint8Array(await crypto.subtle.exportKey("spki", keyPair.publicKey));
      const certDer = await buildSelfSignedCert(spki, keyPair.privateKey);
      const hex = Array.from(certDer, (b) => b.toString(16).padStart(2, "0")).join("");
      await store.save(`attest:${keyId}`, hex);

      logger?.info("software key generated and attested", { keyId });
      return keyId;
    },

    async attestKey(keyId: string, _challengeHash: Uint8Array): Promise<Uint8Array> {
      let attestHex = store.load(`attest:${keyId}`);
      if (!attestHex) {
        const jwkStr = store.load(`key:${keyId}`);
        if (!jwkStr) throw new AppAttestError(`Key not found: ${keyId}`);
        const keys = await loadKeyPair(keyId);
        const spki = new Uint8Array(await crypto.subtle.exportKey("spki", keys.publicKey));
        const certDer = await buildSelfSignedCert(spki, keys.privateKey);
        attestHex = Array.from(certDer, (b) => b.toString(16).padStart(2, "0")).join("");
        await store.save(`attest:${keyId}`, attestHex);
      }

      const certDer = new Uint8Array(attestHex.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)));

      const attStmt = new Map<string, unknown>([
        ["x5c", [certDer]],
        ["receipt", new Uint8Array(0)],
      ]);
      const attestation = new Map<string, unknown>([
        ["fmt", "apple-appattest"],
        ["attStmt", attStmt],
        ["authData", new Uint8Array(0)],
      ]);

      return encodeCBOR(attestation);
    },

    async generateAssertion(keyId: string, clientDataHash: Uint8Array): Promise<Uint8Array> {
      const keys = await loadKeyPair(keyId);
      const sig = new Uint8Array(await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" }, keys.privateKey, clientDataHash,
      ));
      const assertion = new Map<string, unknown>([
        ["signature", sig],
        ["authenticatorData", new Uint8Array(0)],
      ]);
      return encodeCBOR(assertion);
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
