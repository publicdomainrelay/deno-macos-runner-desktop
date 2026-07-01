// Persistent secp256k1 keypair for market bidder identity.
// Stored in macOS Keychain via the existing keychain FFI bridge.
// The same key serves triple duty:
//  1. AttestationKeypair (badge.blue inline signatures)
//  2. XRPC relay keypair (dispatcher registration)
//  3. signer for signServiceAuth (callService)

import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { base58btcEncode } from "@publicdomainrelay/badge-blue-keys-common";
import type { KeychainStore } from "@publicdomainrelay/app-attest-abc";

const KC_MARKET_SIGNER_KEY = "market-signer-key";

const SECP256K1_MULTICODEC = new Uint8Array([0xe7, 0x01]);

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function compressPublicKey(uncompressed: Uint8Array): Uint8Array {
  const x = uncompressed.slice(1, 33);
  const y = uncompressed.slice(33, 65);
  const prefix = y[y.length - 1] % 2 === 0 ? 0x02 : 0x03;
  const out = new Uint8Array(33);
  out[0] = prefix;
  out.set(x, 1);
  return out;
}

function didFromPublicKey(publicKey: Uint8Array): string {
  const prefixed = new Uint8Array(SECP256K1_MULTICODEC.length + publicKey.length);
  prefixed.set(SECP256K1_MULTICODEC, 0);
  prefixed.set(publicKey, SECP256K1_MULTICODEC.length);
  return `did:key:z${base58btcEncode(prefixed)}`;
}

export interface MarketKeypair {
  did(): string;
  sign(bytes: Uint8Array): Promise<Uint8Array>;
  exportHex(): string;
}

class Secp256k1Keypair implements MarketKeypair {
  private constructor(private privateKey: Uint8Array, private publicKey: Uint8Array) {}

  static async create(): Promise<Secp256k1Keypair> {
    const priv = secp256k1.utils.randomPrivateKey();
    const pub = secp256k1.getPublicKey(priv, false);
    return new Secp256k1Keypair(priv, pub);
  }

  static import(privateKeyHex: string): Secp256k1Keypair {
    const priv = fromHex(privateKeyHex);
    const pub = secp256k1.getPublicKey(priv, false);
    return new Secp256k1Keypair(priv, pub);
  }

  did(): string {
    return didFromPublicKey(compressPublicKey(this.publicKey));
  }

  async sign(bytes: Uint8Array): Promise<Uint8Array> {
    const hash = sha256(bytes);
    const sig = secp256k1.sign(hash, this.privateKey, { lowS: true });
    return sig.toCompactRawBytes();
  }

  exportHex(): string {
    return toHex(this.privateKey);
  }
}

export async function loadOrCreateMarketKeypair(
  keychain: KeychainStore,
): Promise<{ keypair: MarketKeypair; hex: string }> {
  const existing = keychain.load(KC_MARKET_SIGNER_KEY);
  if (existing) {
    const keypair = Secp256k1Keypair.import(existing);
    return { keypair, hex: existing };
  }
  const keypair = await Secp256k1Keypair.create();
  const hex = keypair.exportHex();
  const saved = await keychain.save(KC_MARKET_SIGNER_KEY, hex);
  if (!saved) throw new Error("Failed to save market signer key to Keychain");
  return { keypair, hex };
}

export async function deleteMarketKeypair(keychain: KeychainStore): Promise<void> {
  keychain.delete(KC_MARKET_SIGNER_KEY);
}
