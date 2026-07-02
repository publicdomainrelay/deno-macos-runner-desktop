// BadgeBlue Keys common types and constants.
// Portable — zero I/O. Used by badge-blue-keys-atproto (record creation).

/** ATProto Lexicon NSID for badgeBlueKeys records. */
export const BADGE_BLUE_KEYS_NSID = "com.publicdomainrelay.temp.badgeBlueKeys";

/** Wire-format record shape. */
export interface BadgeBlueKeysRecord {
  $type: string;
  keyId: string;
  challenge: string; // DID the key is bound to
  service: string;
  createdAt: string;
}

/**
 * Minimal session fields needed by badge-blue-keys operations.
 * Defined here (not imported from atproto-oauth) to avoid cross-concept deps.
 * The CLI bridges OAuthSession → BadgeBlueKeysSession at the call site.
 */
export interface BadgeBlueKeysSession {
  did: string;
  pds: string;
  accessJwt: string;
  dpopKeyPair: CryptoKeyPair;
  dpopPublicJwk: Record<string, string>;
}

// ===========================================================================
// Base58btc encoder (Bitcoin alphabet). Not cryptography — just an encoding.
// Used for deterministic rkey derivation in badge-blue-keys-atproto.
// ===========================================================================

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58btcEncode(bytes: Uint8Array): string {
  let z = 0;
  while (z < bytes.length && bytes[z] === 0) z++;
  let n = 0n;
  for (let i = 0; i < bytes.length; i++) n = (n << 8n) | BigInt(bytes[i]);
  let s = "";
  while (n > 0n) {
    s = B58[Number(n % 58n)] + s;
    n = n / 58n;
  }
  return "1".repeat(z) + s;
}
