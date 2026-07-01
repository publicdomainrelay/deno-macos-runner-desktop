// BadgeBlue Keys common types, constants, and pure parsing helpers.
// Portable — zero I/O. Used by both badge-blue-keys-atproto (record creation)
// and verify-record.ts (standalone verification).

/** ATProto Lexicon NSID for badgeBlueKeys records. */
export const BADGE_BLUE_KEYS_NSID = "com.publicdomainrelay.temp.badgeBlueKeys";

/** Wire-format record shape. */
export interface BadgeBlueKeysRecord {
  $type: string;
  keyId: string;
  attestation: string; // hex-encoded CBOR attestation object
  challenge: string; // DID the attestation is bound to
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
// Minimal CBOR decoder (RFC 8949) — enough for App Attest attestation objects.
// ===========================================================================

export class CborDecoder {
  private view: DataView;
  private offset: number;

  constructor(private buf: Uint8Array) {
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    this.offset = 0;
  }

  decode(): unknown {
    if (this.offset >= this.buf.length) return undefined;
    const byte = this.buf[this.offset];
    const major = byte >> 5;
    const info = byte & 0x1f;
    if (major === 0) return this.readUint(info);
    if (major === 1) return -1 - this.readUint(info);
    if (major === 2) return this.readBytes(this.readUint(info));
    if (major === 3) {
      const bytes = this.readBytes(this.readUint(info));
      return new TextDecoder().decode(bytes);
    }
    if (major === 4) {
      const len = this.readUint(info);
      const arr: unknown[] = [];
      for (let i = 0; i < len; i++) arr.push(this.decode());
      return arr;
    }
    if (major === 5) {
      const len = this.readUint(info);
      const map = new Map<string, unknown>();
      for (let i = 0; i < len; i++) {
        const key = this.decode() as string;
        map.set(key, this.decode());
      }
      return map;
    }
    if (major === 6) {
      this.decode();
      return this.decode();
    }
    if (major === 7) {
      if (info < 20) return info;
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22) return null;
      if (info === 25) {
        const v = this.view.getFloat16(this.offset);
        this.offset += 2;
        return v;
      }
      if (info === 26) {
        const v = this.view.getFloat32(this.offset);
        this.offset += 4;
        return v;
      }
      if (info === 27) {
        const v = this.view.getFloat64(this.offset);
        this.offset += 8;
        return v;
      }
    }
    throw new Error(`CBOR: major=${major} info=${info} at ${this.offset}`);
  }

  private readUint(info: number): number {
    this.offset++;
    if (info < 24) return info;
    if (info === 24) return this.buf[this.offset++];
    if (info === 25) {
      const v = this.view.getUint16(this.offset);
      this.offset += 2;
      return v;
    }
    if (info === 26) {
      const v = this.view.getUint32(this.offset);
      this.offset += 4;
      return v;
    }
    if (info === 27) {
      const v = Number(this.view.getBigUint64(this.offset));
      this.offset += 8;
      return v;
    }
    throw new Error(`CBOR uint info=${info}`);
  }

  private readBytes(len: number): Uint8Array {
    const bytes = this.buf.slice(this.offset, this.offset + len);
    this.offset += len;
    return bytes;
  }
}

// ===========================================================================
// Attestation parsing helpers — pure functions, no I/O
// ===========================================================================

/** Extract the leaf certificate (x5c[0]) from a CBOR attestation object. */
export function extractX5c0(attestationBytes: Uint8Array): Uint8Array {
  const decoded = new CborDecoder(attestationBytes).decode() as Map<string, unknown>;
  const attStmt = decoded.get("attStmt") as Map<string, unknown>;
  const x5c = attStmt.get("x5c") as Uint8Array[];
  if (!x5c || x5c.length < 1) throw new Error("x5c not found in attestation");
  return x5c[0];
}

// Base58btc encoder (Bitcoin alphabet). Not cryptography — just an encoding.
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

/**
 * Extract SubjectPublicKeyInfo from a DER-encoded X.509 certificate.
 * Navigates ASN.1 TLV structure past outer SEQUENCE → tbsCertificate
 * → version/serial/signature/issuer/validity/subject → reads SPKI.
 */
export function extractSpkiDer(certDer: Uint8Array): Uint8Array {
  const b = certDer;
  let off = 0;

  function readLen(): number {
    const byte = b[off++];
    if (byte < 0x80) return byte;
    const n = byte & 0x7f;
    let len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | b[off++];
    return len;
  }

  function skipTLVvalue() {
    off++;
    const l = readLen();
    off += l;
  }

  // Certificate ::= SEQUENCE
  off++;
  readLen();
  // tbsCertificate ::= SEQUENCE
  off++;
  readLen();
  // version [0] EXPLICIT (optional, tag 0xA0)
  if (b[off] === 0xA0) skipTLVvalue();
  // serialNumber, signature, issuer, validity: skip 4 TLVs
  for (let i = 0; i < 4; i++) skipTLVvalue();
  // subject: skip
  skipTLVvalue();
  // subjectPublicKeyInfo ::= SEQUENCE
  const spkiStart = off;
  off++;
  const spkiLen = readLen();
  return b.slice(spkiStart, off + spkiLen);
}
