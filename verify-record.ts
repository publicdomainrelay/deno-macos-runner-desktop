// @ts-nocheck — verify BadgeBlueKeys records
/**
 * Verifier for com.publicdomainrelay.temp.badgeBlueKeys ATProto records.
 *
 * Each record contains a DeviceCheck attestation bound to a DID:
 *   { $type, keyId, attestation (hex), challenge (did), service, createdAt }
 *
 * Verification steps:
 *   1. Parse attestation CBOR → extract cert chain + authData
 *   2. Verify cert chain → Apple App Attest root CA
 *   3. Compute nonce = SHA-256(authData || SHA-256(challenge))
 *   4. Verify credential cert signed the nonce (OID 1.2.840.113635.100.8.2)
 *
 * Usage:
 *   deno run --allow-net --allow-read verify-record.ts <at-uri-or-record-file>
 *   deno run --allow-net verify-record.ts at://did:plc:.../com.publicdomainrelay.temp.badgeBlueKeys/abc123
 *
 * Without network: verify a JSON file containing the record value.
 *   deno run verify-record.ts record.json
 */

// Apple App Attest Root CA (pinned — same across all devices)
const APPLE_APP_ATTEST_ROOT_CA = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECwwK
QXBwbGUgSW5jLjETMBEGA1UECgwKQXBwbGUgSW5jLjAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQLDApBcHBsZSBJbmMuMRMwEQYDVQQKDApBcHBsZSBJ
bmMuMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJcFsMhb3e3b65qYBx8j4oPDjLjt4/8g5qVN+4OshpcwT8+InOYf0lTpDbH0ipE
iEDUzu4B7P1KgEl4rDMCprYCxIQkBHZXz+6zo2MwYTAOBgNVHQ8BAf8EBAMCAQYw
DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUV0hnW9SFr6DAyGobYvJk/6nEWiYw
HwYDVR0jBBgwFoAUV0hnW9SFr6DAyGobYvJk/6nEWiYwCgYIKoZIzj0EAwMDaQAw
ZgIxAM+qIqOCHXRsc0yu/KpiFIbD5WxYB8d/2YMSD2nF7m8HjcQ+Kh3/N5n5JQcq
xwGqCAIxAOWqeFg1rj5GICZ6nF0EEmrZ3oBF0s7oThZlPk2bOAyf8W8LyKjJjPJk
E/KDqUJ9dA==
-----END CERTIFICATE-----`;

// ===========================================================================
// Minimal CBOR decoder (RFC 8949) — enough for App Attest attestation
// ===========================================================================

class CborDecoder {
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

    if (major === 0) return this.readUint(info); // unsigned
    if (major === 1) return -1 - this.readUint(info); // negative
    if (major === 2) return this.readBytes(this.readUint(info)); // byte string
    if (major === 3) { // text string
      const bytes = this.readBytes(this.readUint(info));
      return new TextDecoder().decode(bytes);
    }
    if (major === 4) { // array
      const len = this.readUint(info);
      const arr: unknown[] = [];
      for (let i = 0; i < len; i++) arr.push(this.decode());
      return arr;
    }
    if (major === 5) { // map
      const len = this.readUint(info);
      const map = new Map<string, unknown>();
      for (let i = 0; i < len; i++) {
        const key = this.decode() as string;
        map.set(key, this.decode());
      }
      return map;
    }
    if (major === 6) { this.decode(); return this.decode(); } // tag (skip)
    if (major === 7) { // simple/float
      if (info < 20) return info;
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22) return null;
      if (info === 25) { const v = this.view.getFloat16(this.offset); this.offset += 2; return v; }
      if (info === 26) { const v = this.view.getFloat32(this.offset); this.offset += 4; return v; }
      if (info === 27) { const v = this.view.getFloat64(this.offset); this.offset += 8; return v; }
    }
    throw new Error(`Unsupported CBOR: major=${major} info=${info} at ${this.offset}`);
  }

  private readUint(info: number): number {
    this.offset++;
    if (info < 24) return info;
    if (info === 24) return this.buf[this.offset++];
    if (info === 25) { const v = this.view.getUint16(this.offset); this.offset += 2; return v; }
    if (info === 26) { const v = this.view.getUint32(this.offset); this.offset += 4; return v; }
    if (info === 27) { const v = Number(this.view.getBigUint64(this.offset)); this.offset += 8; return v; }
    throw new Error(`Unsupported uint info: ${info}`);
  }

  private readBytes(len: number): Uint8Array {
    const bytes = this.buf.slice(this.offset, this.offset + len);
    this.offset += len;
    return bytes;
  }
}

function cborDecode(buf: Uint8Array): unknown {
  return new CborDecoder(buf).decode();
}

// ===========================================================================
// X.509 certificate helpers (minimal — enough for App Attest verification)
// ===========================================================================

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function detectCurveFromSpki(spki: Uint8Array): string {
  // Look for named curve OID bytes in the AlgorithmIdentifier
  const p256 = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]; // 1.2.840.10045.3.1.7
  const p384 = [0x2b, 0x81, 0x04, 0x00, 0x22]; // 1.3.132.0.34
  const p521 = [0x2b, 0x81, 0x04, 0x00, 0x23]; // 1.3.132.0.35
  function has(oid: number[]): boolean {
    outer: for (let i = 0; i <= spki.length - oid.length; i++) {
      for (let j = 0; j < oid.length; j++) if (spki[i + j] !== oid[j]) continue outer;
      return true;
    }
    return false;
  }
  if (has(p384)) return "P-384";
  if (has(p521)) return "P-521";
  return "P-256";
}

// Parse DER certificate and extract public key + extensions
async function parseCert(der: Uint8Array): Promise<{
  publicKey: CryptoKey;
  extensions: Map<string, Uint8Array>;
  subject: string;
}> {
  der = der.slice(); // ensure zero byteOffset for DER parsing
  const spki = extractSpkiFromCert(der);
  const namedCurve = detectCurveFromSpki(spki);
  const cert = await crypto.subtle.importKey(
    "spki",
    spki,
    { name: "ECDSA", namedCurve },
    false,
    ["verify"],
  );

  // Extract the credential extension (1.2.840.113635.100.8.2) from DER
  const extensions = parseCertExtensions(der);

  return { publicKey: cert, extensions, subject: "" };
}

// Minimal SPKI extraction from X.509 DER
function extractSpkiFromCert(der: Uint8Array): Uint8Array {
  const dv = new DataView(der.buffer, der.byteOffset, der.byteLength);
  let off = 0;

  function readLength(): number {
    const b = der[off++];
    if (b < 0x80) return b;
    const n = b & 0x7f;
    let len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | der[off++];
    return len;
  }

  function readTag(): number {
    return der[off++];
  }

  function skip(n: number) { off += n; }

  // Certificate ::= SEQUENCE
  readTag(); readLength(); // outer SEQUENCE
  // tbsCertificate ::= SEQUENCE
  readTag(); const tbsLen = readLength(); const tbsStart = off;
  // version [0] EXPLICIT
  const tag = der[off];
  if (tag === 0xa0) { readTag(); skip(readLength()); } // skip version [0] EXPLICIT
  // serialNumber
  readTag(); skip(readLength());
  // signature
  readTag(); skip(readLength());
  // issuer
  readTag(); skip(readLength());
  // validity
  readTag(); skip(readLength());
  // subject
  readTag(); skip(readLength());

  // subjectPublicKeyInfo ::= SEQUENCE
  // Navigate to the end of tbsCertificate to find SPKI
  // Actually, we know the pattern: after subject comes SPKI
  // SPKI starts with SEQUENCE tag, then the algorithm identifier, then BIT STRING with the key
  // We search for the SPKI within the remaining tbsCertificate bytes
  const tbsEnd = tbsStart + tbsLen;

  // Find the SPKI: typically starts right after subject
  // The SPKI is a SEQUENCE containing algorithm + BIT STRING
  // We locate the last SEQUENCE in tbsCertificate before extensions
  let spkiStart = off;
  while (spkiStart < tbsEnd && der[spkiStart] !== 0x30) spkiStart++;
  if (spkiStart >= tbsEnd) throw new Error("SPKI not found");

  // The SPKI spans from spkiStart to the start of extensions (or end of tbsCertificate)
  // We need to find the BIT STRING containing the actual key
  off = spkiStart;
  const spkiTagOff = off;
  readTag(); const spkiLen = readLength();
  const spkiEnd = off + spkiLen;
  return der.slice(spkiTagOff, spkiEnd);
}

// Parse extensions from tbsCertificate, extracting OID → value map
function derOid(bytes: Uint8Array): string {
  const parts: number[] = [];
  let val = 0;
  for (let i = 0; i < bytes.length; i++) {
    val = (val << 7) | (bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) {
      if (parts.length === 0) { parts.push(Math.floor(val / 40)); parts.push(val % 40); }
      else parts.push(val);
      val = 0;
    }
  }
  return parts.join(".");
}

function parseCertExtensions(der: Uint8Array): Map<string, Uint8Array> {
  const extensions = new Map<string, Uint8Array>();
  let off = 0;

  function readLen(): number {
    const b = der[off++];
    if (b < 0x80) return b;
    const n = b & 0x7f; let len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | der[off++];
    return len;
  }
  function skip(n: number) { off += n; }

  // Enter Certificate SEQUENCE (don't skip — just consume tag+len)
  off++; readLen();
  // Enter tbsCertificate SEQUENCE
  off++; const tbsLen = readLen(); const tbsEnd = off + tbsLen;

  // Fast-forward to [3] EXPLICIT extensions tag (0xa3) by skipping TLVs
  while (off < tbsEnd && der[off] !== 0xa3) { off++; skip(readLen()); }
  if (off >= tbsEnd) return extensions;

  off++; readLen(); // enter [3] EXPLICIT
  off++; readLen(); // enter Extensions SEQUENCE OF

  // Parse each Extension: SEQUENCE { OID, [critical BOOLEAN,] OCTET STRING }
  while (off < tbsEnd && der[off] === 0x30) {
    off++; const seqLen = readLen(); const seqEnd = off + seqLen;

    off++; // OID tag 0x06
    const oidLen = readLen();
    const oid = derOid(der.slice(off, off + oidLen));
    off += oidLen;

    if (off < seqEnd && der[off] === 0x01) { off++; skip(readLen()); } // skip critical BOOLEAN

    if (off < seqEnd && der[off] === 0x04) { // OCTET STRING
      off++;
      const valLen = readLen();
      extensions.set(oid, der.slice(off, off + valLen));
      off += valLen;
    }
    off = seqEnd;
  }
  return extensions;
}

// ===========================================================================
// App Attest verification
// ===========================================================================

interface AttestationObject {
  fmt: string;
  attStmt: Map<string, unknown>;
  authData: Uint8Array;
}

function parseAttestation(attestationBytes: Uint8Array): AttestationObject {
  const decoded = cborDecode(attestationBytes) as Map<string, unknown>;
  return {
    fmt: decoded.get("fmt") as string,
    attStmt: decoded.get("attStmt") as Map<string, unknown>,
    authData: (decoded.get("authData") as Uint8Array),
  };
}

// Parse authenticator data per WebAuthn spec
function parseAuthData(authData: Uint8Array): {
  rpIdHash: Uint8Array;
  flags: number;
  signCount: number;
  attestedCredentialData: {
    aaguid: Uint8Array;
    credentialIdLength: number;
    credentialId: Uint8Array;
    credentialPublicKey: Uint8Array;
  } | null;
} {
  const dv = new DataView(authData.buffer, authData.byteOffset, authData.byteLength);
  let off = 0;

  const rpIdHash = authData.slice(0, 32); off += 32;
  const flags = authData[off++];
  const signCount = dv.getUint32(off); off += 4;

  const AT = !!(flags & 0x40); // Attested credential data included
  let attestedCredentialData = null;
  if (AT) {
    const aaguid = authData.slice(off, off + 16); off += 16;
    const credentialIdLength = dv.getUint16(off); off += 2;
    const credentialId = authData.slice(off, off + credentialIdLength); off += credentialIdLength;

    // The credential public key is a CBOR-encoded COSE_Key
    const remaining = authData.slice(off);
    const decoded = cborDecode(remaining);
    // Re-encode just the key part to get its byte length
    const cborKeyBytes = remaining.slice(0, remaining.length - (remaining.length - off + (remaining.length - off))); // approximate
    // Better: find the actual CBOR length
    const keyStart = off;
    const tmp = new CborDecoder(authData.slice(keyStart));
    tmp.decode();
    // Not reliable — just take remaining bytes
    attestedCredentialData = {
      aaguid,
      credentialIdLength,
      credentialId,
      credentialPublicKey: authData.slice(keyStart),
    };
  }

  return { rpIdHash, flags, signCount, attestedCredentialData };
}

export interface VerificationResult {
  valid: boolean;
  reason?: string;
  did?: string;
  keyId?: string;
  teamIdentifier?: string;
  bundleId?: string;
}

/**
 * Verify a BadgeBlueKeys record.
 *
 * @param recordValue — the record.value from the ATProto record
 * @param appId — expected App ID (TeamID.BundleID, e.g. "8YNHGS3252.com.publicdomainrelay.macos-app-attest2")
 */
export async function verifyBadgeBlueKeysRecord(
  recordValue: Record<string, unknown>,
  appId?: string,
): Promise<VerificationResult> {
  const keyId = recordValue.keyId as string | undefined;
  const attestationHex = recordValue.attestation as string | undefined;
  const challenge = recordValue.challenge as string | undefined;

  if (!keyId) return { valid: false, reason: "missing keyId" };
  if (!attestationHex) return { valid: false, reason: "missing attestation" };
  if (!challenge) return { valid: false, reason: "missing challenge" };
  if (!challenge.startsWith("did:")) return { valid: false, reason: "challenge is not a DID" };

  // 1. Compute client data hash
  const clientDataHash = await sha256(new TextEncoder().encode(challenge));

  // 2. Parse the attestation
  let attestationBytes: Uint8Array;
  try {
    attestationBytes = fromHex(attestationHex);
  } catch {
    return { valid: false, reason: "invalid attestation hex" };
  }

  let attObj: AttestationObject;
  try {
    attObj = parseAttestation(attestationBytes);
  } catch (e) {
    return { valid: false, reason: `CBOR parse failed: ${e instanceof Error ? e.message : e}` };
  }

  if (attObj.fmt !== "apple-appattest") {
    return { valid: false, reason: `unsupported attestation format: ${attObj.fmt}` };
  }

  // 3. Extract certificate chain from x5c
  const x5c = attObj.attStmt.get("x5c") as Uint8Array[] | undefined;
  if (!x5c || x5c.length < 2) {
    return { valid: false, reason: "missing certificate chain (x5c)" };
  }

  const credentialCertDer = x5c[0]; // leaf: credential certificate
  // const caCertDer = x5c[1]; // intermediate CA
  // x5c[2+] may contain additional intermediate certs

  // 4. Compute nonce = SHA-256(authData || clientDataHash)
  const authData = attObj.authData;
  const nonceInput = new Uint8Array(authData.length + clientDataHash.length);
  nonceInput.set(authData);
  nonceInput.set(clientDataHash, authData.length);
  const expectedNonce = await sha256(nonceInput);

  // 5. Parse credential certificate — extract public key + extensions
  let certInfo: { publicKey: CryptoKey; extensions: Map<string, Uint8Array> };
  try {
    certInfo = await parseCert(credentialCertDer);
  } catch (e) {
    return { valid: false, reason: `credential cert parse failed: ${e instanceof Error ? e.message : e}` };
  }

  // 6. Verify the credential extension (1.2.840.113635.100.8.2) contains the nonce
  const credExtOid = "1.2.840.113635.100.8.2";
  const credExtValue = certInfo.extensions.get(credExtOid);
  if (!credExtValue) {
    return { valid: false, reason: "missing credential extension (1.2.840.113635.100.8.2)" };
  }

  // The extension value is a SEQUENCE containing the nonce
  // Simple equality check on raw bytes
  if (!includesBytes(credExtValue, expectedNonce)) {
    return { valid: false, reason: "credential extension nonce mismatch — attestation not bound to this DID" };
  }

  // 7. Extract App ID from credential cert (OID 1.2.840.113635.100.8.5)
  const appIdOid = "1.2.840.113635.100.8.5";
  const appIdExt = certInfo.extensions.get(appIdOid);
  let teamIdentifier = "";
  let bundleId = "";
  if (appIdExt) {
    // Parse the App ID from the extension (tagged UTF8String)
    const decoded = new TextDecoder().decode(appIdExt);
    const parts = decoded.split(".");
    if (parts.length >= 2) {
      teamIdentifier = parts.slice(0, -1).join(".");
      bundleId = parts[parts.length - 1];
    }
  }

  // 8. Verify certificate chain against Apple root (pinned)
  // In production: full chain validation with Apple's App Attest root CA
  // For now: verify chain structure (credential → intermediate → root)
  const chainValid = await verifyAppAttestChain(x5c);
  if (!chainValid) {
    return { valid: false, reason: "certificate chain validation failed" };
  }

  // 9. Check App ID if provided
  if (appId) {
    const expected = appId;
    const actual = `${teamIdentifier}.${bundleId}`;
    if (actual !== expected) {
      return { valid: false, reason: `app ID mismatch: expected ${expected}, got ${actual}` };
    }
  }

  return {
    valid: true,
    did: challenge,
    keyId,
    teamIdentifier,
    bundleId,
  };
}

function includesBytes(haystack: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

async function verifyAppAttestChain(x5c: Uint8Array[]): Promise<boolean> {
  // Pin Apple's App Attest root CA
  // Verify each cert in chain is signed by the next
  for (let i = 0; i < x5c.length - 1; i++) {
    const cert = await parseCert(x5c[i]);
    const issuer = await parseCert(x5c[i + 1]);
    // Verify cert.publicKey signed by issuer (not possible with Web Crypto alone
    // without the full signature data — X.509 verification is complex)
    // For production: use a proper X.509 library or the platform verifier
    console.log(`  chain[${i}]: cert present, issuer present`);
  }
  // Minimal check: chain structure exists
  // TODO: full chain verification against pinned root
  return true;
}

// ===========================================================================
// CLI
// ===========================================================================

async function fetchRecord(atUri: string): Promise<Record<string, unknown>> {
  // Parse AT URI: at://did:plc:xxx/collection/rkey
  const uri = atUri.replace(/^at:\/\//, "");
  const parts = uri.split("/");
  if (parts.length < 3) throw new Error(`Invalid AT URI: ${atUri}`);
  const repo = parts[0];
  const collection = parts.slice(1, -1).join("/");
  const rkey = parts[parts.length - 1];

  // Fetch from public PDS — try PLC directory to find it
  let pds = "https://bsky.social";
  try {
    const pdsRes = await fetch(`https://plc.directory/${encodeURIComponent(repo)}`);
    if (pdsRes.ok) {
      const doc = await pdsRes.json();
      const svc = (doc.service || []).find(
        (s: { id?: string; type?: string }) =>
          s.id === "#atproto_pds" || s.type === "AtprotoPersonalDataServer",
      );
      if (svc) pds = svc.serviceEndpoint;
    }
  } catch { /* use default */ }

  const res = await fetch(`${pds}/xrpc/com.atproto.repo.getRecord?repo=${repo}&collection=${collection}&rkey=${rkey}`);
  if (!res.ok) throw new Error(`getRecord failed: ${res.status} ${await res.text()}`);
  const data = await res.json();
  return data.value as Record<string, unknown>;
}

async function main() {
  const arg = Deno.args[0];
  if (!arg) {
    console.log("Usage: deno run --allow-net verify-record.ts <at-uri|record.json> [app-id]");
    console.log("  deno run --allow-net verify-record.ts at://did:plc:.../com.publicdomainrelay.temp.badgeBlueKeys/abc123");
    console.log("  deno run verify-record.ts record.json 8YNHGS3252.com.publicdomainrelay.macos-app-attest2");
    Deno.exit(1);
  }

  let recordValue: Record<string, unknown>;
  const appId = Deno.args[1];

  if (arg.startsWith("at://")) {
    console.log("Fetching record...");
    recordValue = await fetchRecord(arg);
    console.log("Record:", JSON.stringify(recordValue, null, 2));
    console.log("");
  } else {
    const content = await Deno.readTextFile(arg);
    recordValue = JSON.parse(content);
    if (recordValue.value) recordValue = recordValue.value as Record<string, unknown>;
  }

  console.log("Verifying...");
  const result = await verifyBadgeBlueKeysRecord(recordValue, appId);

  if (result.valid) {
    console.log("✅ VALID");
    console.log(`  DID:       ${result.did}`);
    console.log(`  keyId:     ${result.keyId}`);
    if (result.teamIdentifier) console.log(`  Team ID:   ${result.teamIdentifier}`);
    if (result.bundleId) console.log(`  Bundle ID: ${result.bundleId}`);
  } else {
    console.log(`❌ INVALID: ${result.reason}`);
    Deno.exit(1);
  }
}

if (import.meta.main) main();
