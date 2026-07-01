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

import { CborDecoder } from "@publicdomainrelay/badge-blue-keys-common";

function cborDecode(buf: Uint8Array): unknown {
  return new CborDecoder(buf).decode();
}

// ===========================================================================
// X.509 certificate helpers — real chain/signature verification via
// @peculiar/x509 (replaces the old hand-rolled DER walker, which never
// checked signatures and made verifyAppAttestChain a no-op stub).
// ===========================================================================

import { cryptoProvider, X509Certificate } from "@peculiar/x509";

cryptoProvider.set(crypto);

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

function pemToDer(pem: string): Uint8Array {
  const b64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/, "")
    .replace(/-----END CERTIFICATE-----/, "")
    .replace(/\s+/g, "");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

const APPLE_ROOT_CERT = new X509Certificate(pemToDer(APPLE_APP_ATTEST_ROOT_CA));

// Parse DER certificate and extract extensions (OID → raw extnValue bytes,
// matching the previous Map<string, Uint8Array> shape callers expect).
function parseCert(der: Uint8Array): {
  cert: X509Certificate;
  extensions: Map<string, Uint8Array>;
} {
  const cert = new X509Certificate(der.slice());
  const extensions = new Map<string, Uint8Array>();
  for (const ext of cert.extensions) {
    extensions.set(ext.type, new Uint8Array(ext.value));
  }
  return { cert, extensions };
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
  let certInfo: { cert: X509Certificate; extensions: Map<string, Uint8Array> };
  try {
    certInfo = parseCert(credentialCertDer);
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

  // 8. Verify certificate chain against Apple root (pinned) — real
  // signature + expiry checks, chain must terminate at APPLE_ROOT_CERT.
  const chainResult = await verifyAppAttestChain(x5c);
  if (!chainResult.valid) {
    return { valid: false, reason: `certificate chain validation failed: ${chainResult.reason}` };
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

async function verifyAppAttestChain(
  x5c: Uint8Array[],
): Promise<{ valid: boolean; reason?: string }> {
  if (x5c.length < 2) return { valid: false, reason: "chain too short (need leaf + intermediate)" };

  const certs = x5c.map((der) => parseCert(der).cert);
  const now = new Date();
  for (const c of certs) {
    if (now < c.notBefore || now > c.notAfter) {
      return { valid: false, reason: `certificate expired or not yet valid (subject: ${c.subject})` };
    }
  }

  // Walk leaf -> intermediate(s), each signed by the next cert's key.
  for (let i = 0; i < certs.length - 1; i++) {
    const signedByNext = await certs[i].verify({ publicKey: certs[i + 1].publicKey, signatureOnly: true });
    if (!signedByNext) {
      return { valid: false, reason: `chain[${i}] signature not issued by chain[${i + 1}]` };
    }
  }

  // Final intermediate must be signed by Apple's pinned App Attest root.
  const last = certs[certs.length - 1];
  const signedByRoot = await last.verify({ publicKey: APPLE_ROOT_CERT.publicKey, signatureOnly: true });
  if (!signedByRoot) {
    return { valid: false, reason: "chain does not terminate at pinned Apple App Attest root CA" };
  }

  return { valid: true };
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
