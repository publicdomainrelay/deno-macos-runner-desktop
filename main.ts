// @ts-nocheck — FFI + deno desktop runtime APIs not in compile-time types
import { TRAY_ICON_BASE64 } from "./icon.ts";

// =========================================================================
// 0. Structured JSON logger — delegates to @publicdomainrelay/logger.
//    LOG_RING (last 500 entries) stays for the in-app UI log viewer.
// =========================================================================

import { createStructuredLogger } from "@publicdomainrelay/logger";

// Common types + helpers extracted into ABC-layered packages.
import {
  AppAttestError, encodeCStr, readCStr, allocSizeT, readSizeT,
  KC_SESSION_KEY, KC_DEVICE_KEY_ID,
} from "@publicdomainrelay/app-attest-common";
import type { OAuthSession } from "@publicdomainrelay/atproto-oauth-common";
import {
  OAUTH_CLIENT_ID_DEFAULT, OAUTH_REDIRECT_URI_DEFAULT,
} from "@publicdomainrelay/atproto-oauth-common";
import {
  BADGE_BLUE_KEYS_NSID, CborDecoder, extractX5c0, base58btcEncode,
  extractSpkiDer,
} from "@publicdomainrelay/badge-blue-keys-common";

const LOG_RING: string[] = [];
const LOG_RING_MAX = 500;

const _structured = createStructuredLogger("macos-runner-desktop");

function writeLog(level: string, message: string, meta?: Record<string, unknown>) {
  const entry = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    message,
    ...meta,
  });
  if (LOG_RING.length >= LOG_RING_MAX) LOG_RING.shift();
  LOG_RING.push(entry);
  _structured[level as "info" | "warn" | "error" | "debug"](message, meta);
}

const log = {
  info: (msg: string, meta?: Record<string, unknown>) => writeLog("info", msg, meta),
  warn: (msg: string, meta?: Record<string, unknown>) => writeLog("warn", msg, meta),
  error: (msg: string, meta?: Record<string, unknown>) => writeLog("error", msg, meta),
  debug: (msg: string, meta?: Record<string, unknown>) => writeLog("debug", msg, meta),
};

log.info("App starting", { cwd: Deno.cwd() });

// =========================================================================
// 1. FFI bridge to DCAppAttestService (DeviceCheck framework)
// =========================================================================

// Resolve bridge dylib: dev mode uses source dir; compiled app uses binary dir.
function resolveBridgePath() {
  const name = "devicecheck_bridge.dylib";
  // In dev mode (deno desktop main.ts), import.meta.dirname is the source dir
  const candidate = `${import.meta.dirname}/${name}`;
  try {
    Deno.statSync(candidate);
    return candidate;
  } catch { /* not there */ }
  // In compiled bundle, the binary is Contents/MacOS/laufey_webview
  const execDir = Deno.execPath().replace(/\/[^/]+$/, "");
  return `${execDir}/${name}`;
}
const BRIDGE_PATH = resolveBridgePath();
log.info("Bridge path resolved", { path: BRIDGE_PATH });

let bridge;
let bridgeError = null;

try {
  bridge = Deno.dlopen(BRIDGE_PATH, {
    dc_is_supported: { parameters: [], result: "i32" },
    dc_generate_key: { parameters: [], result: "pointer" },
    dc_attest_key: {
      parameters: ["pointer", "pointer", "usize", "pointer"],
      result: "pointer",
    },
    dc_generate_assertion: {
      parameters: ["pointer", "pointer", "usize", "pointer"],
      result: "pointer",
    },
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
  log.info("Bridge loaded", { symbols: Object.keys(bridge.symbols) });
} catch (e) {
  bridgeError = e instanceof Error ? e.message : String(e);
  log.error("Failed to load devicecheck_bridge.dylib", { error: bridgeError });
}

// =========================================================================
// 2. C memory helpers — imported from @publicdomainrelay/app-attest-common
// =========================================================================

const encoder = new TextEncoder();

// =========================================================================
// 3. Attestation API layer
// =========================================================================

function checkBridge() {
  if (bridgeError) throw new AppAttestError(`Bridge not loaded: ${bridgeError}`);
}

function getLastError() {
  const ptr = bridge.symbols.dc_last_error();
  if (ptr === null) return "unknown error";
  return readCStr(ptr);
}

function isSupported() {
  if (bridgeError) return false;
  try {
    return bridge.symbols.dc_is_supported() !== 0;
  } catch (e) {
    log.error("isSupported check failed", { error: String(e) });
    return false;
  }
}

function generateKey() {
  checkBridge();
  const keyPtr = bridge.symbols.dc_generate_key();
  if (keyPtr === null) {
    const err = getLastError();
    log.error("generateKey failed", { error: err });
    throw new AppAttestError(err);
  }
  const keyId = readCStr(keyPtr);
  bridge.symbols.dc_free_string(keyPtr);
  log.info("generateKey succeeded", { keyId });
  return keyId;
}

function attestKey(keyId, challengeHash) {
  checkBridge();
  const keyCStr = encodeCStr(keyId);
  const outLenBuf = allocSizeT();

  const dataPtr = bridge.symbols.dc_attest_key(
    Deno.UnsafePointer.of(keyCStr),
    Deno.UnsafePointer.of(challengeHash),
    BigInt(challengeHash.length),
    Deno.UnsafePointer.of(outLenBuf),
  );

  if (dataPtr === null) {
    const err = getLastError();
    log.error("attestKey failed", { keyId, error: err });
    throw new AppAttestError(err);
  }

  const len = readSizeT(outLenBuf);
  const buf = new Uint8Array(len);
  buf.set(
    new Uint8Array(Deno.UnsafePointerView.getArrayBuffer(dataPtr, len)),
  );
  bridge.symbols.dc_free_buffer(dataPtr);
  log.info("attestKey succeeded", { keyId, attestationLen: len });
  return buf;
}

function generateAssertion(keyId, clientDataHash) {
  checkBridge();
  const keyCStr = encodeCStr(keyId);
  const outLenBuf = allocSizeT();

  const dataPtr = bridge.symbols.dc_generate_assertion(
    Deno.UnsafePointer.of(keyCStr),
    Deno.UnsafePointer.of(clientDataHash),
    BigInt(clientDataHash.length),
    Deno.UnsafePointer.of(outLenBuf),
  );

  if (dataPtr === null) {
    const err = getLastError();
    log.error("generateAssertion failed", { keyId, error: err });
    throw new AppAttestError(err);
  }

  const len = readSizeT(outLenBuf);
  const buf = new Uint8Array(len);
  buf.set(
    new Uint8Array(Deno.UnsafePointerView.getArrayBuffer(dataPtr, len)),
  );
  bridge.symbols.dc_free_buffer(dataPtr);
  log.info("generateAssertion succeeded", { keyId, assertionLen: len });
  return buf;
}

async function sha256(data) {
  const hash = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hash);
}

function toHex(bytes) {
  const parts = [];
  for (let i = 0; i < bytes.length; i++) {
    parts.push(bytes[i].toString(16).padStart(2, "0"));
  }
  return parts.join("");
}

// =========================================================================
// Keychain helpers (Secure Enclave-backed on Apple Silicon)
// =========================================================================

async function keychainSave(key: string, value: string): Promise<boolean> {
  if (!bridge) return false;
  const keyBuf = encodeCStr(key);
  const valBuf = encoder.encode(value);
  const keyPtr = Deno.UnsafePointer.of(keyBuf);
  const valPtr = Deno.UnsafePointer.of(valBuf);
  return bridge.symbols.keychain_save(keyPtr, valPtr, BigInt(valBuf.byteLength)) === 1;
}

function keychainLoad(key: string): string | null {
  if (!bridge) return null;
  const keyBuf = encodeCStr(key);
  const keyPtr = Deno.UnsafePointer.of(keyBuf);
  const ptr = bridge.symbols.keychain_load_str(keyPtr);
  if (!ptr) return null;
  const str = readCStr(ptr);
  bridge.symbols.dc_free_string(ptr);
  return str || null;
}

function keychainDelete(key: string): boolean {
  if (!bridge) return false;
  const keyBuf = encodeCStr(key);
  return bridge.symbols.keychain_delete(Deno.UnsafePointer.of(keyBuf)) === 1;
}

async function saveSession(session: OAuthSession): Promise<void> {
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
  const ok = await keychainSave(KC_SESSION_KEY, data);
  log.info("session saved to keychain", { ok });
}

async function loadSession(): Promise<OAuthSession | null> {
  try {
    const raw = keychainLoad(KC_SESSION_KEY);
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
    log.warn("failed to load session from keychain", { error: String(e) });
    return null;
  }
}

// =========================================================================
// 3b. Provider state — toggles + accept-scope, persisted to a local JSON file
// =========================================================================

interface ProviderState {
  dispatchingEnabled: boolean;
  workersEnabled: boolean;
  containersEnabled: boolean;
  acceptScope: "only_me" | "direct_network" | null;
  linkedAt: string | null;
}

const DEFAULT_PROVIDER_STATE: ProviderState = {
  dispatchingEnabled: true,
  workersEnabled: true,
  containersEnabled: false,
  acceptScope: null,
  linkedAt: null,
};

function resolveStatePath(): string {
  const home = Deno.env.get("HOME");
  if (home) return `${home}/.compute-provider-state.json`;
  return `${Deno.cwd()}/.compute-provider-state.json`;
}

const STATE_PATH = resolveStatePath();

function loadProviderState(): ProviderState {
  try {
    const raw = Deno.readTextFileSync(STATE_PATH);
    const parsed = JSON.parse(raw);
    return { ...DEFAULT_PROVIDER_STATE, ...parsed };
  } catch {
    return { ...DEFAULT_PROVIDER_STATE };
  }
}

let providerState: ProviderState = loadProviderState();

function saveProviderState(): void {
  try {
    Deno.writeTextFileSync(STATE_PATH, JSON.stringify(providerState));
  } catch (e) {
    log.warn("failed to persist provider state", { error: String(e) });
  }
}

let oauthInFlight = false;
let oauthError: string | null = null;

// =========================================================================
// 4. ATProto OAuth — server-side PKCE+PAR+DPoP with system browser loopback
// =========================================================================

let oauthCodeVerifier: string | null = null;
let oauthDpopKeyPair: CryptoKeyPair | null = null;
let oauthDpopJwk: Record<string, string> | null = null;
let oauthOngoingState: string | null = null;
let oauthServerNonce: string | null = null;
let oauthClientId: string | null = null;

// OAuth client config — from cli-args-env.json defaults, overridable.
const OAUTH_CLIENT_ID = OAUTH_CLIENT_ID_DEFAULT;
const OAUTH_REDIRECT_URI = OAUTH_REDIRECT_URI_DEFAULT;
let oauthDpopKeyPair: CryptoKeyPair | null = null;
let oauthDpopJwk: Record<string, string> | null = null;
let oauthOngoingState: string | null = null;
let oauthServerNonce: string | null = null;
let oauthClientId: string | null = null;

// Persistent device key — loaded from Keychain if present, otherwise
// generated once and saved. Only the explicit "Regenerate Key…" flow
// (POST /api/atproto/regenerate-key) calls generateKey() again.
let persistentKeyId: string | null = null;
try {
  if (bridge && !bridgeError) {
    const existingKeyId = keychainLoad(KC_DEVICE_KEY_ID);
    if (existingKeyId) {
      persistentKeyId = existingKeyId;
      log.info("persistent device key loaded from keychain", { keyId: persistentKeyId });
    } else {
      persistentKeyId = generateKey();
      keychainSave(KC_DEVICE_KEY_ID, persistentKeyId).then((ok) => {
        log.info("persistent device key generated and saved", { keyId: persistentKeyId, ok });
      }).catch((e) => log.error("failed to save device key to keychain", { error: String(e) }));
    }
    bridge.symbols.url_register_handler();
    log.info("URL scheme handler registered (pdrattest://)");
  }
} catch (e) {
  log.error("failed to load/generate persistent key", { error: String(e) });
}

let oauthSession: OAuthSession | null = null;
let SERVE_PORT = 0;

// Restore session from Keychain on startup — validate, refresh if expired,
// clear if dead.
(async () => {
  const saved = await loadSession();
  if (!saved) return;
  // Validate: call getSession to check token still works
  try {
    await fetchSessionInfo(saved.pds, saved.accessJwt, saved.dpopKeyPair, saved.dpopPublicJwk);
    oauthSession = saved;
    log.info("session restored and validated", { did: saved.did, handle: saved.handle });
    refreshAssociationRecord();
  } catch (e) {
    log.warn("session token expired, attempting refresh", { error: String(e) });
    try {
      const refreshed = await refreshSession(saved);
      oauthSession = refreshed;
      await saveSession(refreshed);
      log.info("session refreshed", { did: refreshed.did, handle: refreshed.handle });
      refreshAssociationRecord();
    } catch (e2) {
      log.warn("session refresh failed, clearing", { error: String(e2) });
      try { keychainDelete(KC_SESSION_KEY); } catch { /* best-effort */ }
    }
  }
})();

let associationRecordUri: string | null = null;
let cachedDidKey: string | null = null;

async function associationRecordRkey(): Promise<string> {
  if (cachedDidKey) return cachedDidKey;
  if (!persistentKeyId || !oauthSession) throw new Error("not ready");
  const challengeHash = await sha256(encoder.encode(oauthSession.did));
  const attestationBytes = attestKey(persistentKeyId, challengeHash);
  const certDer = extractX5c0(attestationBytes);
  // Extract SPKI from cert DER, import as CryptoKey, export raw P-256 key
  const spkiDer = extractSpkiDer(certDer);
  const cryptoKey = await crypto.subtle.importKey("spki", spkiDer, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
  const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", cryptoKey));
  // P-256 multicodec prefix (varint 0x1200 = 0x80, 0x24)
  cachedDidKey = `did:key:z${base58btcEncode(new Uint8Array([0x80, 0x24, ...rawKey]))}`;
  log.info("did:key rkey derived", { didKey: cachedDidKey });
  return cachedDidKey;
}

async function createAssociationRecord(service = "*"): Promise<string> {
  if (!oauthSession || !persistentKeyId) throw new Error("not ready");
  const did = oauthSession.did;
  const keyId = persistentKeyId;
  const challengeHash = await sha256(encoder.encode(did));
  const attestationHex = toHex(attestKey(keyId, challengeHash));
  const rkey = await associationRecordRkey();
  const createEndpoint = `${oauthSession.pds}/xrpc/com.atproto.repo.createRecord`;
  const dpopProof = await createDpopProof(oauthSession.dpopKeyPair, oauthSession.dpopPublicJwk, "POST", createEndpoint, oauthServerNonce, oauthSession.accessJwt);
  const res = await fetch(createEndpoint, {
    method: "POST",
    headers: { "content-type": "application/json", "Authorization": `DPoP ${oauthSession.accessJwt}`, "DPoP": dpopProof },
    body: JSON.stringify({ repo: did, collection: BADGE_BLUE_KEYS_NSID, rkey, record: { $type: BADGE_BLUE_KEYS_NSID, keyId, attestation: attestationHex, challenge: did, service, createdAt: new Date().toISOString() } }),
  });
  const nonce = res.headers.get("DPoP-Nonce");
  if (nonce) oauthServerNonce = nonce;
  if (!res.ok) { const eb = await res.text(); throw new Error(`createRecord: ${res.status} ${eb}`); }
  const cd = await res.json();
  log.info("atproto: record created — verify with: deno run --allow-net verify-record.ts " + cd.uri, { uri: cd.uri, cid: cd.cid, keyId, verify: `deno run --allow-net verify-record.ts ${cd.uri}` });
  return cd.uri;
}

async function refreshAssociationRecord(): Promise<void> {
  if (!oauthSession || !persistentKeyId) { associationRecordUri = null; return; }
  try {
    const rkey = await associationRecordRkey();
    const endpoint = `${oauthSession.pds}/xrpc/com.atproto.repo.getRecord?repo=${oauthSession.did}&collection=${BADGE_BLUE_KEYS_NSID}&rkey=${rkey}`;
    const dpopProof = await createDpopProof(oauthSession.dpopKeyPair, oauthSession.dpopPublicJwk, "GET", endpoint, oauthServerNonce, oauthSession.accessJwt);
    const res = await fetch(endpoint, {
      headers: { "Authorization": `DPoP ${oauthSession.accessJwt}`, "DPoP": dpopProof },
    });
    if (res.ok) {
      const data = await res.json();
      associationRecordUri = data.uri || null;
      log.info("association record found", { uri: associationRecordUri });
    } else {
      // Record doesn't exist yet — create it automatically
      log.info("association record not found, creating", { rkey });
      associationRecordUri = await createAssociationRecord();
    }
  } catch (e) {
    log.warn("refreshAssociationRecord failed", { error: String(e) });
    associationRecordUri = null;
  }
}

function base64url(bytes: Uint8Array): string {
  let s = btoa(String.fromCharCode(...bytes));
  return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function randomHex(n: number): string {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

// Per-launch shared secret. The loopback HTTP server has no other caller
// auth (any local process can reach 127.0.0.1:SERVE_PORT) — mutating
// /api/* routes require this header, value only ever handed to the
// webview via the served HTML, never logged.
const APP_TOKEN = randomHex(24);

async function pkceChallenge(verifier: string): Promise<string> {
  const hash = await sha256(encoder.encode(verifier));
  return base64url(hash);
}

async function generateDpopKey(): Promise<{ keyPair: CryptoKeyPair; publicJwk: Record<string, string> }> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey) as Record<string, string>;
  return { keyPair, publicJwk: { kty: jwk.kty!, crv: jwk.crv!, x: jwk.x!, y: jwk.y! } };
}

async function createDpopProof(
  keyPair: CryptoKeyPair, publicJwk: Record<string, string>,
  htm: string, htu: string, nonce?: string | null, accessToken?: string | null,
): Promise<string> {
  const header = { typ: "dpop+jwt", alg: "ES256", jwk: publicJwk };
  const payload: Record<string, unknown> = {
    jti: randomHex(20), htm, htu, iat: Math.floor(Date.now() / 1000),
  };
  if (nonce) payload.nonce = nonce;
  if (accessToken) payload.ath = base64url(await sha256(encoder.encode(accessToken)));
  const headerB64 = base64url(encoder.encode(JSON.stringify(header)));
  const payloadB64 = base64url(encoder.encode(JSON.stringify(payload)));
  const signingInput = headerB64 + "." + payloadB64;
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, keyPair.privateKey, encoder.encode(signingInput),
  );
  return signingInput + "." + base64url(new Uint8Array(sig));
}

async function resolveHandleToDid(handle: string): Promise<string> {
  try {
    const r = await fetch(`https://${handle}/.well-known/atproto-did`);
    if (r.ok) { const did = (await r.text()).trim(); if (did.startsWith("did:")) return did; }
  } catch { /* fall through */ }
  const r = await fetch(`https://bsky.social/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(handle)}`);
  if (!r.ok) throw new Error(`identity resolve failed: ${r.status}`);
  const did: string = (await r.json()).did;
  if (!did) throw new Error("No DID in response");
  return did;
}

async function resolveDidToPds(did: string): Promise<string> {
  let didDoc;
  if (did.startsWith("did:web:")) {
    const rest = did.slice("did:web:".length).split(":").map(decodeURIComponent);
    const host = rest.shift();
    const path = rest.length ? `/${rest.join("/")}/.well-known/did.json` : "/.well-known/did.json";
    const dr = await fetch(`https://${host}${path}`);
    if (!dr.ok) throw new Error(`DID doc fetch failed: ${dr.status}`);
    didDoc = await dr.json();
  } else {
    const dr = await fetch(`https://plc.directory/${encodeURIComponent(did)}`);
    if (!dr.ok) throw new Error(`PLC directory fetch failed: ${dr.status}`);
    didDoc = await dr.json();
  }
  const svc = (didDoc.service || []).find(
    (s: { id?: string; type?: string }) => s.id === "#atproto_pds" || s.type === "AtprotoPersonalDataServer",
  );
  if (!svc) throw new Error("No PDS in DID doc");
  return svc.serviceEndpoint as string;
}

async function getAuthServerMeta(authServer: string) {
  const r = await fetch(`${authServer}/.well-known/oauth-authorization-server`);
  if (!r.ok) throw new Error(`Auth metadata: ${r.status}`);
  return r.json();
}

async function resolveAuthServer(handle: string): Promise<{ did: string; pds: string; authServer: string }> {
  const did = await resolveHandleToDid(handle);
  const pds = await resolveDidToPds(did);
  const mr = await fetch(`${pds}/.well-known/oauth-protected-resource`);
  if (!mr.ok) throw new Error(`PDS metadata: ${mr.status}`);
  const authServers: string[] = (await mr.json()).authorization_servers;
  if (!authServers?.[0]) throw new Error("No authorization_servers");
  const am = await getAuthServerMeta(authServers[0]);
  if (!am.authorization_endpoint || !am.token_endpoint) throw new Error("Missing auth endpoints");
  return { did, pds, authServer: authServers[0] };
}

async function startOAuth(handle: string): Promise<{ did: string }> {
  const { did, authServer } = await resolveAuthServer(handle);
  const meta = await getAuthServerMeta(authServer);
  const parEndpoint: string = meta.pushed_authorization_request_endpoint;
  const authEndpoint: string = meta.authorization_endpoint;

  const codeVerifier = randomHex(48);
  const codeChallenge = await pkceChallenge(codeVerifier);
  const dpop = await generateDpopKey();
  const state = randomHex(16);

  oauthCodeVerifier = codeVerifier;
  oauthDpopKeyPair = dpop.keyPair;
  oauthDpopJwk = dpop.publicJwk;
  oauthOngoingState = state;

  oauthClientId = OAUTH_CLIENT_ID;

  const parBody = new URLSearchParams({
    client_id: OAUTH_CLIENT_ID,
    response_type: "code",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    redirect_uri: OAUTH_REDIRECT_URI,
    scope: `atproto repo:${BADGE_BLUE_KEYS_NSID}?action=create`,
    state,
  });
  // DPoP required on PAR per spec. Retry with server nonce if needed.
  let parDpop = await createDpopProof(dpop.keyPair, dpop.publicJwk, "POST", parEndpoint);
  let parRes = await fetch(parEndpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", "DPoP": parDpop },
    body: parBody.toString(),
  });
  let parErrBody = "";
  if (parRes.status === 400) {
    parErrBody = await parRes.text();
    if (parErrBody.includes("use_dpop_nonce")) {
      const serverNonce = parRes.headers.get("DPoP-Nonce");
      if (!serverNonce) throw new Error("PAR: server requested nonce but none provided");
      log.info("oauth: retrying PAR with server nonce", { nonce: serverNonce });
      parDpop = await createDpopProof(dpop.keyPair, dpop.publicJwk, "POST", parEndpoint, serverNonce);
      parRes = await fetch(parEndpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", "DPoP": parDpop },
        body: parBody.toString(),
      });
      parErrBody = "";
    }
  }
  if (!parRes.ok) {
    if (!parErrBody) parErrBody = await parRes.text();
    throw new Error(`PAR failed: ${parRes.status} ${parErrBody}`);
  }
  const parNonce = parRes.headers.get("DPoP-Nonce");
  if (parNonce) oauthServerNonce = parNonce;
  const requestUri: string = (await parRes.json()).request_uri;
  if (!requestUri) throw new Error("No request_uri");

  const authUrl = `${authEndpoint}?client_id=${encodeURIComponent(OAUTH_CLIENT_ID)}&request_uri=${encodeURIComponent(requestUri)}`;
  log.info("oauth: opening system browser", { authEndpoint, did });
  new Deno.Command("open", { args: [authUrl] }).spawn().status.catch(() => {});
  return { did };
}

async function exchangeCode(
  authServer: string, tokenEndpoint: string, code: string,
  redirectUri: string, codeVerifier: string,
  dpopKeyPair: CryptoKeyPair, dpopJwk: Record<string, string>,
): Promise<{ accessToken: string; refreshToken: string; sub: string }> {
  async function doExchange(nonce: string | null): Promise<Response> {
    const proof = await createDpopProof(dpopKeyPair, dpopJwk, "POST", tokenEndpoint, nonce);
    return fetch(tokenEndpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", "DPoP": proof },
      body: tokenBody.toString(),
    });
  }

  // Use exact same client_id as PAR (URLSearchParams-encoded, stored in oauthClientId)
  const tokenBody = new URLSearchParams({
    grant_type: "authorization_code", code, redirect_uri: redirectUri,
    client_id: oauthClientId!, code_verifier: codeVerifier,
  });

  // Use nonce from PAR response (or null for first attempt)
  let res = await doExchange(oauthServerNonce);
  let exchangeErrBody = "";

  // Retry with server nonce if required
  if (res.status === 400) {
    exchangeErrBody = await res.text();
    if (exchangeErrBody.includes("use_dpop_nonce")) {
      const serverNonce = res.headers.get("DPoP-Nonce");
      if (!serverNonce) throw new Error("Token exchange: server requested nonce but none provided");
      log.info("oauth: retrying token exchange with server nonce", { nonce: serverNonce });
      res = await doExchange(serverNonce);
      exchangeErrBody = "";
    }
  }

  if (!res.ok) {
    if (!exchangeErrBody) exchangeErrBody = await res.text();
    throw new Error(`Token exchange: ${res.status} ${exchangeErrBody}`);
  }
  const nonce = res.headers.get("DPoP-Nonce");
  if (nonce) oauthServerNonce = nonce;
  const data = await res.json();
  return { accessToken: data.access_token, refreshToken: data.refresh_token, sub: data.sub };
}

async function fetchSessionInfo(
  pds: string, accessToken: string,
  dpopKeyPair: CryptoKeyPair, dpopJwk: Record<string, string>,
): Promise<{ handle: string; did: string }> {
  const endpoint = `${pds}/xrpc/com.atproto.server.getSession`;

  async function doGetSession(nonce: string | null): Promise<Response> {
    const proof = await createDpopProof(dpopKeyPair, dpopJwk, "GET", endpoint, nonce, accessToken);
    return fetch(endpoint, {
      headers: { "Authorization": `DPoP ${accessToken}`, "DPoP": proof },
    });
  }

  let res = await doGetSession(oauthServerNonce);
  let errBody = "";
  if (res.status === 400 || res.status === 401) {
    errBody = await res.text();
    if (errBody.includes("use_dpop_nonce")) {
      const serverNonce = res.headers.get("DPoP-Nonce");
      if (serverNonce) {
        oauthServerNonce = serverNonce;
        res = await doGetSession(serverNonce);
        errBody = "";
      }
    }
  }

  const nonce = res.headers.get("DPoP-Nonce");
  if (nonce) oauthServerNonce = nonce;
  if (!res.ok) {
    if (!errBody) errBody = await res.text();
    throw new Error(`getSession: ${res.status} ${errBody}`);
  }
  const data = await res.json();
  return { handle: data.handle, did: data.did };
}

async function refreshSession(saved: OAuthSession): Promise<OAuthSession> {
  // Discover auth server from PDS
  const mr = await fetch(`${saved.pds}/.well-known/oauth-protected-resource`);
  if (!mr.ok) throw new Error(`PDS metadata: ${mr.status}`);
  const authServers: string[] = (await mr.json()).authorization_servers;
  if (!authServers?.[0]) throw new Error("No authorization_servers");
  const meta = await getAuthServerMeta(authServers[0]);
  const tokenEndpoint: string = meta.token_endpoint;

  async function doRefresh(nonce: string | null): Promise<Response> {
    const proof = await createDpopProof(saved.dpopKeyPair, saved.dpopPublicJwk, "POST", tokenEndpoint, nonce);
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: saved.refreshJwt,
      client_id: OAUTH_CLIENT_ID,
    });
    return fetch(tokenEndpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", "DPoP": proof },
      body: body.toString(),
    });
  }

  let res = await doRefresh(null);
  let errBody = "";

  if (res.status === 400) {
    errBody = await res.text();
    if (errBody.includes("use_dpop_nonce")) {
      const serverNonce = res.headers.get("DPoP-Nonce");
      if (!serverNonce) throw new Error("Token refresh: server requested nonce but none provided");
      log.info("oauth: retrying token refresh with server nonce", { nonce: serverNonce });
      res = await doRefresh(serverNonce);
      errBody = "";
    }
  }

  if (!res.ok) {
    if (!errBody) errBody = await res.text();
    throw new Error(`Token refresh: ${res.status} ${errBody}`);
  }
  const nonce = res.headers.get("DPoP-Nonce");
  if (nonce) oauthServerNonce = nonce;
  const data = await res.json();
  return {
    accessJwt: data.access_token,
    refreshJwt: data.refresh_token ?? saved.refreshJwt,
    did: saved.did,
    handle: saved.handle,
    pds: saved.pds,
    dpopKeyPair: saved.dpopKeyPair,
    dpopPublicJwk: saved.dpopPublicJwk,
  };
}

// =========================================================================
// 5. Windows, tray and dock — tray-only app, no default window.
//
//    The desktop runtime auto-creates a startup BrowserWindow; the first
//    `new Deno.BrowserWindow()` call adopts it (per
//    https://docs.deno.com/runtime/desktop/windows/). We adopt it, hide it
//    immediately, and hide the dock icon — the "tray-only background app"
//    pattern from https://docs.deno.com/runtime/desktop/tray_and_dock/.
//
//    All UI lives in two routes on the same Deno.serve loopback:
//      /tray     — 320px popover shown via Tray.attachPanel()
//      /settings — normal chrome'd window (General/Identity/Policy tabs)
//
//    IPC is fetch()-based throughout (not win.bind()/bindings.*), matching
//    the rest of this app — see NOTES.md / CLAUDE.md on the WKWebView
//    bindings caveat.
// =========================================================================

let startupWindow: Deno.BrowserWindow | null = null;

// Settings used to live in a second native BrowserWindow, opened/closed via
// its own titlebar. On this macOS build, clicking that window's native
// traffic-light close button hangs inside AppKit's windowShouldClose
// delegate itself — confirmed via logging that the hang happens before any
// JS "close" event fires, so nothing on the app side can catch or avoid it.
// Settings is now just another view inside the single tray panel (proven
// stable: dismissed via blur, no native close button in the picture at
// all), reached via the right-hand nav rail instead of a second window.
let requestedTrayView: string | null = null;

function showTrayPanel(view?: string): void {
  if (view) requestedTrayView = view;
  if (trayPanelHandle) trayPanelHandle.show();
  else if (trayPopoverWindow) {
    try {
      const bounds = trayHandle?.getBounds();
      if (bounds) trayPopoverWindow.setPosition(bounds.x, bounds.y + bounds.height);
    } catch (e) {
      log.warn("tray.getBounds failed", { error: String(e) });
    }
    trayPopoverWindow.show();
    trayPopoverWindow.focus();
  }
}

let sentinelWindow: Deno.BrowserWindow | null = null;
let trayHandle: Deno.Tray | null = null;
let trayPanelHandle: Deno.TrayPanel | null = null;
let trayPopoverWindow: Deno.BrowserWindow | null = null;
const TRAY_PANEL_WIDTH_HOME = 320;
const TRAY_PANEL_WIDTH_SETTINGS = 560;

function resizeTrayPanel(contentWidth: number, contentHeight: number): void {
  const width = Math.max(1, Math.round(contentWidth));
  const height = Math.max(1, Math.round(contentHeight));
  try {
    const win = trayPanelHandle?.window ?? trayPopoverWindow;
    if (!win) return;
    // attachPanel's own place() anchors the panel's TOP edge just below
    // the tray icon, computed once per show() from the panel's width/height
    // at attachPanel-call time (1px tall). BrowserWindow.setSize() on the
    // native (Cocoa) side keeps the window's bottom-left origin fixed and
    // grows/shrinks upward — so a naive setSize() here pushes the top edge
    // further up the screen every time content height changes, eventually
    // off the top of the display (the bug: only a sliver visible). Re-derive
    // the position from the tray icon's own bounds after every resize so
    // the top edge stays pinned and the panel only grows down/sideways.
    win.setSize(width, height);
    const bounds = trayHandle?.getBounds();
    if (bounds) {
      win.setPosition(
        Math.round(bounds.x + bounds.width / 2 - width / 2),
        Math.round(bounds.y + bounds.height),
      );
    }
  } catch (e) {
    log.warn("Tray panel resize failed", { error: String(e) });
  }
}

function setupWindowsAndTray(port: number): void {
  // Adopt the implicit startup window, but do NOT hide it yet: this patched
  // deno build's NSApplication delegate quits the whole process as soon as
  // visible-window count hits zero (applicationShouldTerminateAfterLastWindowClosed
  // defaults to YES) — even though Deno.serve and the tray are still alive.
  // Empirically, Tray.attachPanel()'s returned panel does not eagerly
  // materialize an OS window (it's created lazily on first toggle), so it
  // does NOT count toward "windows open" the moment setupWindowsAndTray runs.
  // To make this robust regardless of that lazily-created panel's internals,
  // we keep a tiny always-alive sentinel window (1x1, off-screen, frameless,
  // noActivate, never shown to the user, never hidden/closed) that exists for
  // the lifetime of the process, and only THEN hide the adopted startup
  // window + dock icon.
  try {
    startupWindow = new Deno.BrowserWindow({ title: "Compute Provider" });
    log.info("Startup window adopted", { windowId: startupWindow.windowId });
  } catch (e) {
    log.error("Failed to adopt startup window", { error: String(e) });
  }

  try {
    // Deliberately NOT frameless/noActivate: those create an NSPanel-style
    // utility window that (empirically, on this patched build) AppKit does
    // not count for "last regular window closed" auto-quit purposes. A
    // normal bordered window does count, so we use one here, parked off
    // -screen, to keep the app alive.
    sentinelWindow = new Deno.BrowserWindow({
      title: "",
      width: 1,
      height: 1,
      x: -10000,
      y: -10000,
      resizable: false,
    });
    log.info("Sentinel window created", { windowId: sentinelWindow.windowId });
  } catch (e) {
    log.warn("Failed to create sentinel window", { error: String(e) });
  }

  try {
    const tray = new Deno.Tray();
    trayHandle = tray;
    tray.setTooltip("Compute Provider");
    try {
      const binaryStr = atob(TRAY_ICON_BASE64);
      const iconBytes = new Uint8Array(binaryStr.length);
      for (let i = 0; i < binaryStr.length; i++) iconBytes[i] = binaryStr.charCodeAt(i);
      tray.setIcon(iconBytes);
      log.info("Tray icon set", { bytes: iconBytes.length });
    } catch (e) {
      log.warn("Tray icon not loaded", { error: String(e) });
    }

    tray.setMenu([
      { item: { label: "Open Settings…", id: "settings", enabled: true } },
      "separator",
      { item: { label: "Quit", id: "quit", enabled: true } },
    ]);
    tray.addEventListener("menuclick", (e) => {
      if (e.detail.id === "settings") showTrayPanel("identity");
      if (e.detail.id === "quit") Deno.exit(0);
    });

    let panel: Deno.TrayPanel | null = null;
    try {
      panel = tray.attachPanel({
        url: `http://127.0.0.1:${port}/tray`,
        width: TRAY_PANEL_WIDTH_HOME,
        height: 1,
      });
      trayPanelHandle = panel;
      log.info("Tray panel attached");
    } catch (e) {
      log.warn("attachPanel not available, falling back to manual popover", { error: String(e) });
    }

    if (!panel) {
      const popover = new Deno.BrowserWindow({
        title: "",
        width: TRAY_PANEL_WIDTH_HOME,
        height: 1,
        frameless: true,
        noActivate: true,
      });
      trayPopoverWindow = popover;
      popover.navigate(`http://127.0.0.1:${port}/tray`);
      popover.hide();
      tray.addEventListener("click", () => {
        try {
          const bounds = tray.getBounds();
          if (bounds) popover.setPosition(bounds.x, bounds.y + bounds.height);
        } catch (e) {
          log.warn("tray.getBounds failed", { error: String(e) });
        }
        popover.show();
        popover.focus();
      });
      popover.addEventListener("blur", () => popover.hide());
    }

    log.info("Tray ready");
  } catch (e) {
    log.warn("Tray not available", { error: String(e) });
  }

  try {
    Deno.dock.setMenu([
      { item: { label: "Open Settings…", id: "settings", enabled: true } },
    ]);
    Deno.dock.addEventListener("menuclick", (e) => {
      if (e.detail.id === "settings") showTrayPanel("identity");
    });
  } catch {
    // Dock menu is macOS-only; no-op elsewhere
  }

  // Now that the sentinel window exists, it's safe to hide the adopted
  // startup window and the dock icon without tripping the "last window
  // closed" auto-quit.
  try {
    startupWindow?.hide();
    log.info("Startup window hidden");
  } catch (e) {
    log.warn("Failed to hide startup window", { error: String(e) });
  }
  try {
    Deno.dock.setVisible(false);
  } catch (e) {
    log.warn("Dock not available", { error: String(e) });
  }
}

// =========================================================================
// 6. HTTP server. IPC is fetch()-based throughout — the /tray and /settings
//    documents call fetch('/api/...') against this same-origin loopback
//    server, never win.bind()/bindings.*.
// =========================================================================

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

async function handler(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;

  if (req.method === "GET") {
    if (path === "/oauth-client-metadata.json") {
      return new Response(JSON.stringify({
        client_id: OAUTH_CLIENT_ID,
        application_type: "native",
        dpop_bound_access_tokens: true,
        redirect_uris: [OAUTH_REDIRECT_URI],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        scope: `atproto repo:${BADGE_BLUE_KEYS_NSID}?action=create`,
        token_endpoint_auth_method: "none",
        client_name: "Compute Provider",
      }), { headers: { "content-type": "application/json" } });
    }

    if (path === "/api/health") {
      return json({ ok: true, logEntries: LOG_RING.length });
    }
    if (path === "/api/logs") {
      return json({ entries: [...LOG_RING] });
    }

    if (path === "/api/atproto/session") {
      if (oauthSession) return json({ loggedIn: true, did: oauthSession.did, handle: oauthSession.handle });
      return json({ loggedIn: false });
    }

    if (path === "/api/state") {
      const requestedView = requestedTrayView;
      requestedTrayView = null;
      return json({
        ...providerState,
        oauthInFlight,
        oauthError,
        persistentKeyId,
        associationRecordUri,
        session: oauthSession ? { handle: oauthSession.handle, did: oauthSession.did } : null,
        requestedView,
      });
    }

    if (path === "/tray") {
      return new Response(TRAY_HTML.replace("__APP_TOKEN__", APP_TOKEN), { headers: { "content-type": "text/html; charset=utf-8" } });
    }

    // OAuth callback from system browser
    if (path === "/" || path === "") {
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      const iss = url.searchParams.get("iss");
      if (code && state && iss && state === oauthOngoingState) {
        try {
          const meta = await getAuthServerMeta(iss);
          const tokenEndpoint: string = meta.token_endpoint;
          const redirectUri = OAUTH_REDIRECT_URI;
          const tokens = await exchangeCode(iss, tokenEndpoint, code, redirectUri, oauthCodeVerifier!, oauthDpopKeyPair!, oauthDpopJwk!);
          const did = tokens.sub;
          let pds = iss;
          try {
            const dr = await fetch(`https://plc.directory/${encodeURIComponent(did)}`);
            if (dr.ok) {
              const doc = await dr.json();
              const svc = (doc.service || []).find(
                (s: { id?: string; type?: string }) => s.id === "#atproto_pds" || s.type === "AtprotoPersonalDataServer",
              );
              if (svc) pds = svc.serviceEndpoint;
            }
          } catch { /* use iss */ }
          const info = await fetchSessionInfo(pds, tokens.accessToken, oauthDpopKeyPair!, oauthDpopJwk!);
          oauthSession = { accessJwt: tokens.accessToken, refreshJwt: tokens.refreshToken, did: info.did, handle: info.handle, pds, dpopKeyPair: oauthDpopKeyPair!, dpopPublicJwk: oauthDpopJwk! };
          oauthCodeVerifier = null; oauthOngoingState = null;
          oauthInFlight = false; oauthError = null;
          if (!providerState.acceptScope) providerState.acceptScope = "only_me";
          providerState.linkedAt = new Date().toISOString();
          saveProviderState();
          log.info("oauth: session stored", { did: info.did, handle: info.handle });
          saveSession(oauthSession).catch((e) => log.error("keychain save failed", { error: String(e) }));
          refreshAssociationRecord();
          return new Response(
            `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Authenticated</title><style>body{font-family:-apple-system,sans-serif;background:#1e1e2e;color:#cdd6f4;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center}.ok{color:#a6e3a1;font-size:24px;margin-bottom:12px}</style></head><body><div><div class="ok">Authenticated</div><p>Signed in as <strong>@${info.handle}</strong></p><p>You may close this window and return to the app.</p></div></body></html>`,
            { headers: { "content-type": "text/html; charset=utf-8" } },
          );
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          oauthInFlight = false; oauthError = msg;
          log.error("oauth: callback error", { error: msg });
          return new Response(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Auth Error</title><style>body{font-family:-apple-system,sans-serif;background:#1e1e2e;color:#f38ba8;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center}</style></head><body><div><h2>Authentication Error</h2><p>${msg}</p></div></body></html>`, { status: 500, headers: { "content-type": "text/html; charset=utf-8" } });
        }
      }
    }
  }

  if (req.method === "POST") {
    // Loopback server has no other caller auth — any local process can
    // reach 127.0.0.1:SERVE_PORT. Require the per-launch token the
    // webview received in its served HTML on every mutating route.
    if (req.headers.get("X-App-Token") !== APP_TOKEN) {
      return json({ error: "unauthorized" }, 401);
    }

    let body: Record<string, unknown> = {};
    if (req.headers.get("content-type")?.includes("application/json")) {
      try { body = await req.json(); } catch { /* use empty */ }
    }

    if (path === "/api/tray-resize") {
      const width = Number(body.width);
      const height = Number(body.height);
      if (!Number.isFinite(width) || width <= 0) return json({ error: "invalid width" }, 400);
      if (!Number.isFinite(height) || height <= 0) return json({ error: "invalid height" }, 400);
      resizeTrayPanel(width, height);
      return json({ ok: true });
    }

    if (path === "/api/atproto/start-oauth") {
      try {
        const handle = String(body.handle ?? "").trim();
        if (!handle) return json({ error: "handle required" }, 400);
        if (!SERVE_PORT) return json({ error: "server not ready" }, 503);
        oauthInFlight = true; oauthError = null;
        const { did } = await startOAuth(handle);
        log.info("oauth: authorization started", { did, handle });
        return json({ ok: true, did });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        oauthInFlight = false; oauthError = msg;
        log.error("oauth: start failed", { error: msg });
        return json({ error: msg }, 500);
      }
    }

    if (path === "/api/atproto/cancel-oauth") {
      oauthOngoingState = null;
      oauthCodeVerifier = null;
      oauthInFlight = false;
      log.info("oauth: cancelled by user");
      return json({ ok: true });
    }

    if (path === "/api/atproto/unlink") {
      oauthSession = null;
      try { keychainDelete(KC_SESSION_KEY); } catch { /* best-effort */ }
      providerState.acceptScope = null;
      providerState.linkedAt = null;
      associationRecordUri = null;
      cachedDidKey = null;
      saveProviderState();
      log.info("atproto: unlinked");
      return json({ ok: true });
    }

    if (path === "/api/atproto/regenerate-key") {
      try {
        persistentKeyId = generateKey();
        await keychainSave(KC_DEVICE_KEY_ID, persistentKeyId);
        oauthSession = null;
        try { keychainDelete(KC_SESSION_KEY); } catch { /* best-effort */ }
        providerState.acceptScope = null;
        providerState.linkedAt = null;
        associationRecordUri = null;
        saveProviderState();
        log.info("device key regenerated", { keyId: persistentKeyId });
        return json({ ok: true, keyId: persistentKeyId });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        log.error("regenerate-key failed", { error: msg });
        return json({ error: msg }, 500);
      }
    }

    if (path === "/api/open-external") {
      const target = String(body.url ?? "").trim();
      if (!target || !target.startsWith("https://")) return json({ error: "invalid url" }, 400);
      new Deno.Command("open", { args: [target] }).spawn().status.catch(() => {});
      return json({ ok: true });
    }

    if (path === "/api/state") {
      const allowed: (keyof ProviderState)[] = ["dispatchingEnabled", "workersEnabled", "containersEnabled", "acceptScope"];
      for (const k of allowed) if (k in body) (providerState as Record<string, unknown>)[k] = body[k];
      saveProviderState();
      return json({ ok: true });
    }

    if (path === "/api/atproto/create-key-record") {
      try {
        if (!oauthSession) return json({ error: "not authenticated" }, 401);
        const service = String(body.service ?? "*").trim();
        const uri = await createAssociationRecord(service);
        associationRecordUri = uri;
        return json({ ok: true, uri, keyId: persistentKeyId, service });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        log.error("create-key-record failed", { error: msg });
        return json({ error: msg }, 500);
      }
    }
  }

  return Response.redirect(`${url.origin}/tray`, 302);
}

Deno.serve(
  {
    port: 0,
    hostname: "127.0.0.1",
    onListen({ port }) {
      SERVE_PORT = port;
      log.info("HTTP server started", { port });
      setupWindowsAndTray(port);
    },
  },
  handler,
);

// Poll for custom URL scheme callbacks (pdrattest://callback?code=...&state=...&iss=...)
if (bridge && !bridgeError) {
  setInterval(async () => {
    const ptr = bridge.symbols.url_scheme_pending();
    if (!ptr) return;
    const urlStr = readCStr(ptr);
    bridge.symbols.dc_free_string(ptr);
    if (!urlStr) return;
    log.info("url scheme callback received", { url: urlStr });
    try {
      const u = new URL(urlStr);
      const code = u.searchParams.get("code");
      const state = u.searchParams.get("state");
      const iss = u.searchParams.get("iss");
      if (code && state && iss && state === oauthOngoingState) {
        const meta = await getAuthServerMeta(iss);
        const tokenEndpoint: string = meta.token_endpoint;
        const redirectUri = OAUTH_REDIRECT_URI;
        const tokens = await exchangeCode(iss, tokenEndpoint, code, redirectUri, oauthCodeVerifier!, oauthDpopKeyPair!, oauthDpopJwk!);
        const did = tokens.sub;
        let pds = iss;
        try {
          const dr = await fetch(`https://plc.directory/${encodeURIComponent(did)}`);
          if (dr.ok) {
            const doc = await dr.json();
            const svc = (doc.service || []).find(
              (s) => s.id === "#atproto_pds" || s.type === "AtprotoPersonalDataServer",
            );
            if (svc) pds = svc.serviceEndpoint;
          }
        } catch { /* use iss */ }
        const info = await fetchSessionInfo(pds, tokens.accessToken, oauthDpopKeyPair!, oauthDpopJwk!);
        oauthSession = { accessJwt: tokens.accessToken, refreshJwt: tokens.refreshToken, did: info.did, handle: info.handle, pds, dpopKeyPair: oauthDpopKeyPair!, dpopPublicJwk: oauthDpopJwk! };
        oauthCodeVerifier = null; oauthOngoingState = null;
        oauthInFlight = false; oauthError = null;
        if (!providerState.acceptScope) providerState.acceptScope = "only_me";
        providerState.linkedAt = new Date().toISOString();
        saveProviderState();
        log.info("oauth: session stored via url scheme", { did: info.did, handle: info.handle });
        saveSession(oauthSession).catch((e) => log.error("keychain save failed", { error: String(e) }));
        refreshAssociationRecord();
      }
    } catch (e) {
      oauthInFlight = false; oauthError = e instanceof Error ? e.message : String(e);
      log.error("url scheme callback error", { error: String(e) });
    }
  }, 500);
}

// =========================================================================
// =========================================================================

const attestSupported = isSupported();
log.info("App ready", { attestSupported });

// =========================================================================
// HTML UI — /tray (320px popover) and /settings (460x460 window)
// =========================================================================

const TRAY_STYLE = `
:root{
  --bg:rgba(246,246,248,.96);--border:rgba(0,0,0,.06);--shadow:0 10px 26px rgba(0,0,0,.12);
  --text:#1d1d1f;--sub:#6e6e73;--accent:#007aff;--accent-bg:rgba(0,122,255,.06);
  --green:#34c759;--divider:rgba(0,0,0,.08);--gear-bg:rgba(0,0,0,.06);
  --danger-text:#c41e3a;--danger-border:#c41e3a;--banner-bg:#fdeceb;--banner-border:#f8c9c5;--banner-text:#a13b32;--banner-dismiss:#c79490;
  --avatar-bg:#d8dde3;--avatar-text:#48484a;--scope-border:rgba(0,0,0,.08);--scope-radio:#8e8e93;
  --card-bg:#f5f5f7;--card-border:rgba(0,0,0,.07);--nav-bg:#ececec;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:rgba(40,40,42,.9);--border:rgba(255,255,255,.1);--shadow:0 10px 30px rgba(0,0,0,.5);
    --text:#f2f2f3;--sub:#9a9a9e;--accent:#0a84ff;--accent-bg:rgba(10,132,255,.12);
    --green:#32d74b;--divider:rgba(255,255,255,.08);--gear-bg:rgba(255,255,255,.08);
    --danger-text:#ff3b3b;--danger-border:#ff3b3b;--banner-bg:rgba(248,113,113,.14);--banner-border:rgba(248,113,113,.3);--banner-text:#fca5a5;--banner-dismiss:#fca5a5;
    --avatar-bg:#4a4a4d;--avatar-text:#e3e3e5;--scope-border:rgba(255,255,255,.1);--scope-radio:#8e8e93;
    --card-bg:#2f2f32;--card-border:rgba(255,255,255,.14);--nav-bg:#2c2c2e;
  }
}
*{box-sizing:border-box}
html,body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;background:var(--bg)}
.panel{width:320px;position:relative;transition:width .32s cubic-bezier(.4,0,.2,1);overflow:hidden}
.panel-blur{position:absolute;inset:0;background:var(--bg);z-index:0}
.panel>*:not(.panel-blur){position:relative;z-index:1}
.appshell{display:flex}
.contentarea{flex:1;min-width:0}
.navrail{flex:none;width:0;overflow:hidden;display:flex;flex-direction:column;gap:2px;padding:14px 0;background:var(--nav-bg);border-right:0 solid var(--divider);opacity:0;transition:width .32s cubic-bezier(.4,0,.2,1),opacity .22s ease-out,padding .32s cubic-bezier(.4,0,.2,1)}
.navrail.show{width:120px;padding:14px 8px;opacity:1;border-right-width:1px}
.navitem{padding:8px 10px;border-radius:7px;font-size:12px;font-weight:600;color:var(--sub);cursor:pointer;white-space:nowrap}
.navitem.active{background:var(--accent-bg);color:var(--accent)}
.settings-content{padding:18px 20px;animation:paneIn .1s ease-out}
@keyframes paneIn{from{opacity:0}to{opacity:1}}
.section-title{font-size:10.5px;font-weight:700;color:var(--sub);text-transform:uppercase;letter-spacing:.04em;margin-bottom:8px}
.section-title.danger{color:var(--danger-text)}
.card{background:var(--card-bg);border:1px solid var(--card-border);border-radius:8px;padding:11px 13px;margin-bottom:14px}
.card-label{font-size:10px;color:#8e8e93;margin-bottom:3px}
.card-mono{font-family:ui-monospace,'SF Mono',monospace;font-size:12px;color:var(--text)}
.assoc-row{display:flex;align-items:center;gap:9px}
.assoc-avatar{width:24px;height:24px;border-radius:50%;background:#4a4a4d;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;color:#e3e3e5}
.assoc-info{flex:1}
.assoc-handle{font-size:12px;color:var(--text)}
.assoc-date{font-size:10px;color:#8e8e93}
.btn-proof{font-size:11px;color:var(--accent);font-weight:600;cursor:pointer;margin-top:4px}
.btn-proof:hover{opacity:.8}
.assoc-action{font-size:11px;color:var(--accent);font-weight:600;cursor:pointer}
.hr{border-top:1px solid var(--divider);margin:0 0 14px}
.danger-row{display:flex;align-items:center;justify-content:space-between;gap:14px}
.danger-copy{font-size:11px;color:var(--sub);line-height:1.5}
.btn-outline-danger{flex:none;background:transparent;border:1.5px solid var(--danger-border);color:var(--danger-text);font-size:11.5px;font-weight:600;padding:7px 13px;border-radius:7px;white-space:nowrap;cursor:pointer}
.placeholder{padding:24px;color:var(--sub);font-size:12px;text-align:center}
.policy-pill{font-size:11px;font-weight:700;color:#8e8e93;letter-spacing:.04em;text-transform:uppercase;background:var(--card-bg);display:inline-block;padding:4px 10px;border-radius:6px;margin-bottom:12px}
.policy-heading{font-size:13px;font-weight:600;color:var(--text);margin-bottom:6px;text-align:center}
.policy-body{font-size:11.5px;color:var(--sub);line-height:1.55;max-width:280px;margin:0 auto 16px;text-align:center}
.policy-addrule{border:1px dashed var(--card-border);border-radius:8px;padding:10px;opacity:.5}
.policy-addrule-text{font-size:11px;color:#8e8e93;text-align:left}
.modal-backdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.4);align-items:center;justify-content:center;z-index:2}
.modal-backdrop.show{display:flex}
.modal{background:var(--card-bg);border-radius:12px;box-shadow:0 20px 50px rgba(0,0,0,.4);padding:22px 22px 16px;width:280px;text-align:center}
.modal-icon{width:38px;height:38px;border-radius:50%;background:rgba(196,30,58,.15);display:flex;align-items:center;justify-content:center;margin:0 auto 10px}
.modal-icon-inner{width:22px;height:22px;border-radius:50%;background:var(--danger-border);color:#fff;font-size:14px;font-weight:800;display:flex;align-items:center;justify-content:center}
.modal-title{font-size:13.5px;font-weight:700;color:var(--text);margin-bottom:6px}
.modal-body{font-size:11.5px;color:var(--sub);line-height:1.5;margin-bottom:16px}
.modal-actions{display:flex;gap:8px;justify-content:flex-end}
.btn{padding:6px 14px;border-radius:6px;font-size:12px;cursor:pointer;border:1px solid var(--card-border);color:var(--text);background:transparent}
.btn-danger{background:var(--danger-border);color:#fff;font-weight:600;border:none}
.banner{display:none;background:var(--banner-bg);border-bottom:1px solid var(--banner-border);padding:10px 16px;align-items:center;gap:8px}
.banner.show{display:flex}
.banner-icon{width:16px;height:16px;border-radius:50%;background:var(--danger-border);color:#fff;font-size:11px;font-weight:800;display:flex;align-items:center;justify-content:center;flex:none}
.banner-text{font-size:11px;color:var(--banner-text);line-height:1.4;flex:1}
.banner-retry{font-weight:700;text-decoration:underline;cursor:pointer}
.banner-dismiss{font-size:14px;color:var(--banner-dismiss);cursor:pointer}
.header{display:flex;align-items:center;gap:9px;padding:14px 16px 10px}
.glyph{width:22px;height:22px;border-radius:6px;background:linear-gradient(140deg,#1d1d1f,#48484a)}
@media (prefers-color-scheme: dark){.glyph{background:linear-gradient(140deg,#e8e8ea,#aeb0b6)}}
.title{font-size:13.5px;font-weight:600;color:var(--text);flex:1}
.active{display:flex;align-items:center;gap:5px;margin-right:6px}
.active .dot{width:6px;height:6px;border-radius:50%;background:var(--green)}
.active .label{font-size:10.5px;color:var(--green);font-weight:600}
.gear{width:20px;height:20px;border-radius:5px;background:var(--gear-bg);display:flex;align-items:center;justify-content:center;font-size:11px;color:var(--sub);cursor:pointer}
.avatar-row{padding:0 16px 12px;display:flex;align-items:center;gap:9px}
.avatar{width:24px;height:24px;border-radius:50%;background:var(--avatar-bg);display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;color:var(--avatar-text)}
.handle{font-size:12px;color:var(--text);flex:1}
.checkmark{width:14px;height:14px;border-radius:50%;background:var(--green);display:flex;align-items:center;justify-content:center;color:#fff;font-size:9px}
.divider{height:1px;background:var(--divider);margin:0 16px}
.row{padding:14px 16px;display:flex;align-items:center;justify-content:space-between}
.row.compact{padding:8px 16px}
.row-label{font-size:12.5px;font-weight:600;color:var(--text)}
.row.compact .row-label{font-weight:400;font-size:12.5px}
.row-sub{font-size:10.5px;color:var(--sub)}
.toggle{width:36px;height:21px;border-radius:11px;position:relative;cursor:pointer;flex:none;background:#d1d1d6}
@media (prefers-color-scheme: dark){.toggle{background:rgba(255,255,255,.16)}}
.toggle.on{background:var(--green)}
.toggle .knob{position:absolute;top:2px;left:2px;width:17px;height:17px;border-radius:50%;background:#fff;box-shadow:0 1px 2px rgba(0,0,0,.25);transition:left .15s}
.toggle.on .knob{left:17px}
.section-header{padding:12px 16px 4px;font-size:10.5px;font-weight:600;color:var(--sub);text-transform:uppercase;letter-spacing:.03em}
.scope-list{padding:8px 16px 4px}
.scope-row{display:flex;align-items:center;gap:9px;border:1px solid var(--scope-border);border-radius:8px;padding:8px 10px;margin-bottom:7px}
.scope-row.selectable{cursor:pointer}
.scope-row.selected{border:1.5px solid var(--accent);background:var(--accent-bg)}
.scope-row.locked{opacity:.45}
.scope-row.locked-todo{opacity:.35}
.scope-radio{width:14px;height:14px;border-radius:50%;border:1.5px solid var(--scope-radio);flex:none}
.scope-row.selected .scope-radio{border:4px solid var(--accent)}
.scope-label{font-size:12px;color:var(--text);flex:1}
.scope-row.selected .scope-label{font-weight:600}
.scope-lock{font-size:13px}
.scope-pill{font-size:9px;border:1px solid var(--scope-radio);border-radius:3px;padding:1px 5px;color:var(--sub)}
.scope-caption{font-size:10.5px;color:var(--sub);opacity:.85;line-height:1.4;padding:2px 2px 12px}
.footer{padding:12px 16px}
.footer-link{font-size:11.5px;color:var(--accent);font-weight:600;margin-bottom:3px;cursor:pointer}
.footer-sub{font-size:10.5px;color:var(--sub);line-height:1.4}
.linking{padding:16px}
.linking .header{padding:0 0 14px}
.linking-box{background:rgba(127,127,127,.08);border:1px solid var(--border);border-radius:10px;padding:12px;display:flex;align-items:center;gap:10px}
.spinner{width:16px;height:16px;border-radius:50%;border:2.5px solid rgba(0,122,255,.25);border-top-color:var(--accent);animation:spin .9s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.linking-text{font-size:12.5px;color:var(--text)}
.linking-help{font-size:11px;color:var(--sub);margin:10px 2px 0}
.cancel-link{font-size:12px;color:var(--accent);font-weight:600;text-align:center;margin-top:12px;cursor:pointer}
`;

const TRAY_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Compute Provider</title>
<style>${TRAY_STYLE}</style>
</head>
<body>
<div class="panel">
  <div class="panel-blur"></div>
  <div class="banner" id="banner">
    <div class="banner-icon">!</div>
    <div class="banner-text">Couldn't connect identity — request expired. <span class="banner-retry" id="bannerRetry">Retry</span></div>
    <div class="banner-dismiss" id="bannerDismiss">&times;</div>
  </div>

  <div id="linkingView" class="linking" style="display:none">
    <div class="header"><div class="glyph"></div><div class="title">Compute Provider</div></div>
    <div class="linking-box"><div class="spinner"></div><div class="linking-text">Waiting for approval in your browser…</div></div>
    <div class="linking-help">Local jobs keep running while you finish.</div>
    <div class="cancel-link" id="cancelLink">Cancel</div>
  </div>

  <div id="mainView">
  <div class="appshell">
  <div class="navrail" id="navrail">
    <div class="navitem active" id="navHome" data-view="home">Home</div>
    <div class="navitem" id="navGeneral" data-view="general">General</div>
    <div class="navitem" id="navIdentity" data-view="identity">Identity</div>
    <div class="navitem" id="navPolicy" data-view="policy">Policy</div>
  </div>
  <div class="contentarea">
  <div id="paneHome">
    <div class="header">
      <div class="glyph"></div>
      <div class="title">Compute Provider</div>
      <div class="active"><span class="dot"></span><span class="label">Active</span></div>
      <div class="gear" id="gearBtn">&#9881;</div>
    </div>

    <div class="avatar-row" id="avatarRow" style="display:none">
      <div class="avatar" id="avatarInitial">?</div>
      <div class="handle" id="handleText"></div>
      <div class="checkmark">&#10003;</div>
    </div>
    <div class="divider" id="avatarDivider" style="display:none"></div>

    <div class="row">
      <div><div class="row-label">Dispatching</div><div class="row-sub">Accepting jobs from authorized sources</div></div>
      <div class="toggle" id="toggleDispatch"><div class="knob"></div></div>
    </div>
    <div class="divider"></div>
    <div class="section-header">Job Types</div>
    <div class="row compact">
      <div><div class="row-label">Deno Workers</div><div class="row-sub">Lightweight isolated functions</div></div>
      <div class="toggle" id="toggleWorkers"><div class="knob"></div></div>
    </div>
    <div class="row compact" style="padding-bottom:12px">
      <div><div class="row-label">Containers</div><div class="row-sub">Full OCI containers via runtime</div></div>
      <div class="toggle" id="toggleContainers"><div class="knob"></div></div>
    </div>
    <div class="divider"></div>
    <div class="section-header">Accept Jobs From</div>
    <div class="scope-list">
      <div class="scope-row" id="scopeOnlyMe" data-scope="only_me">
        <div class="scope-radio"></div><div class="scope-label">Only me</div>
      </div>
      <div class="scope-row" id="scopeDirectNetwork" data-scope="direct_network">
        <div class="scope-radio"></div><div class="scope-label">Direct network</div>
      </div>
      <div class="scope-row locked-todo">
        <div class="scope-radio"></div><div class="scope-label">Policy-based</div><div class="scope-pill">TODO</div>
      </div>
      <div class="scope-caption" id="scopeCaption">No remote scopes are available yet — nothing dispatches jobs here until you link an identity.</div>
    </div>
    <div class="divider"></div>
    <div class="footer" id="footerUnlinked">
      <div class="footer-link" id="connectLink">Connect ATProto identity</div>
      <div class="footer-sub">Unlocks "Only me" and "Direct network" scoping.</div>
    </div>
    <div class="footer" id="footerLinked" style="display:none">
      <div class="footer-link" id="openSettingsLink">Open Settings…</div>
    </div>
  </div>

  <div id="paneGeneral" class="settings-content" style="display:none">
    <div class="placeholder">General settings are coming soon.</div>
  </div>
  <div id="paneIdentity" class="settings-content" style="display:none">
    <div class="section-title">Hardware-bound Key</div>
    <div class="card">
      <div class="card-label">Secure Enclave Key ID</div>
      <div class="card-mono" id="keyIdText">—</div>
    </div>
    <div class="section-title">ATProto Association</div>
    <div class="card" id="assocCard">
      <div class="assoc-row" id="assocLinked" style="display:none">
        <div class="assoc-avatar" id="assocAvatar">?</div>
        <div class="assoc-info"><div class="assoc-handle" id="assocHandle"></div><div class="assoc-date" id="assocDate"></div><div class="btn-proof" id="assocProof" style="display:none">View Association Proof</div></div>
        <div class="assoc-action" id="unlinkBtn">Unlink</div>
      </div>
      <div class="assoc-row" id="assocUnlinked">
        <div class="assoc-info"><div class="assoc-handle">Not linked</div></div>
        <div class="assoc-action" id="connectBtn">Connect identity</div>
      </div>
    </div>
    <div class="hr"></div>
    <div class="section-title danger">Danger Zone</div>
    <div class="danger-row">
      <div class="danger-copy">Creates a brand-new Secure Enclave key pair. Your current ATProto association becomes invalid.</div>
      <div class="btn-outline-danger" id="regenBtn">Regenerate Key…</div>
    </div>
  </div>
  <div id="panePolicy" class="settings-content" style="display:none">
    <div style="text-align:center">
      <div class="policy-pill">Coming soon</div>
      <div class="policy-heading">Policy-based dispatch</div>
      <div class="policy-body">Define rules for exactly which DIDs, domains, or networks may dispatch jobs to this device.</div>
      <div class="policy-addrule"><div class="policy-addrule-text">+ Add rule</div></div>
    </div>
  </div>
  </div>
  </div>
  </div>

  <div class="modal-backdrop" id="regenModal">
    <div class="modal">
      <div class="modal-icon"><div class="modal-icon-inner">!</div></div>
      <div class="modal-title">Regenerate device key?</div>
      <div class="modal-body" id="regenBody">This creates a new key and invalidates your ATProto association. You'll need to sign in again to re-link.</div>
      <div class="modal-actions">
        <div class="btn" id="regenCancel">Cancel</div>
        <div class="btn btn-danger" id="regenConfirm">Regenerate</div>
      </div>
    </div>
  </div>
</div>
<script>
(function(){
var $=function(id){return document.getElementById(id);};
var APP_TOKEN='__APP_TOKEN__';
var _fetch=window.fetch;
window.fetch=function(input,init){init=init||{};init.headers=Object.assign({},init.headers,{'X-App-Token':APP_TOKEN});return _fetch(input,init);};
var state=null;
var views={home:$('paneHome'),general:$('paneGeneral'),identity:$('paneIdentity'),policy:$('panePolicy')};
var navItems={home:$('navHome'),general:$('navGeneral'),identity:$('navIdentity'),policy:$('navPolicy')};
var panelEl=document.querySelector('.panel');
var navrailEl=$('navrail');
var currentPanelWidth=320;
function showView(name){
  Object.keys(views).forEach(function(k){
    views[k].style.display=k===name?'':'none';
    navItems[k].className='navitem'+(k===name?' active':'');
  });
  var expanded=name!=='home';
  var growing=expanded&&currentPanelWidth<560;
  var shrinking=!expanded&&currentPanelWidth>320;
  currentPanelWidth=expanded?560:320;
  // Native window resize is instant while the CSS width transition takes
  // ~100ms, so sequence them to avoid clipping content mid-transition:
  // grow the native window first (extra room is harmless), shrink it only
  // after the CSS transition has visually finished.
  if(growing)reportHeight();
  navrailEl.className='navrail'+(expanded?' show':'');
  panelEl.style.width=currentPanelWidth+'px';
  if(shrinking)setTimeout(reportHeight,330);else if(!growing)reportHeight();
}
Object.keys(navItems).forEach(function(k){navItems[k].addEventListener('click',function(){showView(k);});});

function setToggle(el,on){el.className='toggle'+(on?' on':'');}

function patchState(patch){
  fetch('/api/state',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(patch)}).then(render);
}

function render(){
  fetch('/api/state').then(function(r){return r.json();}).then(function(d){
    state=d;
    var linked=!!(d.session&&d.session.handle);

    if(d.oauthInFlight){
      $('linkingView').style.display='';
      $('mainView').style.display='none';
      $('banner').className='banner';
      return;
    }
    $('linkingView').style.display='none';
    $('mainView').style.display='';

    if(d.oauthError){
      $('banner').className='banner show';
    }else{
      $('banner').className='banner';
    }

    if(linked){
      $('avatarRow').style.display='flex';
      $('avatarDivider').style.display='';
      $('avatarInitial').textContent=d.session.handle.charAt(0).toUpperCase();
      $('handleText').textContent='@'+d.session.handle;
      $('footerUnlinked').style.display='none';
      $('footerLinked').style.display='';
    }else{
      $('avatarRow').style.display='none';
      $('avatarDivider').style.display='none';
      $('footerUnlinked').style.display='';
      $('footerLinked').style.display='none';
    }

    setToggle($('toggleDispatch'),d.dispatchingEnabled);
    setToggle($('toggleWorkers'),d.workersEnabled);
    setToggle($('toggleContainers'),d.containersEnabled);

    var only=$('scopeOnlyMe'),direct=$('scopeDirectNetwork');
    only.className='scope-row'+(linked?' selectable':' locked');
    direct.className='scope-row'+(linked?' selectable':' locked');
    only.querySelector('.scope-lock')&&only.removeChild(only.querySelector('.scope-lock'));
    if(!linked){
      if(!only.querySelector('.scope-lock')){var l1=document.createElement('div');l1.className='scope-lock';l1.textContent='\\uD83D\\uDD12';only.appendChild(l1);}
      if(!direct.querySelector('.scope-lock')){var l2=document.createElement('div');l2.className='scope-lock';l2.textContent='\\uD83D\\uDD12';direct.appendChild(l2);}
    }else{
      var lo=only.querySelector('.scope-lock');if(lo)only.removeChild(lo);
      var ld=direct.querySelector('.scope-lock');if(ld)direct.removeChild(ld);
      if(d.acceptScope==='only_me')only.classList.add('selected');else only.classList.remove('selected');
      if(d.acceptScope==='direct_network')direct.classList.add('selected');else direct.classList.remove('selected');
    }
    $('scopeCaption').style.display=linked?'none':'';

    $('keyIdText').textContent=d.persistentKeyId||'—';
    $('assocLinked').style.display=linked?'flex':'none';
    $('assocUnlinked').style.display=linked?'none':'flex';
    if(linked){
      $('assocAvatar').textContent=d.session.handle.charAt(0).toUpperCase();
      $('assocHandle').textContent='@'+d.session.handle;
      $('assocDate').textContent=d.linkedAt?('Linked '+new Date(d.linkedAt).toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'})):'';
      var proofEl=$('assocProof');
      if(d.associationRecordUri){
        proofEl.style.display=''; proofEl.onclick=function(){
          fetch('/api/open-external',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({url:'https://pdsls.dev/'+d.associationRecordUri})});
        };
      } else { proofEl.style.display='none'; }
      $('regenBody').textContent="This creates a new key and invalidates your ATProto association. You'll need to sign in again to re-link @"+d.session.handle+".";
    }

    if(d.requestedView&&views[d.requestedView])showView(d.requestedView);
    reportHeight();
  });
}

var lastReportedHeight=0;
var lastReportedWidth=0;
function reportHeight(){
  requestAnimationFrame(function(){
    var w=currentPanelWidth;
    var h=document.body.scrollHeight;
    if(h===lastReportedHeight&&w===lastReportedWidth)return;
    lastReportedHeight=h;
    lastReportedWidth=w;
    fetch('/api/tray-resize',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({width:w,height:h})});
  });
}

$('gearBtn').addEventListener('click',function(){showView('identity');});
$('openSettingsLink').addEventListener('click',function(){showView('identity');});
$('unlinkBtn').addEventListener('click',function(){fetch('/api/atproto/unlink',{method:'POST'}).then(render);});
$('connectBtn').addEventListener('click',startConnect);
$('regenBtn').addEventListener('click',function(){$('regenModal').className='modal-backdrop show';});
$('regenCancel').addEventListener('click',function(){$('regenModal').className='modal-backdrop';});
$('regenConfirm').addEventListener('click',function(){
  fetch('/api/atproto/regenerate-key',{method:'POST'}).then(function(){
    $('regenModal').className='modal-backdrop';
    render();
  });
});
$('toggleDispatch').addEventListener('click',function(){patchState({dispatchingEnabled:!(state&&state.dispatchingEnabled)});});
$('toggleWorkers').addEventListener('click',function(){patchState({workersEnabled:!(state&&state.workersEnabled)});});
$('toggleContainers').addEventListener('click',function(){patchState({containersEnabled:!(state&&state.containersEnabled)});});
$('scopeOnlyMe').addEventListener('click',function(){if(state&&state.session)patchState({acceptScope:'only_me'});});
$('scopeDirectNetwork').addEventListener('click',function(){if(state&&state.session)patchState({acceptScope:'direct_network'});});
$('bannerDismiss').addEventListener('click',function(){$('banner').className='banner';});
$('bannerRetry').addEventListener('click',function(){startConnect();});
$('cancelLink').addEventListener('click',function(){fetch('/api/atproto/cancel-oauth',{method:'POST'}).then(render);});

function startConnect(){
  var handle=window.prompt('ATProto handle','alice.bsky.social');
  if(!handle)return;
  fetch('/api/atproto/start-oauth',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({handle:handle})}).then(render);
}
$('connectLink').addEventListener('click',startConnect);

render();
setInterval(render,2000);
})();
</script>
</body>
</html>`;

