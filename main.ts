// @ts-nocheck — FFI + deno desktop runtime APIs not in compile-time types
/**
 * macOS App Attest — Deno Desktop App
 *
 * Uses DCAppAttestService (DeviceCheck framework) via FFI to:
 *  1. Check if App Attest is supported on this device
 *  2. Generate a hardware-bound key pair in the Secure Enclave
 *  3. Attest the key (Apple-signed proof the key is genuine)
 *  4. Generate assertions (prove a request comes from the attested app)
 *
 * Prerequisites:
 *   ./build_bridge.sh           — compile the FFI bridge dylib
 *   deno desktop main.ts        — run the desktop app
 *
 * Entitlements (after build):
 *   codesign -f -s - --entitlements app.entitlements dist/macOS-App-Attest.app
 */

// =========================================================================
// 0. Structured JSON file logger
// =========================================================================

function resolveLogDir(): string {
  // Try cwd first (works in dev mode: deno desktop main.ts).
  const cwd = Deno.cwd();
  const cwdLogs = `${cwd}/logs`;
  try {
    Deno.mkdirSync(cwdLogs, { recursive: true });
    Deno.statSync(cwdLogs);
    return cwdLogs;
  } catch { /* cwd not writable (e.g. compiled app launched via open) */ }
  // Fall back to HOME (always writable for desktop apps).
  const home = Deno.env.get("HOME");
  if (home) {
    const homeLogs = `${home}/logs/app-attest`;
    try {
      Deno.mkdirSync(homeLogs, { recursive: true });
      return homeLogs;
    } catch { /* HOME not writable either */ }
  }
  return null;
}

const LOG_DIR = resolveLogDir();
let logFile: Deno.FsFile | null = null;
let LOG_PATH: string | null = null;
let logBuf: string[] = [];
let flushTimer: number | null = null;

function openLogFile() {
  if (!LOG_DIR) return;
  const ts = new Date().toISOString().replace(/:/g, "-");
  LOG_PATH = `${LOG_DIR}/${ts}.ndjson`;
  try {
    logFile = Deno.openSync(LOG_PATH, { write: true, create: true, append: true });
  } catch (e) {
    console.error("Failed to open log file:", LOG_PATH, e);
  }
}

function flushLogs() {
  if (!logFile || logBuf.length === 0) return;
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(logBuf.join("\n") + "\n");
    logFile.writeSync(data);
    logBuf = [];
  } catch {
    // Degrade silently
  }
  flushTimer = null;
}

function scheduleFlush() {
  if (flushTimer !== null) return;
  flushTimer = setTimeout(() => {
    flushLogs();
    flushTimer = null;
  }, 1000);
}

// In-memory ring buffer (last 500 entries) for UI log viewer.
const LOG_RING: string[] = [];
const LOG_RING_MAX = 500;

function writeLog(level: string, message: string, meta?: Record<string, unknown>) {
  const entry = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    message,
    ...meta,
  });

  // Ring buffer
  if (LOG_RING.length >= LOG_RING_MAX) LOG_RING.shift();
  LOG_RING.push(entry);

  // Console output
  if (level === "error") console.error(entry);
  else if (level === "warn") console.warn(entry);
  else console.log(entry);

  // File output — batch writes to avoid per-line fsync storms
  if (logFile) {
    logBuf.push(entry);
    scheduleFlush();
  }
}

const log = {
  info: (msg: string, meta?: Record<string, unknown>) => writeLog("info", msg, meta),
  warn: (msg: string, meta?: Record<string, unknown>) => writeLog("warn", msg, meta),
  error: (msg: string, meta?: Record<string, unknown>) => writeLog("error", msg, meta),
  debug: (msg: string, meta?: Record<string, unknown>) => writeLog("debug", msg, meta),
};

openLogFile();
log.info("App starting", { cwd: Deno.cwd(), logDir: LOG_DIR });

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
    keychain_delete: { parameters: ["pointer"], result: "i32" },
  });
  log.info("Bridge loaded", { symbols: Object.keys(bridge.symbols) });
} catch (e) {
  bridgeError = e instanceof Error ? e.message : String(e);
  log.error("Failed to load devicecheck_bridge.dylib", { error: bridgeError });
}

// =========================================================================
// 2. C memory helpers
// =========================================================================

const encoder = new TextEncoder();

function encodeCStr(s) {
  return encoder.encode(s + "\0");
}

function readCStr(ptr) {
  if (ptr === null) return "";
  return new Deno.UnsafePointerView(ptr).getCString();
}

function allocSizeT() {
  return new Uint8Array(new BigUint64Array([0n]).buffer);
}

function readSizeT(buf) {
  return Number(new DataView(buf.buffer).getBigUint64(0, true));
}

// =========================================================================
// 3. Attestation API layer
// =========================================================================

class AppAttestError extends Error {
  constructor(message) {
    super(message);
    this.name = "AppAttestError";
  }
}

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

const KC_SESSION_KEY = "oauth-session";

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
  const lenBuf = new BigUint64Array(1);
  const keyPtr = Deno.UnsafePointer.of(keyBuf);
  const lenPtr = Deno.UnsafePointer.of(new Uint8Array(lenBuf.buffer));
  const ptr = bridge.symbols.keychain_load(keyPtr, lenPtr);
  if (!ptr) return null;
  const len = Number(lenBuf[0]);
  const bytes = new Uint8Array(Deno.UnsafePointerView.getArrayBuffer(ptr, len));
  bridge.symbols.dc_free_buffer(ptr);
  return new TextDecoder().decode(bytes);
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
// 4. ATProto OAuth — server-side PKCE+PAR+DPoP with system browser loopback
// =========================================================================

const BADGE_BLUE_KEYS_COLLECTION = "com.publicdomainrelay.temp.badgeBlueKeys";

const OAUTH_CLIENT_ID = "https://attest--johnandersen777-bsky-social.fedproxy.com/oauth-client-metadata.json";
const OAUTH_REDIRECT_URI = "com.fedproxy.attest--johnandersen777-bsky-social:/callback";

let oauthCodeVerifier: string | null = null;
let oauthDpopKeyPair: CryptoKeyPair | null = null;
let oauthDpopJwk: Record<string, string> | null = null;
let oauthOngoingState: string | null = null;
let oauthServerNonce: string | null = null;
let oauthClientId: string | null = null;

// Persistent device key — generated once at startup, reused across records
let persistentKeyId: string | null = null;
try {
  if (bridge && !bridgeError) {
    persistentKeyId = generateKey();
    log.info("persistent device key generated", { keyId: persistentKeyId });
    bridge.symbols.url_register_handler();
    log.info("URL scheme handler registered (pdrattest://)");
  }
} catch (e) {
  log.error("failed to generate persistent key", { error: String(e) });
}

interface OAuthSession {
  accessJwt: string;
  refreshJwt: string;
  did: string;
  handle: string;
  pds: string;
  dpopKeyPair: CryptoKeyPair;
  dpopPublicJwk: Record<string, string>;
}

let oauthSession: OAuthSession | null = null;
let SERVE_PORT = 0;

// Restore session from Keychain on startup
(async () => {
  const saved = await loadSession();
  if (saved) {
    oauthSession = saved;
    log.info("session restored from keychain", { did: saved.did, handle: saved.handle });
  }
})();

function base64url(bytes: Uint8Array): string {
  let s = btoa(String.fromCharCode(...bytes));
  return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function randomHex(n: number): string {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

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
    scope: `atproto repo:${BADGE_BLUE_KEYS_COLLECTION}?action=create`,
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

// =========================================================================
// 5. BrowserWindow — create BEFORE HTTP server so bindings are registered
//     before the desktop runtime navigates the webview to app://.
// =========================================================================

const win = new Deno.BrowserWindow({
  title: "macOS App Attest",
  width: 720,
  height: 980,
});
log.info("BrowserWindow created", { windowId: win.windowId });

// Register bindings BEFORE HTTP server. Desktop runtime navigates
// webview to app:// once the server is ready — bindings must be in
// place before navigation so the page sees them.
try {
  win.bind("generateKey", () => {
    log.info("generateKey: binding called");
    const t0 = Date.now();
    const keyId = generateKey();
    log.info("generateKey: done", { keyId, elapsedMs: Date.now() - t0 });
    return { keyId };
  });
  log.info("Binding registered: generateKey");
} catch (e) {
  log.error("Failed to bind generateKey", { error: String(e) });
}

try {
  win.bind("attestKey", async (keyId, challenge) => {
    log.info("attestKey: binding called", { keyId });
    const hash = await sha256(encoder.encode(challenge));
    const data = attestKey(keyId, hash);
    return { hex: toHex(data), length: data.length };
  });
  log.info("Binding registered: attestKey");
} catch (e) {
  log.error("Failed to bind attestKey", { error: String(e) });
}

try {
  win.bind("generateAssertion", async (keyId, clientData) => {
    log.info("generateAssertion: binding called", { keyId });
    const hash = await sha256(encoder.encode(clientData));
    const data = generateAssertion(keyId, hash);
    return { hex: toHex(data), length: data.length };
  });
  log.info("Binding registered: generateAssertion");
} catch (e) {
  log.error("Failed to bind generateAssertion", { error: String(e) });
}

try {
  win.bind("getLogs", () => {
    return { entries: [...LOG_RING] };
  });
  log.info("Binding registered: getLogs");
} catch (e) {
  log.error("Failed to bind getLogs", { error: String(e) });
}

// =========================================================================
// 5. HTTP server. win.bind() calls (registered above) expose each function
//    in the webview as `bindings.<name>()`. Per the Deno desktop docs
//    (/runtime/desktop/bindings/) this is the primary IPC — the webview just
//    calls `await bindings.generateKey()`, etc. We also serve a small
//    /app.js that wires the UI to these bindings.
// =========================================================================

const APP_JS = `(function(){
var $=function(id){return document.getElementById(id);};

function api(method,path,body){var init={method:method};if(body){init.headers={'content-type':'application/json'};init.body=JSON.stringify(body);}return fetch(path,init).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.error||('HTTP '+r.status));return d;});});}

function setResult(el,data){
  el.className='result ok';
  el.innerHTML='<div>'+data.length+' bytes<\\/div><div>'+data.hex+'<\\/div>';
}
function setError(el,e){
  el.className='result error';
  el.textContent=(e&&(e.message||e.name))||String(e);
}

function showBanner(msg){
  var b=$('banner');
  b.style.display='block';
  b.style.background='#3a1e2a';
  b.style.color='#f38ba8';
  b.style.padding='10px 16px';
  b.style.borderRadius='10px';
  b.style.fontSize='13px';
  b.style.marginBottom='16px';
  b.style.wordBreak='break-all';
  b.textContent=msg;
}

$('btnGenKey').addEventListener('click',async function(){
  var el=$('keyResult');
  this.disabled=true;
  el.className='result';
  el.textContent='Generating\\u2026';
  try{
    var d=await api('POST','/api/generate-key');
    el.className='result ok';
    el.textContent=d.keyId;
    $('attestKeyId').value=d.keyId;
    $('assertKeyId').value=d.keyId;
  }catch(e){setError(el,e);}
  this.disabled=false;
});

$('btnAttest').addEventListener('click',async function(){
  var el=$('attestResult'),k=$('attestKeyId').value.trim(),c=$('attestChallenge').value.trim();
  if(!k||!c){el.className='result error';el.textContent=(!k?'Key ID':'Challenge')+' required.';return}
  this.disabled=true;
  el.className='result';el.textContent='Attesting\\u2026';
  try{var d=await api('POST','/api/attest-key',{keyId:k,challenge:c});setResult(el,d);}catch(e){setError(el,e);}
  this.disabled=false;
});

$('btnAssert').addEventListener('click',async function(){
  var el=$('assertResult'),k=$('assertKeyId').value.trim(),v=$('assertData').value.trim();
  if(!k||!v){el.className='result error';el.textContent=(!k?'Key ID':'Client data')+' required.';return}
  this.disabled=true;
  el.className='result';el.textContent='Generating assertion\\u2026';
  try{var d=await api('POST','/api/generate-assertion',{keyId:k,clientData:v});setResult(el,d);}catch(e){setError(el,e);}
  this.disabled=false;
});

var autoRefreshTimer=null;
async function refreshLogs(){
  var viewer=$('logViewer');
  try{
    var r=await fetch('/api/logs');
    var data=await r.json();
    if(!data||!data.entries||!data.entries.length){viewer.innerHTML='<span class=\\'log-line debug\\'>No log entries yet.<\\/span>';return}
    var lines=[],i,entry,obj,ts,cls;
    for(i=0;i<data.entries.length;i++){entry=data.entries[i];
      try{obj=JSON.parse(entry);ts=obj.ts?obj.ts.slice(11,23):'';cls='log-line '+(obj.level||'info');lines.push('<span class=\\''+cls+'\\'>'+ts+' '+ (obj.message||entry)+'<\\/span>');}
      catch(_){lines.push('<span class=\\'log-line info\\'>'+entry+'<\\/span>');}
    }
    viewer.innerHTML=lines.join('\\n');viewer.scrollTop=viewer.scrollHeight;
  }catch(e){viewer.innerHTML='<span class=\\'log-line error\\'>Failed: '+(e.message||e)+'<\\/span>';}
}
function startAutoRefresh(){if(autoRefreshTimer)clearInterval(autoRefreshTimer);autoRefreshTimer=setInterval(refreshLogs,2000);}
function stopAutoRefresh(){if(autoRefreshTimer){clearInterval(autoRefreshTimer);autoRefreshTimer=null;}}
$('btnRefreshLogs').addEventListener('click',refreshLogs);
$('chkAutoRefresh').addEventListener('change',function(){if(this.checked)startAutoRefresh();else stopAutoRefresh();});

// Bridge self-test — uses fetch (HTTP works immediately; no bindings race).
(function(){
var bs=$('bridgeStatus');
fetch('/api/health').then(function(r){return r.json();}).then(function(d){
  bs.className='result ok';
  bs.textContent='Bridge OK \\u2014 HTTP serving working. Log entries: '+((d&&d.logEntries)?d.logEntries:'?');
}).catch(function(e){
  bs.className='result error';
  bs.textContent='Bridge FAILED: '+(e.message||e);
  showBanner('Bridge unavailable: '+(e.message||e));
});

refreshLogs();
startAutoRefresh();
})();
})();`;

function buildHTML() {
  const statusClass = bridgeError ? "fail" : isSupported() ? "ok" : "warn";
  const statusText = bridgeError
    ? "Bridge not loaded: " + bridgeError
    : isSupported()
    ? "App Attest supported on this device"
    : "App Attest not supported on this device. On macOS, requires macOS 27+ (announced WWDC 2026). Current device may also need Secure Enclave and valid entitlement.";
  return HTML
    .replace("{{STATUS_CLASS}}", statusClass)
    .replace("{{STATUS_TEXT}}", statusText)
    .replace("{{LOG_PATH}}", LOG_PATH ?? "not writable — logs to console only");
}

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
        scope: `atproto repo:${BADGE_BLUE_KEYS_COLLECTION}?action=create`,
        token_endpoint_auth_method: "none",
        client_name: "macOS App Attest",
      }), { headers: { "content-type": "application/json" } });
    }

    if (path === "/app.js") {
      return new Response(APP_JS, {
        headers: { "content-type": "application/javascript; charset=utf-8" },
      });
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
          log.info("oauth: session stored", { did: info.did, handle: info.handle });
          saveSession(oauthSession).catch((e) => log.error("keychain save failed", { error: String(e) }));
          return new Response(
            `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Authenticated</title><style>body{font-family:-apple-system,sans-serif;background:#1e1e2e;color:#cdd6f4;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center}.ok{color:#a6e3a1;font-size:24px;margin-bottom:12px}</style></head><body><div><div class="ok">Authenticated</div><p>Signed in as <strong>@${info.handle}</strong></p><p>You may close this window and return to the app.</p></div></body></html>`,
            { headers: { "content-type": "text/html; charset=utf-8" } },
          );
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          log.error("oauth: callback error", { error: msg });
          return new Response(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Auth Error</title><style>body{font-family:-apple-system,sans-serif;background:#1e1e2e;color:#f38ba8;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center}</style></head><body><div><h2>Authentication Error</h2><p>${msg}</p></div></body></html>`, { status: 500, headers: { "content-type": "text/html; charset=utf-8" } });
        }
      }
    }
  }

  if (req.method === "POST") {
    let body: Record<string, unknown> = {};
    if (req.headers.get("content-type")?.includes("application/json")) {
      try { body = await req.json(); } catch { /* use empty */ }
    }

    if (path === "/api/generate-key") {
      try {
        const keyId = generateKey();
        log.info("api: generateKey ok", { keyId });
        return json({ keyId });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        log.error("api: generateKey error", { error: msg });
        return json({ error: msg }, 500);
      }
    }

    if (path === "/api/attest-key") {
      try {
        const keyId = String(body.keyId ?? "");
        const challenge = String(body.challenge ?? "");
        if (!keyId || !challenge) return json({ error: "keyId and challenge required" }, 400);
        const hash = await sha256(encoder.encode(challenge));
        const data = attestKey(keyId, hash);
        log.info("api: attestKey ok", { keyId });
        return json({ hex: toHex(data), length: data.length });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        log.error("api: attestKey error", { error: msg });
        return json({ error: msg }, 500);
      }
    }

    if (path === "/api/generate-assertion") {
      try {
        const keyId = String(body.keyId ?? "");
        const clientData = String(body.clientData ?? "");
        if (!keyId || !clientData) return json({ error: "keyId and clientData required" }, 400);
        const hash = await sha256(encoder.encode(clientData));
        const data = generateAssertion(keyId, hash);
        log.info("api: generateAssertion ok", { keyId });
        return json({ hex: toHex(data), length: data.length });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        log.error("api: generateAssertion error", { error: msg });
        return json({ error: msg }, 500);
      }
    }

    if (path === "/api/atproto/start-oauth") {
      try {
        const handle = String(body.handle ?? "").trim();
        if (!handle) return json({ error: "handle required" }, 400);
        if (!SERVE_PORT) return json({ error: "server not ready" }, 503);
        const { did } = await startOAuth(handle);
        log.info("oauth: authorization started", { did, handle });
        return json({ ok: true, did });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        log.error("oauth: start failed", { error: msg });
        return json({ error: msg }, 500);
      }
    }

    if (path === "/api/atproto/regenerate-key") {
      try {
        persistentKeyId = generateKey();
        log.info("atproto: persistent key regenerated", { keyId: persistentKeyId });
        return json({ ok: true, keyId: persistentKeyId });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        return json({ error: msg }, 500);
      }
    }

    if (path === "/api/atproto/create-key-record") {
      try {
        if (!oauthSession) return json({ error: "not authenticated" }, 401);
        const service = String(body.service ?? "*").trim();
        const did = oauthSession.did;
        const keyId = persistentKeyId ?? generateKey();
        log.info("atproto: using device key", { did, keyId, persisted: !!persistentKeyId });
        const challenge = did;
        const challengeHash = await sha256(encoder.encode(challenge));
        const attestationHex = toHex(attestKey(keyId, challengeHash));
        log.info("atproto: key attested", { keyId, challenge });
        const createEndpoint = `${oauthSession.pds}/xrpc/com.atproto.repo.createRecord`;
        const dpopProof = await createDpopProof(oauthSession.dpopKeyPair, oauthSession.dpopPublicJwk, "POST", createEndpoint, oauthServerNonce, oauthSession.accessJwt);
        const res = await fetch(createEndpoint, {
          method: "POST",
          headers: { "content-type": "application/json", "Authorization": `DPoP ${oauthSession.accessJwt}`, "DPoP": dpopProof },
          body: JSON.stringify({ repo: did, collection: BADGE_BLUE_KEYS_COLLECTION, record: { $type: BADGE_BLUE_KEYS_COLLECTION, keyId, attestation: attestationHex, challenge, service, createdAt: new Date().toISOString() } }),
        });
        const nonce = res.headers.get("DPoP-Nonce");
        if (nonce) oauthServerNonce = nonce;
        if (!res.ok) { const eb = await res.text(); return json({ error: `createRecord: ${res.status} ${eb}` }, 500); }
        const cd = await res.json();
        log.info("atproto: record created — verify with: deno run --allow-net verify-record.ts " + cd.uri, { uri: cd.uri, cid: cd.cid, keyId, service, verify: `deno run --allow-net verify-record.ts ${cd.uri}` });
        return json({ ok: true, uri: cd.uri, cid: cd.cid, keyId, service });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        log.error("create-key-record failed", { error: msg });
        return json({ error: msg }, 500);
      }
    }
  }

  return new Response(buildHTML(), {
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

Deno.serve(
  { port: 0, hostname: "127.0.0.1", onListen({ port }) { SERVE_PORT = port; log.info("HTTP server started", { port }); } },
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
        log.info("oauth: session stored via url scheme", { did: info.did, handle: info.handle });
        saveSession(oauthSession).catch((e) => log.error("keychain save failed", { error: String(e) }));
      }
    } catch (e) {
      log.error("url scheme callback error", { error: String(e) });
    }
  }, 500);
}

// =========================================================================
// 7. Tray icon
// =========================================================================

function resolveTrayIconPath() {
  const name = "tray-icon.png";
  const candidate = `${import.meta.dirname}/${name}`;
  try { Deno.statSync(candidate); return candidate; } catch { /* not there */ }
  const execDir = Deno.execPath().replace(/\/[^/]+$/, "");
  return `${execDir}/${name}`;
}

try {
  const tray = new Deno.Tray();
  tray.setTooltip("macOS App Attest");
  try {
    const iconPath = resolveTrayIconPath();
    const iconBytes = Deno.readFileSync(iconPath);
    tray.setIcon(iconBytes);
    log.info("Tray icon set", { path: iconPath, bytes: iconBytes.length });
  } catch (e) {
    log.warn("Tray icon not loaded", { error: String(e) });
  }
  tray.setMenu([
    { item: { label: "Show Window", id: "show", enabled: true } },
    "separator",
    { item: { label: "Quit", id: "quit", enabled: true } },
  ]);
  tray.addEventListener("menuclick", (e) => {
    if (e.detail.id === "show") win.show();
    if (e.detail.id === "quit") Deno.exit(0);
  });
  tray.addEventListener("click", () => win.show());
  log.info("Tray icon ready");
} catch (e) {
  log.warn("Tray not available", { error: String(e) });
}

// =========================================================================
// 8. Dock menu (macOS only)
// =========================================================================

try {
  Deno.dock.setMenu([
    { item: { label: "New Window", id: "new", enabled: true } },
  ]);
  Deno.dock.addEventListener("menuclick", (e) => {
    if (e.detail.id === "new") {
      new Deno.BrowserWindow({ title: "macOS App Attest", width: 720, height: 980 });
    }
  });
} catch {
  // Dock menu is macOS-only; no-op elsewhere
}

const attestSupported = isSupported();
log.info("App ready", { attestSupported });

// Flush logs before serving
flushLogs();

// =========================================================================
// HTML UI
// =========================================================================

const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>macOS App Attest</title>
<style>
  :root {
    --bg: #1e1e2e;
    --surface: #313244;
    --text: #cdd6f4;
    --sub: #a6adc8;
    --accent: #89b4fa;
    --green: #a6e3a1;
    --red: #f38ba8;
    --border: #45475a;
    --radius: 10px;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Text', sans-serif;
    background: var(--bg);
    color: var(--text);
    padding: 24px;
    max-width: 680px;
    margin: 0 auto;
    -webkit-font-smoothing: antialiased;
  }
  h1 { font-size: 22px; font-weight: 600; margin-bottom: 4px; }
  .subtitle { color: var(--sub); font-size: 13px; margin-bottom: 4px; }
  .logpath { color: var(--sub); font-size: 11px; margin-bottom: 24px; font-family: 'SF Mono', 'Fira Code', monospace; word-break: break-all; }
  .status {
    display: flex; align-items: center; gap: 8px;
    padding: 10px 16px; border-radius: var(--radius);
    font-size: 14px; font-weight: 500; margin-bottom: 24px;
  }
  .status.ok { background: #1e3a2f; color: var(--green); }
  .status.fail { background: #3a1e2a; color: var(--red); }
  .status.warn { background: #2a2a1e; color: #f9e2af; }
  .status .dot { width: 8px; height: 8px; border-radius: 50%; }
  .status.ok .dot { background: var(--green); }
  .status.fail .dot { background: var(--red); }
  .status.warn .dot { background: #f9e2af; }
  section {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px;
    margin-bottom: 16px;
  }
  section h2 {
    font-size: 15px; font-weight: 600; margin-bottom: 14px;
    color: var(--accent);
  }
  .help { font-size: 12px; color: var(--sub); margin-bottom: 10px; }
  label { display: block; font-size: 12px; color: var(--sub); margin: 10px 0 4px; font-weight: 500; }
  label:first-of-type { margin-top: 0; }
  input {
    width: 100%; padding: 8px 12px; border-radius: 6px;
    border: 1px solid var(--border); background: var(--bg);
    color: var(--text); font-size: 13px;
    font-family: 'SF Mono', 'Fira Code', monospace;
  }
  button {
    margin-top: 12px; padding: 8px 18px; border-radius: 6px;
    border: none; font-size: 13px; font-weight: 500; cursor: pointer;
    background: var(--accent); color: var(--bg); transition: opacity .15s;
  }
  button:hover { opacity: .85; }
  button:active { opacity: .7; }
  button:disabled { opacity: .4; cursor: not-allowed; }
  .result {
    margin-top: 12px; padding: 10px 14px; border-radius: 6px;
    background: var(--bg); font-size: 12px;
    font-family: 'SF Mono', 'Fira Code', monospace;
    word-break: break-all; max-height: 200px; overflow-y: auto;
    white-space: pre-wrap;
  }
  .result.ok { color: var(--green); }
  .result.error { color: var(--red); }
  .result.empty { color: var(--sub); font-style: italic; }
  .log-viewer {
    background: var(--bg); border: 1px solid var(--border);
    border-radius: 6px; padding: 10px 14px; margin-top: 8px;
    max-height: 300px; overflow-y: auto;
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 11px; line-height: 1.5; white-space: pre-wrap;
    word-break: break-all;
  }
  .log-line.info { color: var(--text); }
  .log-line.warn { color: #f9e2af; }
  .log-line.error { color: var(--red); }
  .log-line.debug { color: var(--sub); }
  .quick-chip {
    display: inline-block; padding: 4px 12px; border-radius: 14px;
    border: 1px solid var(--border); background: var(--surface);
    color: var(--accent); font-size: 12px; cursor: pointer;
    transition: background .15s;
  }
  .quick-chip:hover { background: var(--border); }
  .quick-chip.active { background: var(--accent); color: var(--bg); border-color: var(--accent); }
</style>
</head>
<body>

<h1>macOS App Attest</h1>
<p class="subtitle">DeviceCheck DCAppAttestService via Deno FFI</p>
<p class="logpath">{{LOG_PATH}}</p>

<div id="status" class="status {{STATUS_CLASS}}"><span class="dot"></span> <span id="statusText">{{STATUS_TEXT}}</span></div>

<div id="banner" style="display:none"></div>

<section>
  <h2>Bridge</h2>
  <p class="help">UI calls Deno via same-origin fetch() to the in-process app:// server. This self-test confirms the channel works.</p>
  <div id="bridgeStatus" class="result empty">Checking bridge…</div>
</section>

<section>
  <h2>1. Generate Key</h2>
  <p class="help">Creates a hardware-bound key pair in the Secure Enclave.</p>
  <button id="btnGenKey">Generate Key</button>
  <div id="keyResult" class="result empty">No key generated yet.</div>
</section>

<section>
  <h2>2. Attest Key</h2>
  <p class="help">Requests an Apple-signed attestation for the key. Challenge is SHA-256 hashed before sending.</p>
  <label for="attestKeyId">Key ID</label>
  <input id="attestKeyId" type="text" placeholder="Paste key ID from step 1">
  <label for="attestChallenge">Challenge (any text)</label>
  <input id="attestChallenge" type="text" value="challenge-nonce-1" placeholder="e.g. server-challenge-nonce">
  <button id="btnAttest">Attest Key</button>
  <div id="attestResult" class="result empty">No attestation yet.</div>
</section>

<section>
  <h2>3. Generate Assertion</h2>
  <p class="help">Creates an assertion signed by the attested key. Verifiable by a server to confirm genuine device + app.</p>
  <label for="assertKeyId">Key ID</label>
  <input id="assertKeyId" type="text" placeholder="Paste key ID from step 1">
  <label for="assertData">Client data (any text)</label>
  <input id="assertData" type="text" value="client-data-1" placeholder="e.g. server-challenge">
  <button id="btnAssert">Generate Assertion</button>
  <div id="assertResult" class="result empty">No assertion yet.</div>
</section>

<section>
  <h2>4. Associate with ATProto Account</h2>
  <p class="help">Link this device's hardware-bound Secure Enclave key to your ATProto identity. Opens your system browser for OAuth, then creates a <code>com.publicdomainrelay.temp.badgeBlueKeys</code> record with Apple-signed attestation.</p>
  <div id="assocLoggedOut">
    <label for="atpHandle">Handle</label>
    <input id="atpHandle" type="text" placeholder="alice.bsky.social" autocomplete="off">
    <div id="handleQuickPick" style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px">
      <span class="quick-chip" data-domain="bsky.social">Bluesky</span>
      <span class="quick-chip" data-domain="">Custom domain</span>
    </div>
    <button id="btnAssociate" style="margin-top:14px">Associate with ATProto Account</button>
    <button id="btnRegenKey" style="margin-top:14px;margin-left:8px;background:var(--surface);color:var(--sub);border:1px solid var(--border);font-size:11px">Regenerate Key</button>
  </div>
  <div id="assocLoggedIn" style="display:none">
    <div id="assocUser" class="result ok" style="margin-bottom:12px"></div>
    <div id="assocResult" class="result empty" style="margin-top:8px">Creating BadgeBlue key…</div>
  </div>
  <div id="assocStatus" class="result empty" style="margin-top:8px"></div>
</section>

<section>
  <h2>Logs</h2>
  <button id="btnRefreshLogs">Refresh</button>
  <label style="display:inline;margin-left:8px;font-size:12px;color:var(--sub)">
    <input type="checkbox" id="chkAutoRefresh" checked> Auto-refresh
  </label>
  <div id="logViewer" class="log-viewer">Loading logs...</div>
</section>

<script src="/app.js"></script>
<script>
(function(){
var $=function(id){return document.getElementById(id);};
var pollTimer=null;
var keyCreated=false;
function setEl(el,c,t){el.className='result '+c;el.textContent=t;}
function createKey(){
  if(keyCreated)return;keyCreated=true;
  var r=$('assocResult');
  setEl(r,'','Creating BadgeBlue key…');
  fetch('/api/atproto/create-key-record',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({service:'*'})})
    .then(function(res){return res.json().then(function(d){if(!res.ok)throw new Error(d.error);return d;});})
    .then(function(d){
      r.className='result ok';
      r.innerHTML="<div>Key created!</div><div>AT URI: <a href='https://pdsls.dev/"+d.uri+"' target='_blank'>"+d.uri+"</a></div><div>keyId: "+d.keyId+"</div>";
    }).catch(function(e){setEl(r,'error',e.message);keyCreated=false;});
}
function showIn(handle,did){
  $('assocLoggedOut').style.display='none';
  $('assocLoggedIn').style.display='';
  $('assocUser').textContent='Logged in as @'+handle+' ('+did+')';
  createKey();
}
function showOut(){
  $('assocLoggedOut').style.display='';
  $('assocLoggedIn').style.display='none';
}
function pollSession(){
  fetch('/api/atproto/session').then(function(r){return r.json();}).then(function(d){
    if(d.loggedIn){showIn(d.handle,d.did);if(pollTimer){clearInterval(pollTimer);pollTimer=null;}$('assocStatus').textContent='';}
  });
}

// Quick-pick chips
document.querySelectorAll('#handleQuickPick .quick-chip').forEach(function(c){
  c.addEventListener('click',function(){
    var d=this.dataset.domain,i=$('atpHandle');
    document.querySelectorAll('#handleQuickPick .quick-chip').forEach(function(x){x.classList.remove('active');});
    this.classList.add('active');
    if(d){i.value=d;i.setSelectionRange(0,0);i.placeholder='your-name.'+d;}
    else{i.value='';i.placeholder='alice.example.com';}
    i.focus();
  });
});

$('btnAssociate').addEventListener('click',function(){
  var s=$('assocStatus'),h=$('atpHandle').value.trim();
  if(!h){setEl(s,'error','Handle required.');return}
  this.disabled=true;setEl(s,'','Opening system browser for OAuth…');
  fetch('/api/atproto/start-oauth',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({handle:h})})
    .then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.error);return d;});})
    .then(function(d){
      setEl(s,'ok','System browser opened. Sign in there, then return here.');
      $('btnAssociate').disabled=false;
      pollSession();if(!pollTimer)pollTimer=setInterval(pollSession,2000);
    }).catch(function(e){setEl(s,'error',e.message);$('btnAssociate').disabled=false;});
});


$('btnRegenKey').addEventListener('click',function(){
  var b=this;b.disabled=true;b.textContent='Generating…';
  fetch('/api/atproto/regenerate-key',{method:'POST',headers:{'content-type':'application/json'}})
    .then(function(r){return r.json();})
    .then(function(d){b.textContent='Regenerated: '+d.keyId.slice(0,12)+'…';b.disabled=false;})
    .catch(function(e){b.textContent='Failed';b.disabled=false;});
});

pollSession();
})();
</script>
</body>
</html>`;
