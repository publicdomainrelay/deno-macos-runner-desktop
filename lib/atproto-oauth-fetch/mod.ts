// ATProto OAuth fetch implementation — PAR + PKCE + DPoP over HTTP fetch.
// Portable: Web Crypto + fetch only, zero Deno-specific APIs.

import type {
  OAuthSession,
} from "@publicdomainrelay/atproto-oauth-common";
import type {
  OAuthCallbackResult,
  OAuthFlow,
} from "@publicdomainrelay/atproto-oauth-abc";

// ===========================================================================
// Pure crypto helpers
// ===========================================================================

async function sha256(data: BufferSource): Promise<Uint8Array> {
  const hash = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hash);
}

function toHex(bytes: Uint8Array): string {
  const parts: string[] = [];
  for (let i = 0; i < bytes.length; i++) {
    parts.push(bytes[i].toString(16).padStart(2, "0"));
  }
  return parts.join("");
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

async function pkceChallenge(verifier: string): Promise<string> {
  const hash = await sha256(new TextEncoder().encode(verifier));
  return base64url(hash);
}

// ===========================================================================
// DPoP helpers
// ===========================================================================

async function generateDpopKey(): Promise<{
  keyPair: CryptoKeyPair;
  publicJwk: Record<string, string>;
}> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey) as Record<string, string>;
  return { keyPair, publicJwk: { kty: jwk.kty!, crv: jwk.crv!, x: jwk.x!, y: jwk.y! } };
}

async function createDpopProof(
  keyPair: CryptoKeyPair,
  publicJwk: Record<string, string>,
  htm: string,
  htu: string,
  nonce?: string | null,
  accessToken?: string | null,
): Promise<string> {
  const enc = new TextEncoder();
  const header = { typ: "dpop+jwt", alg: "ES256", jwk: publicJwk };
  const payload: Record<string, unknown> = {
    jti: randomHex(20), htm, htu, iat: Math.floor(Date.now() / 1000),
  };
  if (nonce) payload.nonce = nonce;
  if (accessToken) payload.ath = base64url(await sha256(enc.encode(accessToken)));
  const headerB64 = base64url(enc.encode(JSON.stringify(header)));
  const payloadB64 = base64url(enc.encode(JSON.stringify(payload)));
  const signingInput = headerB64 + "." + payloadB64;
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, keyPair.privateKey, enc.encode(signingInput),
  );
  return signingInput + "." + base64url(new Uint8Array(sig));
}

// ===========================================================================
// Identity resolution
// ===========================================================================

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
  let didDoc: Record<string, unknown>;
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
  const svc = ((didDoc.service || []) as Array<{ id?: string; type?: string; serviceEndpoint?: string }>).find(
    (s) => s.id === "#atproto_pds" || s.type === "AtprotoPersonalDataServer",
  );
  if (!svc) throw new Error("No PDS in DID doc");
  return svc.serviceEndpoint!;
}

async function getAuthServerMeta(authServer: string): Promise<Record<string, unknown>> {
  const r = await fetch(`${authServer}/.well-known/oauth-authorization-server`);
  if (!r.ok) throw new Error(`Auth metadata: ${r.status}`);
  return r.json();
}

async function resolveAuthServer(handle: string): Promise<{
  did: string; pds: string; authServer: string;
}> {
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

// ===========================================================================
// PAR (Pushed Authorization Request) — stateless: caller owns intermediate
// state; we return it for the caller to store.
// ===========================================================================

export interface ParState {
  codeVerifier: string;
  dpopKeyPair: CryptoKeyPair;
  dpopPublicJwk: Record<string, string>;
  state: string;
  authServer: string;
  did: string;
  requestUri: string;
  oauthServerNonce: string | null;
}

async function pushPar(
  handle: string,
  clientId: string,
  redirectUri: string,
  scope: string,
): Promise<ParState> {
  const { did, authServer } = await resolveAuthServer(handle);
  const meta = await getAuthServerMeta(authServer);
  const parEndpoint: string = meta.pushed_authorization_request_endpoint as string;
  const authEndpoint: string = meta.authorization_endpoint as string;

  const codeVerifier = randomHex(48);
  const codeChallenge = await pkceChallenge(codeVerifier);
  const dpop = await generateDpopKey();
  const state = randomHex(16);

  const parBody = new URLSearchParams({
    client_id: clientId,
    response_type: "code",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    redirect_uri: redirectUri,
    scope,
    state,
  });

  let parDpop = await createDpopProof(dpop.keyPair, dpop.publicJwk, "POST", parEndpoint);
  let parRes = await fetch(parEndpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", "DPoP": parDpop },
    body: parBody.toString(),
  });

  let oauthServerNonce: string | null = null;
  if (parRes.status === 400) {
    const errBody = await parRes.text();
    if (errBody.includes("use_dpop_nonce")) {
      const serverNonce = parRes.headers.get("DPoP-Nonce");
      if (!serverNonce) throw new Error("PAR: server requested nonce but none provided");
      parDpop = await createDpopProof(dpop.keyPair, dpop.publicJwk, "POST", parEndpoint, serverNonce);
      parRes = await fetch(parEndpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", "DPoP": parDpop },
        body: parBody.toString(),
      });
    }
  }
  if (!parRes.ok) throw new Error(`PAR failed: ${parRes.status} ${await parRes.text()}`);

  const parNonce = parRes.headers.get("DPoP-Nonce");
  if (parNonce) oauthServerNonce = parNonce;
  const requestUri: string = (await parRes.json()).request_uri;
  if (!requestUri) throw new Error("No request_uri");

  return {
    codeVerifier, dpopKeyPair: dpop.keyPair, dpopPublicJwk: dpop.publicJwk,
    state, authServer: authEndpoint, did, requestUri, oauthServerNonce,
  };
}

// ===========================================================================
// Token exchange
// ===========================================================================

async function exchangeCode(
  tokenEndpoint: string,
  code: string,
  redirectUri: string,
  clientId: string,
  codeVerifier: string,
  dpopKeyPair: CryptoKeyPair,
  dpopPublicJwk: Record<string, string>,
  serverNonce: string | null,
): Promise<{ accessToken: string; refreshToken: string; sub: string; oauthServerNonce: string | null }> {
  const doExchange = async (nonce: string | null): Promise<Response> => {
    const proof = await createDpopProof(dpopKeyPair, dpopPublicJwk, "POST", tokenEndpoint, nonce);
    return fetch(tokenEndpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", "DPoP": proof },
      body: new URLSearchParams({
        grant_type: "authorization_code", code, redirect_uri: redirectUri,
        client_id: clientId, code_verifier: codeVerifier,
      }).toString(),
    });
  };

  let res = await doExchange(serverNonce);
  if (res.status === 400) {
    const errBody = await res.text();
    if (errBody.includes("use_dpop_nonce")) {
      const newNonce = res.headers.get("DPoP-Nonce");
      if (!newNonce) throw new Error("Token exchange: server requested nonce but none provided");
      res = await doExchange(newNonce);
    }
  }
  if (!res.ok) throw new Error(`Token exchange: ${res.status} ${await res.text()}`);

  const newNonce = res.headers.get("DPoP-Nonce") || null;
  const data = await res.json();
  return {
    accessToken: data.access_token, refreshToken: data.refresh_token,
    sub: data.sub, oauthServerNonce: newNonce || serverNonce,
  };
}

// ===========================================================================
// Session validation
// ===========================================================================

async function fetchSessionInfo(
  pds: string,
  accessToken: string,
  dpopKeyPair: CryptoKeyPair,
  dpopPublicJwk: Record<string, string>,
  serverNonce: string | null,
): Promise<{ handle: string; did: string; oauthServerNonce: string | null }> {
  const endpoint = `${pds}/xrpc/com.atproto.server.getSession`;

  const doGetSession = async (nonce: string | null): Promise<Response> => {
    const proof = await createDpopProof(dpopKeyPair, dpopPublicJwk, "GET", endpoint, nonce, accessToken);
    return fetch(endpoint, {
      headers: { "Authorization": `DPoP ${accessToken}`, "DPoP": proof },
    });
  };

  let res = await doGetSession(serverNonce);
  if (res.status === 400 || res.status === 401) {
    const errBody = await res.text();
    if (errBody.includes("use_dpop_nonce")) {
      const newNonce = res.headers.get("DPoP-Nonce");
      if (newNonce) {
        res = await doGetSession(newNonce);
      }
    }
  }

  const newNonce = res.headers.get("DPoP-Nonce") || null;
  if (!res.ok) throw new Error(`getSession: ${res.status} ${await res.text()}`);
  const data = await res.json();
  return { handle: data.handle, did: data.did, oauthServerNonce: newNonce || serverNonce };
}

async function refreshSession(
  saved: OAuthSession,
  clientId: string,
  serverNonce: string | null,
): Promise<{ session: OAuthSession; oauthServerNonce: string | null }> {
  const mr = await fetch(`${saved.pds}/.well-known/oauth-protected-resource`);
  if (!mr.ok) throw new Error(`PDS metadata: ${mr.status}`);
  const authServers: string[] = (await mr.json()).authorization_servers;
  if (!authServers?.[0]) throw new Error("No authorization_servers");
  const meta = await getAuthServerMeta(authServers[0]);
  const tokenEndpoint: string = meta.token_endpoint as string;

  const doRefresh = async (nonce: string | null): Promise<Response> => {
    const proof = await createDpopProof(saved.dpopKeyPair, saved.dpopPublicJwk, "POST", tokenEndpoint, nonce);
    return fetch(tokenEndpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", "DPoP": proof },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: saved.refreshJwt,
        client_id: clientId,
      }).toString(),
    });
  };

  let res = await doRefresh(serverNonce);
  if (res.status === 400) {
    const errBody = await res.text();
    if (errBody.includes("use_dpop_nonce")) {
      const newNonce = res.headers.get("DPoP-Nonce");
      if (!newNonce) throw new Error("Token refresh: server requested nonce but none provided");
      res = await doRefresh(newNonce);
    }
  }
  if (!res.ok) throw new Error(`Token refresh: ${res.status} ${await res.text()}`);

  const newNonce = res.headers.get("DPoP-Nonce") || null;
  const data = await res.json();
  return {
    session: {
      accessJwt: data.access_token,
      refreshJwt: data.refresh_token ?? saved.refreshJwt,
      did: saved.did, handle: saved.handle, pds: saved.pds,
      dpopKeyPair: saved.dpopKeyPair, dpopPublicJwk: saved.dpopPublicJwk,
    },
    oauthServerNonce: newNonce || serverNonce,
  };
}

// ===========================================================================
// OAuthFlow factory — stateless: CLI owns intermediate state, nonces, etc.
// ===========================================================================

export function createOAuthFlow(opts: {
  clientId: string;
  redirectUri: string;
  scope: string;
}): OAuthFlow {
  const { clientId, redirectUri, scope } = opts;

  return {
    async startAuth(handle: string) {
      const parState = await pushPar(handle, clientId, redirectUri, scope);
      const authUrl = `${parState.authServer}?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(parState.requestUri)}`;
      // Open system browser — caller-kicks this off via Deno.Command("open", ...)
      // We return the URL + state; the CLI handles the actual browser open.
      return { did: parState.did, authServer: parState.authServer, authUrl, parState };
    },

    async handleCallback(
      code: string, state: string, iss: string,
      expectedState: string,
      codeVerifier: string,
      dpopKeyPair: CryptoKeyPair,
      dpopPublicJwk: Record<string, string>,
      serverNonce: string | null,
    ): Promise<OAuthCallbackResult> {
      if (state !== expectedState) throw new Error("OAuth state mismatch");
      const meta = await getAuthServerMeta(iss);
      const tokenEndpoint: string = meta.token_endpoint as string;
      const tokens = await exchangeCode(
        tokenEndpoint, code, redirectUri, clientId,
        codeVerifier, dpopKeyPair, dpopPublicJwk, serverNonce,
      );
      const did = tokens.sub;
      let pds = iss;
      try {
        const dr = await fetch(`https://plc.directory/${encodeURIComponent(did)}`);
        if (dr.ok) {
          const doc = await dr.json();
          const svc = ((doc.service || []) as Array<{ id?: string; type?: string; serviceEndpoint?: string }>)
            .find((s) => s.id === "#atproto_pds" || s.type === "AtprotoPersonalDataServer");
          if (svc) pds = svc.serviceEndpoint!;
        }
      } catch { /* use iss */ }
      const info = await fetchSessionInfo(pds, tokens.accessToken, dpopKeyPair, dpopPublicJwk, tokens.oauthServerNonce);
      return {
        accessToken: tokens.accessToken, refreshToken: tokens.refreshToken,
        did: info.did, handle: info.handle, pds,
        dpopKeyPair, dpopPublicJwk,
        oauthServerNonce: info.oauthServerNonce,
      };
    },

    async validateSession(session: OAuthSession) {
      return fetchSessionInfo(session.pds, session.accessJwt, session.dpopKeyPair, session.dpopPublicJwk, null);
    },

    async refreshSession(session: OAuthSession) {
      const { session: refreshed } = await refreshSession(session, clientId, null);
      return refreshed;
    },
  };
}

// Also export the raw functions for callers that need them directly.
export { sha256, toHex, base64url, randomHex, pkceChallenge, generateDpopKey, createDpopProof };
export { resolveHandleToDid, resolveDidToPds, getAuthServerMeta, resolveAuthServer };
export { pushPar, exchangeCode, fetchSessionInfo, refreshSession };
