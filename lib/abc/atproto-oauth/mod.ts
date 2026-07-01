// ATProto OAuth ABC — pure interface for OAuth authorization code flow
// with DPoP-bound tokens. Zero I/O, zero side effects.

import type { OAuthSession } from "@publicdomainrelay/atproto-oauth-common";

/** Result returned by handleCallback after successful code exchange. */
export interface OAuthCallbackResult {
  accessToken: string;
  refreshToken: string;
  did: string;
  handle: string;
  pds: string;
  dpopKeyPair: CryptoKeyPair;
  dpopPublicJwk: Record<string, string>;
  oauthServerNonce: string | null;
}

export interface OAuthFlow {
  /** Begin authorization: resolve handle→DID→PDS→auth server, push PAR,
   *  open system browser. Returns the DID being authorized. */
  startAuth(handle: string): Promise<{ did: string; authServer: string }>;

  /** Exchange authorization code for tokens. Called by both the HTTP
   *  callback handler and the URL scheme poller (single implementation). */
  handleCallback(
    code: string,
    state: string,
    iss: string,
    expectedState: string,
    codeVerifier: string,
    dpopKeyPair: CryptoKeyPair,
    dpopPublicJwk: Record<string, string>,
    serverNonce?: string | null,
  ): Promise<OAuthCallbackResult>;

  /** Validate a stored session by calling getSession on the PDS. */
  validateSession(
    session: OAuthSession,
  ): Promise<{ handle: string; did: string }>;

  /** Refresh an expired session using the refresh token. */
  refreshSession(
    session: OAuthSession,
  ): Promise<OAuthSession>;
}
