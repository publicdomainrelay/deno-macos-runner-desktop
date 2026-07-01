// ATProto OAuth common types and default constants.
// Portable — no I/O, no fetch, no crypto.

export interface OAuthSession {
  accessJwt: string;
  refreshJwt: string;
  did: string;
  handle: string;
  pds: string;
  dpopKeyPair: CryptoKeyPair;
  dpopPublicJwk: Record<string, string>;
}

// Default OAuth client metadata — overridden via cli-args-env.json options.
export const OAUTH_CLIENT_ID_DEFAULT =
  "https://attest--johnandersen777-bsky-social.fedproxy.com/oauth-client-metadata.json";
export const OAUTH_REDIRECT_URI_DEFAULT =
  "com.fedproxy.attest--johnandersen777-bsky-social:/callback";
