// @ts-nocheck — Deno desktop runtime APIs not in compile-time types
// macOS tray — Deno Desktop App
//
// Thin CLI entrypoint composing ABC-layered packages:
//   device-key-webcrypto — software device keys (portable, Web Crypto)
//   secret-store-chain — win32 CredMan → gnome-keyring → filesystem
//   atproto-oauth-fetch — ATProto OAuth (PAR + PKCE + DPoP)
//   badge-blue-keys-atproto — key→DID association records

import { Command } from "@publicdomainrelay/cli-args-env";
import { createStructuredLogger, type StructuredLoggerInterface } from "@publicdomainrelay/logger";
import { createServe, type ServeHandle } from "@publicdomainrelay/serve";
import { Hono } from "@hono/hono";
import {
  createDeviceKeyService, createRichKeychainStore,
} from "@publicdomainrelay/device-key-webcrypto";
import { createFilesystemKeychainStore } from "@publicdomainrelay/secret-store-filesystem";
import { createGnomeKeychainStore } from "@publicdomainrelay/secret-store-gnome";
import { createWin32KeychainStore } from "@publicdomainrelay/secret-store-win32";
import { buildStandardChain } from "@publicdomainrelay/secret-store-chain";
import type { DeviceKeyService } from "@publicdomainrelay/device-key-abc";
import { createOAuthFlow, generateDpopKey, type ParState } from "@publicdomainrelay/atproto-oauth-fetch";
import type { OAuthFlow } from "@publicdomainrelay/atproto-oauth-abc";
import type { OAuthSession } from "@publicdomainrelay/atproto-oauth-common";
import {
  OAUTH_CLIENT_ID_DEFAULT, OAUTH_REDIRECT_URI_DEFAULT,
} from "@publicdomainrelay/atproto-oauth-common";
import { createAssociationService } from "@publicdomainrelay/badge-blue-keys-atproto";
import type { AssociationService } from "@publicdomainrelay/badge-blue-keys-abc";
import { BADGE_BLUE_KEYS_NSID, type BadgeBlueKeysSession } from "@publicdomainrelay/badge-blue-keys-common";
import { TRAY_ICON_BASE64 } from "../icon.ts";
import {
  TRAY_STYLE, TRAY_HTML, TRAY_PANEL_WIDTH_HOME, TRAY_PANEL_WIDTH_SETTINGS,
} from "./tray-ui.ts";

import cliArgsEnv from "./cli-args-env.json" with { type: "json" };

// Market bidder — dynamic imports in startBidder() avoid deno desktop
// module graph analyzer walking @atproto/* npm deps.
import { loadOrCreateMarketKeypair, deleteMarketKeypair, type MarketKeypair } from "@publicdomainrelay/market-bidder-keys";
import type { ContractEvent } from "@publicdomainrelay/market-bidder-abc";
import type { RelayRef } from "@publicdomainrelay/serve";
// Static import ensures deno compile bundles this file. Content extracted
// at runtime to cache dir so copySystemctlShim finds it without fetch().
import systemctlShimSource from "../../hono-compute-provider/lib/compute-provider-local/systemctl-shim.ts" with { type: "text" };

// ===========================================================================
// Config resolution
// ===========================================================================

let runtimeConfig: Record<string, unknown> | null = null;
try {
  runtimeConfig = (await import("./config.json", { with: { type: "json" } })).default;
} catch { /* optional */ }

const { options } = await new Command(
  "CONFIG_PATH_HONO_MACOS_RUNNER_DESKTOP",
  cliArgsEnv,
  runtimeConfig,
).resolve();

const serviceName = (options.serviceName as string) ?? "macos-runner-desktop";
const logger = createStructuredLogger(serviceName);

const OAUTH_CLIENT_ID = (options.oauthClientId as string) || OAUTH_CLIENT_ID_DEFAULT;
const OAUTH_REDIRECT_URI = (options.oauthRedirectUri as string) || OAUTH_REDIRECT_URI_DEFAULT;
const BIDDER_SCOPE_COLLECTIONS = [
  "com.publicdomainrelay.temp.auth.allowlist.rbacDid",
  "com.publicdomainrelay.temp.market.offering",
  "com.publicdomainrelay.temp.market.bid",
  "com.publicdomainrelay.temp.market.bids.free",
  "com.publicdomainrelay.temp.market.bids.x402",
  "com.publicdomainrelay.temp.market.receipt",
  "com.publicdomainrelay.temp.market.receipts.free",
  "com.publicdomainrelay.temp.market.receipts.x402",
  "com.publicdomainrelay.temp.market.event",
  "com.publicdomainrelay.temp.compute.config.wif.simple",
  "com.fedproxy.rbac",
];
const OAUTH_SCOPE = `atproto ${
  BIDDER_SCOPE_COLLECTIONS.map((c) => `repo:${c}?action=create repo:${c}?action=update`).join(" ")
} repo:${BADGE_BLUE_KEYS_NSID}?action=create`
  + " rpc:com.publicdomainrelay.temp.market.submitBid?aud=*"
  + " rpc:com.publicdomainrelay.temp.market.submitEvent?aud=*";

const DISPATCHER_HOST = (options.dispatcherHost as string) || "xrpc.fedproxy.com";
const PLC_DIRECTORY_URL = (options.plcDirectoryUrl as string) || "https://plc.directory";
const FIREHOSE_URL = options.firehoseUrl as string | undefined;
const OFFERING_REFRESH_MS = ((options.offeringRefreshSec as number) ?? 300) * 1000;
const SKIP_MARKET = (options.skipMarket as boolean) ?? false;

// ===========================================================================
// Logger — ring buffer for UI log viewer + structured JSON stderr
// ===========================================================================

const LOG_RING: string[] = [];
const LOG_RING_MAX = 500;

function writeLog(level: string, message: string, meta?: Record<string, unknown>) {
  const entry = JSON.stringify({ ts: new Date().toISOString(), level, message, ...meta });
  if (LOG_RING.length >= LOG_RING_MAX) LOG_RING.shift();
  LOG_RING.push(entry);
  logger[level as "info" | "warn" | "error" | "debug"](message, meta);
}

const log = {
  info: (msg: string, meta?: Record<string, unknown>) => writeLog("info", msg, meta),
  warn: (msg: string, meta?: Record<string, unknown>) => writeLog("warn", msg, meta),
  error: (msg: string, meta?: Record<string, unknown>) => writeLog("error", msg, meta),
  debug: (msg: string, meta?: Record<string, unknown>) => writeLog("debug", msg, meta),
};

const CONTRACT_LOG: ContractEvent[] = [];
const CONTRACT_LOG_MAX = 500;

function onContractChange(event: ContractEvent): void {
  if (CONTRACT_LOG.length >= CONTRACT_LOG_MAX) CONTRACT_LOG.shift();
  CONTRACT_LOG.push(event);
}

// ===========================================================================
// Services (from ABC-layered packages)
// ===========================================================================

const storageDir = (options.storageDir as string) || undefined;

const gnomeStore = createGnomeKeychainStore({ logger });
const win32Store = createWin32KeychainStore({ logger });
const fsStore = createFilesystemKeychainStore({ storageDir, logger });

let win32Available = false;
let gnomeAvailable = false;
try {
  win32Available = (win32Store as ReturnType<typeof createWin32KeychainStore>).isAvailable();
} catch { /* not on Windows or advapi32 not loadable */ }
try {
  gnomeAvailable = await (gnomeStore as ReturnType<typeof createGnomeKeychainStore>).isAvailable();
} catch { /* gnome-keyring not running */ }

const secretStore = buildStandardChain({
  win32Store,
  win32Available,
  gnomeStore,
  gnomeAvailable,
  filesystemStore: fsStore,
  logger,
});

const deviceKeys: DeviceKeyService = createDeviceKeyService({ keychain: secretStore, logger });
const keychain = createRichKeychainStore(secretStore, { logger });

const oauth: OAuthFlow & { startAuth: (handle: string) => Promise<{ did: string; authServer: string; authUrl: string; parState: ParState }> } = createOAuthFlow({
  clientId: OAUTH_CLIENT_ID,
  redirectUri: OAUTH_REDIRECT_URI,
  scope: OAUTH_SCOPE,
}) as never;

const assoc: AssociationService = createAssociationService();

// ===========================================================================
// Application state (CLI-owned)
// ===========================================================================

let oauthSession: OAuthSession | null = null;
let persistentKeyId: string | null = null;
let associationRecordUri: string | null = null;
let oauthServerNonce: string | null = null;
let oauthInFlight = false;
let oauthError: string | null = null;
let parState: ParState | null = null;

// Market bidder state
let marketBidder: { beginServe(): Promise<void>; shutdown(): void } | null = null;
let marketKeypair: MarketKeypair | null = null;
let marketSignerHex: string | null = null;
let bidderRelay: RelayRef | null = null;
let bidderServe: ServeHandle | null = null;
let bidderStarted = false;

// ===========================================================================
// Provider state (4 toggles — too thin for a package)
// ===========================================================================

interface ProviderState {
  dispatchingEnabled: boolean;
  workersEnabled: boolean;
  containersEnabled: boolean;
  acceptScope: "only_me" | "direct_network" | null;
  linkedAt: string | null;
}

const DEFAULT_PROVIDER_STATE: ProviderState = {
  dispatchingEnabled: true, workersEnabled: true, containersEnabled: true,
  acceptScope: null, linkedAt: null,
};

function resolveStatePath(): string {
  const home = Deno.env.get("HOME") ?? "";
  return (options.statePath as string) || (home ? `${home}/.compute-provider-state.json` : `${Deno.cwd()}/.compute-provider-state.json`);
}

const STATE_PATH = resolveStatePath();

let providerState: ProviderState = (() => {
  try { return { ...DEFAULT_PROVIDER_STATE, ...JSON.parse(Deno.readTextFileSync(STATE_PATH)) }; }
  catch { return { ...DEFAULT_PROVIDER_STATE }; }
})();

function saveProviderState(): void {
  try { Deno.writeTextFileSync(STATE_PATH, JSON.stringify(providerState)); } catch { /* degrade */ }
}

// ===========================================================================
// Market bidder lifecycle (start/stop on dispatchingEnabled toggle)
// ===========================================================================

async function startBidder(): Promise<void> {
  if (SKIP_MARKET) { log.info("bidder: skipped (skip-market)"); return; }
  if (!oauthSession) { log.warn("bidder: no oauth session"); return; }
  if (bidderStarted) { log.info("bidder: already running"); return; }
  try {
    // Dynamic imports — relative paths avoid deno.json import map entries that
    // would trigger deno desktop module graph analyzer panic on @atproto/* deps
    const [
      { createXrpcRelay },
      { createMarketBidder },
      { createComputeProviderHooks },
      { createOAuthAgent, createDesktopATProto },
      { loadOrGenerateKeypair },
      { createPlcDirectoryClient },
      { createLocalComputeProvider },
      { createOidcProvisioningEnricher },
      { createRbacProvisioner },
    ] = await Promise.all([
      import("../../atproto-market/lib/xrpc-relay/mod.ts"),
      import("../../atproto-market/lib/market-bidder/mod.ts"),
      import("../../atproto-market/lib/market-bidder-compute/mod.ts"),
      import("../../atproto-market/lib/market-bidder-agent/mod.ts"),
      import("../../atproto-market/lib/market-atproto/mod.ts"),
      import("../../atproto-market/lib/did-plc/mod.ts"),
      import("../../hono-compute-provider/lib/compute-provider-local/mod.ts"),
      import("../../hono-compute-provider/lib/oidc-issuer-hono/mod.ts"),
      import("../../hono-compute-provider/lib/rbac-atproto/mod.ts"),
    ]);

    const { keypair, hex } = await loadOrCreateMarketKeypair(keychain);
    marketKeypair = keypair; marketSignerHex = hex;

    const oauthAgent = createOAuthAgent(
      { did: oauthSession.did, pds: oauthSession.pds, accessJwt: oauthSession.accessJwt,
        dpopKeyPair: oauthSession.dpopKeyPair, dpopPublicJwk: oauthSession.dpopPublicJwk },
      keypair,
      { refreshSession: async () => {
          const r = await oauth.refreshSession(oauthSession!);
          oauthSession = r; keychain.saveSession(r).catch(() => {});
          return { did: r.did, pds: r.pds, accessJwt: r.accessJwt,
            dpopKeyPair: r.dpopKeyPair, dpopPublicJwk: r.dpopPublicJwk };
        },
        onSessionRefreshed: (s) => { oauthSession = { ...oauthSession!, accessJwt: s.accessJwt,
          dpopKeyPair: s.dpopKeyPair, dpopPublicJwk: s.dpopPublicJwk }; },
      },
    );

    const badgeBlueSigner = await loadOrGenerateKeypair(hex) as never;
    const plcClient = createPlcDirectoryClient({ plcDirectoryUrl: PLC_DIRECTORY_URL });
    const idResolver = {
      did: { async resolve(did: string) { try {
        if (did.startsWith("did:web:")) { const h = did.slice("did:web:".length);
          const r = await fetch(`https://${h}/.well-known/did.json`);
          return r.ok ? r.json() as Record<string, unknown> : null; }
        const r = await fetch(`${PLC_DIRECTORY_URL}/${encodeURIComponent(did)}`);
        if (!r.ok) return null; return r.json() as Record<string, unknown>;
      } catch { return null; } } },
    };
    const atproto = await createDesktopATProto(logger, oauthAgent, badgeBlueSigner, idResolver as never, plcClient);

    bidderRelay = createXrpcRelay({
      logger, dispatcherHost: DISPATCHER_HOST,
      signer: atproto.signer,
      keypair: { did: keypair.did.bind(keypair), sign: keypair.sign.bind(keypair) },
    });

    // Bidder gets its own serve (separate from main desktop serve) so market
    // routes + OIDC issuer mount before any request builds the Hono matcher.
    // Matches hono-bidder pattern: one serve per relay, routes mounted first.
    bidderServe = createServe({
      logger,
      tcp: { addr: "127.0.0.1", port: 0 },
      relays: [bidderRelay],
    });

    // Ensure container runtime is ready on macOS before provisioning.
    if (Deno.build.os === "darwin" && providerState.containersEnabled) {
      try {
        const p = new Deno.Command("container", { args: ["system", "start"] }).spawn();
        await p.status;
        log.info("bidder: container system start ok");
        // Write bundled shim to cache so copySystemctlShim finds it.
        const home = Deno.env.get("HOME") ?? Deno.cwd();
        const cacheDir = `${home}/.cache/pdr-compute`;
        await Deno.mkdir(cacheDir, { recursive: true });
        await Deno.writeTextFile(`${cacheDir}/systemctl-shim-ubuntu.ts`, systemctlShimSource);
        const { createContainerBackend } = await import("../../hono-compute-provider/lib/container-backend-container/mod.ts");
        const backend = createContainerBackend();
        const imgTag = "container-runner-ubuntu:latest";
        if (!(await backend.imageExists(imgTag))) {
          const { buildContainerImage } = await import("../../hono-compute-provider/lib/compute-provider-local/mod.ts");
          await buildContainerImage(backend, "ubuntu");
        }
        log.info("bidder: container image ready");
      } catch (e) {
        log.warn("bidder: container init failed", { error: String(e) });
      }
    }

    const localComputeProvider = createLocalComputeProvider({
      logger,
      atproto: atproto as never,
      serve: bidderServe,
      getIssuerUrl: () => {
        const ref = bidderRelay?.proxyRef ?? "";
        return ref.startsWith("did:web:") ? "https://" + ref.slice("did:web:".length) : ref;
      },
      containerMode: "container",
      oidcProvisioner: createOidcProvisioningEnricher(() => {
        const ref = bidderRelay?.proxyRef ?? "";
        return ref.startsWith("did:web:") ? "https://" + ref.slice("did:web:".length) : ref;
      }),
      rbacProvisioner: createRbacProvisioner(),
    });

    const providers: Array<{
      serviceId: string; appliesTo: string[];
      setup?(): Promise<void>; teardown?(): Promise<void>;
      buildCallbacks(d: Record<string, unknown>): Record<string, unknown>;
    }> = [createComputeProviderHooks({ provider: localComputeProvider }) as never];

    marketBidder = await createMarketBidder({
      logger: log, serve: bidderServe, atproto, relay: bidderRelay, providers,
      skipServeBegin: true,
      offeringRefreshMs: OFFERING_REFRESH_MS > 0 ? OFFERING_REFRESH_MS : undefined,
      acceptScope: providerState.acceptScope ?? undefined,
      onContractChange,
    });
    // Mount market routes on bidderServe.app BEFORE beginServe so Hono matcher
    // isn't built yet (no requests have arrived on this serve).
    await marketBidder.beginServe();
    // Now start the serve — connects relay, fires onConnected (mounts OIDC).
    await bidderServe.beginServe();

    // Create offering with correct appliesTo + relay endpoint URL now that
    // the relay has connected and proxyRef is set. Old offerings from before
    // providers existed have empty appliesTo — requester skips them.
    try {
      const OFFERING_NSID = "com.publicdomainrelay.temp.market.offering";
      const proxyRef = bidderRelay?.proxyRef ?? "";
      const endpointUrl = proxyRef.startsWith("did:web:")
        ? "https://" + proxyRef.slice("did:web:".length)
        : `${atproto.did}#pdr_temp_market`;
      await atproto.createRecord(OFFERING_NSID, {
        $type: OFFERING_NSID,
        endpointUrl,
        appliesTo: ["com.publicdomainrelay.temp.compute.vm"],
        createdAt: new Date().toISOString(),
        refreshedAt: new Date().toISOString(),
      });
      log.info("bidder: created offering with appliesTo", { endpointUrl });
    } catch (e) {
      log.warn("bidder: offering create failed", { error: String(e) });
    }

    // Create bidderAssociation reverse pointer on the bidder's repo.
    // Bridges did:key → operator DID for vouch graph traversal.
    if (associationRecordUri) {
      try {
        const BIDDER_ASSOCIATION_NSID = "com.publicdomainrelay.temp.market.bidderAssociation";
        await atproto.createRecord(BIDDER_ASSOCIATION_NSID, {
          $type: BIDDER_ASSOCIATION_NSID,
          operatorDid: oauthSession!.did,
          associationProof: {
            $type: "com.atproto.repo.strongRef",
            uri: associationRecordUri,
            cid: "",
          },
          createdAt: new Date().toISOString(),
        });
        log.info("bidder: bidderAssociation created", { operatorDid: oauthSession!.did });
      } catch (e) {
        log.warn("bidder: bidderAssociation create failed", { error: String(e) });
      }
    }

    bidderStarted = true;
    log.info("bidder: started", { did: atproto.did, proxyRef: bidderRelay?.proxyRef });
  } catch (e) {
    log.error("bidder: start failed", { error: String(e) });
    try { bidderRelay?.close(); } catch { /* ignore */ }
    try { bidderServe?.shutdown(); } catch { /* ignore */ }
    bidderRelay = null; bidderServe = null; marketBidder = null;
    marketKeypair = null; marketSignerHex = null;
  }
}

function stopBidder(): void {
  if (!bidderStarted) return;
  try { marketBidder?.shutdown(); bidderRelay?.close(); bidderServe?.shutdown(); } catch (e) { log.warn("bidder: stop error", { error: String(e) }); }
  marketBidder = null; bidderRelay = null; bidderServe = null; bidderStarted = false;
  log.info("bidder: stopped");
}

// ===========================================================================
// Persistent key + session restore
// ===========================================================================

async function initKeysAndSession(): Promise<void> {
  persistentKeyId = keychain.getDeviceKeyId();
  if (persistentKeyId) {
    log.info("persistent device key loaded from keychain", { keyId: persistentKeyId });
  } else {
    try {
      persistentKeyId = await deviceKeys.generateKey();
      keychain.saveDeviceKeyId(persistentKeyId).then((ok) =>
        log.info("persistent device key generated and saved", { keyId: persistentKeyId, ok }),
      ).catch((e) => log.error("failed to save device key to keychain", { error: String(e) }));
    } catch (e) {
      log.error("failed to generate persistent key", { error: String(e) });
    }
  }
  const saved = await keychain.loadSession();
  if (!saved) {
    log.info("no saved session found in keychain, skipping restore");
    return;
  }
  log.info("saved session loaded from keychain, validating", { did: saved.did, handle: saved.handle });
  try {
    await oauth.validateSession(saved);
    oauthSession = saved;
    log.info("session restored and validated", { did: saved.did, handle: saved.handle });
    assoc.findOrCreateRecord(toBadgeSession(saved), persistentKeyId!).then((uri) => {
      associationRecordUri = uri;
      log.info("findOrCreateRecord after restore", { associationRecordUri });
    }).catch((e) => log.warn("findOrCreateRecord after restore failed", { error: String(e) }));
  } catch (e) {
    log.warn("session token expired, attempting refresh", { error: String(e) });
    try {
      const refreshed = await oauth.refreshSession(saved);
      oauthSession = refreshed;
      await keychain.saveSession(refreshed);
      assoc.findOrCreateRecord(toBadgeSession(refreshed), persistentKeyId!).then((uri) => {
        associationRecordUri = uri;
        log.info("findOrCreateRecord after refresh", { associationRecordUri });
      }).catch((e2) => log.warn("findOrCreateRecord after refresh failed", { error: String(e2) }));
    } catch (e2) {
      log.warn("session refresh failed, clearing", { error: String(e2) });
      keychain.delete("oauth-session");
    }
  }
  // Autostart bidder after session restore
  if (oauthSession && OAUTH_SCOPE.includes("rpc:")) {
    try {
      const { createOAuthAgent } = await import("../../atproto-market/lib/market-bidder-agent/mod.ts");
      const { keypair } = await loadOrCreateMarketKeypair(keychain);
      const agent = createOAuthAgent(
        { did: oauthSession.did, pds: oauthSession.pds, accessJwt: oauthSession.accessJwt,
          dpopKeyPair: oauthSession.dpopKeyPair, dpopPublicJwk: oauthSession.dpopPublicJwk },
        keypair,
        { refreshSession: async () => oauthSession! },
      );
      const saAgent = agent as { getServiceAuth?: (aud: string, lxm?: string) => Promise<string> };
      if (saAgent.getServiceAuth) {
        await saAgent.getServiceAuth("did:web:scope-check.localhost", "com.publicdomainrelay.temp.market.submitBid");
        log.info("oauth session has rpc scopes");
      }
    } catch (e) {
      const msg = String(e);
      if (msg.includes("ScopeMissing") || msg.includes("scope")) {
        log.warn("oauth session missing rpc scopes, clearing for re-auth", { error: msg });
        oauthSession = null;
        keychain.delete("oauth-session");
      }
    }
  }
  if (oauthSession && providerState.dispatchingEnabled && !SKIP_MARKET) {
    startBidder().catch((e) => log.error("bidder: restore auto-start failed", { error: String(e) }));
  }
}
initKeysAndSession();

function toBadgeSession(s: OAuthSession): BadgeBlueKeysSession {
  return { did: s.did, pds: s.pds, accessJwt: s.accessJwt, dpopKeyPair: s.dpopKeyPair, dpopPublicJwk: s.dpopPublicJwk };
}

// ===========================================================================
// Per-launch CSRF token + Hono app
// ===========================================================================

const APP_TOKEN = Array.from(crypto.getRandomValues(new Uint8Array(24)), (b) => b.toString(16).padStart(2, "0")).join("");
const app = new Hono();

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status, headers: { "content-type": "application/json; charset=utf-8" },
  });
}

// -- GET routes (unauthenticated) --

app.get("/oauth-client-metadata.json", () =>
  new Response(JSON.stringify({
    client_id: OAUTH_CLIENT_ID,
    application_type: "native",
    dpop_bound_access_tokens: true,
    redirect_uris: [OAUTH_REDIRECT_URI],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    scope: OAUTH_SCOPE,
    token_endpoint_auth_method: "none",
    client_name: "Compute Provider",
  }), { headers: { "content-type": "application/json" } }));

app.get("/api/health", () => json({ ok: true, logEntries: LOG_RING.length }));

app.get("/api/bidder/status", () => json({
  running: bidderStarted,
  skipMarket: SKIP_MARKET,
  proxyRef: bidderRelay?.proxyRef ?? null,
  signerDid: marketKeypair?.did() ?? null,
  hasSession: !!oauthSession,
  dispatchingEnabled: providerState.dispatchingEnabled,
}));
app.get("/api/logs", () => json({ entries: [...LOG_RING] }));

app.get("/api/atproto/session", () =>
  oauthSession
    ? json({ loggedIn: true, did: oauthSession.did, handle: oauthSession.handle })
    : json({ loggedIn: false }));

app.get("/api/state", (c) => {
  const requestedView = c.req.query("requestedView") || null;
  const active = new Map<string, ContractEvent>();
  const past: ContractEvent[] = [];
  for (const e of CONTRACT_LOG) {
    if (e.type === "accepted" || e.type === "provisioned" || e.type === "provisioning-failed") {
      active.set(e.key, e);
    } else if (e.type === "terminated") {
      active.delete(e.key);
      past.push(e);
    }
  }
  return json({
    ...providerState,
    oauthInFlight, oauthError, persistentKeyId, associationRecordUri,
    session: oauthSession ? { handle: oauthSession.handle, did: oauthSession.did } : null,
    requestedView,
    bidder: {
      running: bidderStarted,
      skipMarket: SKIP_MARKET,
      proxyRef: bidderRelay?.proxyRef ?? null,
      signerDid: marketKeypair?.did() ?? null,
    },
    logEntries: [...LOG_RING],
    contracts: { active: [...active.values()], past },
  });
});

app.get("/tray", () =>
  new Response(TRAY_HTML.replace("__APP_TOKEN__", APP_TOKEN),
    { headers: { "content-type": "text/html; charset=utf-8" } }));

// OAuth callback — arrives either as an HTTP GET (loopback redirect_uri) or,
// for custom URL scheme redirect_uri, via the native url-scheme-bridge poll
// loop below. Both paths funnel through this one handler.
async function processOAuthCallback(
  code: string, state: string, iss: string,
): Promise<{ ok: true; handle: string } | { ok: false; error: string }> {
  if (!parState || state !== parState.state) {
    return { ok: false, error: "invalid or stale state" };
  }
  try {
    const result = await oauth.handleCallback(
      code, state, iss, parState.state, parState.codeVerifier,
      parState.dpopKeyPair, parState.dpopPublicJwk, oauthServerNonce,
    );
    oauthSession = {
      accessJwt: result.accessToken, refreshJwt: result.refreshToken,
      did: result.did, handle: result.handle, pds: result.pds,
      dpopKeyPair: result.dpopKeyPair!, dpopPublicJwk: result.dpopPublicJwk!,
    };
    oauthServerNonce = result.oauthServerNonce;
    parState = null; oauthInFlight = false; oauthError = null;
    if (!providerState.acceptScope) providerState.acceptScope = "only_me";
    providerState.linkedAt = new Date().toISOString();
    saveProviderState();
    keychain.saveSession(oauthSession).catch(() => {});
    // Start bidder immediately — don't block on association record.
    if (providerState.dispatchingEnabled && !bidderStarted) {
      startBidder().catch((e) => log.error("bidder: post-login auto-start failed", { error: String(e) }));
    }
    assoc.findOrCreateRecord(toBadgeSession(oauthSession), persistentKeyId!).then((uri) => {
      associationRecordUri = uri;
      log.info("findOrCreateRecord after login", { associationRecordUri });
    }).catch((e) => log.warn("findOrCreateRecord after login failed", { error: String(e) }));
    return { ok: true, handle: result.handle };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    oauthInFlight = false; oauthError = msg;
    log.error("oauth: callback error", { error: msg });
    return { ok: false, error: msg };
  }
}

app.get("/", async (c) => {
  const code = c.req.query("code");
  const state = c.req.query("state");
  const iss = c.req.query("iss");
  if (!code || !state || !iss) return new Response("Invalid callback", { status: 400 });
  const result = await processOAuthCallback(code, state, iss);
  if (result.ok) {
    return new Response(
      `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Authenticated</title><style>body{font-family:-apple-system,sans-serif;background:#1e1e2e;color:#cdd6f4;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center}.ok{color:#a6e3a1;font-size:24px;margin-bottom:12px}</style></head><body><div><div class="ok">Authenticated</div><p>Signed in as <strong>@${result.handle}</strong></p><p>You may close this window and return to the app.</p></div></body></html>`,
      { headers: { "content-type": "text/html; charset=utf-8" } });
  }
  return new Response(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Auth Error</title><style>body{font-family:-apple-system,sans-serif;background:#1e1e2e;color:#f38ba8;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center}</style></head><body><div><h2>Authentication Error</h2><p>${result.error}</p></div></body></html>`, { status: 500, headers: { "content-type": "text/html; charset=utf-8" } });
});

// -- POST routes (CSRF-protected) --

app.post("/api/tray-resize", async (c) => {
  if (c.req.header("X-App-Token") !== APP_TOKEN) return json({ error: "unauthorized" }, 401);
  const body = await c.req.json().catch(() => ({}));
  const width = Number(body.width); const height = Number(body.height);
  if (!Number.isFinite(width) || width <= 0) return json({ error: "invalid width" }, 400);
  if (!Number.isFinite(height) || height <= 0) return json({ error: "invalid height" }, 400);
  resizeTrayPanel(width, height);
  return json({ ok: true });
});

app.post("/api/atproto/start-oauth", async (c) => {
  if (c.req.header("X-App-Token") !== APP_TOKEN) return json({ error: "unauthorized" }, 401);
  try {
    const body = await c.req.json().catch(() => ({}));
    const handle = String(body.handle ?? "").trim();
    if (!handle) return json({ error: "handle required" }, 400);
    oauthInFlight = true; oauthError = null;
    const result = await oauth.startAuth(handle);
    parState = result.parState;
    new Deno.Command("open", { args: [result.authUrl] }).spawn().status.catch(() => {});
    return json({ ok: true, did: result.did });
  } catch (e) {
    oauthInFlight = false; oauthError = e instanceof Error ? e.message : String(e);
    log.error("oauth: start-oauth failed", { error: oauthError });
    return json({ error: oauthError }, 500);
  }
});

app.post("/api/atproto/cancel-oauth", (c) => {
  if (c.req.header("X-App-Token") !== APP_TOKEN) return json({ error: "unauthorized" }, 401);
  parState = null; oauthInFlight = false;
  return json({ ok: true });
});

app.post("/api/atproto/unlink", (c) => {
  if (c.req.header("X-App-Token") !== APP_TOKEN) return json({ error: "unauthorized" }, 401);
  stopBidder();
  oauthSession = null; keychain.delete("oauth-session");
  providerState.acceptScope = null; providerState.linkedAt = null;
  providerState.dispatchingEnabled = false;
  associationRecordUri = null; saveProviderState();
  return json({ ok: true });
});

app.post("/api/atproto/regenerate-key", async (c) => {
  if (c.req.header("X-App-Token") !== APP_TOKEN) return json({ error: "unauthorized" }, 401);
  try {
    persistentKeyId = await deviceKeys.generateKey();
    await keychain.saveDeviceKeyId(persistentKeyId!);
    oauthSession = null; keychain.delete("oauth-session");
    providerState.acceptScope = null; providerState.linkedAt = null;
    associationRecordUri = null; saveProviderState();
    return json({ ok: true, keyId: persistentKeyId });
  } catch (e) {
    return json({ error: e instanceof Error ? e.message : String(e) }, 500);
  }
});

app.post("/api/open-external", async (c) => {
  if (c.req.header("X-App-Token") !== APP_TOKEN) return json({ error: "unauthorized" }, 401);
  const body = await c.req.json().catch(() => ({}));
  const target = String(body.url ?? "").trim();
  if (!target || !target.startsWith("https://")) return json({ error: "invalid url" }, 400);
  new Deno.Command("open", { args: [target] }).spawn().status.catch(() => {});
  return json({ ok: true });
});

app.post("/api/state", async (c) => {
  if (c.req.header("X-App-Token") !== APP_TOKEN) return json({ error: "unauthorized" }, 401);
  const body = await c.req.json().catch(() => ({}));
  const allowed: (keyof ProviderState)[] = ["dispatchingEnabled", "workersEnabled", "containersEnabled", "acceptScope"];
  const oldDispatch = providerState.dispatchingEnabled;
  const oldWorkers = providerState.workersEnabled;
  const oldContainers = providerState.containersEnabled;
  const oldAcceptScope = providerState.acceptScope;
  for (const k of allowed) if (k in body) (providerState as Record<string, unknown>)[k] = body[k];

  if (providerState.dispatchingEnabled && !oauthSession) {
    providerState.dispatchingEnabled = false;
    saveProviderState();
    return json({ ok: false, error: "Link your ATProto identity first" }, 400);
  }
  saveProviderState();

  const needsRestart = bidderStarted && (
    oldWorkers !== providerState.workersEnabled ||
    oldContainers !== providerState.containersEnabled ||
    oldAcceptScope !== providerState.acceptScope
  );
  if (needsRestart) stopBidder();
  if (providerState.dispatchingEnabled && !bidderStarted) {
    startBidder().catch((e) => log.error("bidder: auto-start failed", { error: String(e) }));
  } else if (!providerState.dispatchingEnabled && bidderStarted) {
    stopBidder();
  }
  return json({ ok: true });
});

app.post("/api/atproto/create-key-record", async (c) => {
  if (c.req.header("X-App-Token") !== APP_TOKEN) return json({ error: "unauthorized" }, 401);
  if (!oauthSession) return json({ error: "not authenticated" }, 401);
  try {
    const body = await c.req.json().catch(() => ({}));
    const service = String(body.service ?? "*").trim();
    const uri = await assoc.createRecord(toBadgeSession(oauthSession), persistentKeyId!, service);
    associationRecordUri = uri;
    return json({ ok: true, uri, keyId: persistentKeyId, service });
  } catch (e) {
    return json({ error: e instanceof Error ? e.message : String(e) }, 500);
  }
});

// ===========================================================================
// Window + tray management (Deno desktop APIs — CLI layer only)
// ===========================================================================

let sentinelWindow: Deno.BrowserWindow | null = null;
let trayHandle: Deno.Tray | null = null;
let trayPanelHandle: Deno.TrayPanel | null = null;
let trayPopoverWindow: Deno.BrowserWindow | null = null;
let requestedTrayView: string | null = null;

function resizeTrayPanel(contentWidth: number, contentHeight: number): void {
  const width = Math.max(1, Math.round(contentWidth));
  const height = Math.max(1, Math.round(contentHeight));
  try {
    const win = trayPanelHandle?.window ?? trayPopoverWindow;
    if (!win) return;
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

function showTrayPanel(view?: string): void {
  if (view) requestedTrayView = view;
  if (trayPanelHandle) trayPanelHandle.show();
  else if (trayPopoverWindow) {
    try {
      const bounds = trayHandle?.getBounds();
      if (bounds) trayPopoverWindow.setPosition(bounds.x, bounds.y + bounds.height);
    } catch { /* ignore */ }
    trayPopoverWindow.show();
    trayPopoverWindow.focus();
  }
}

function setupWindowsAndTray(port: number): void {
  const startupWindow = new Deno.BrowserWindow({ title: "Compute Provider" });
  sentinelWindow = new Deno.BrowserWindow({
    title: "", width: 1, height: 1, x: -10000, y: -10000, resizable: false,
  });

  const tray = new Deno.Tray();
  trayHandle = tray;
  tray.setTooltip("Compute Provider");
  try {
    const binaryStr = atob(TRAY_ICON_BASE64);
    const iconBytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) iconBytes[i] = binaryStr.charCodeAt(i);
    tray.setIcon(iconBytes);
  } catch { /* degrade */ }
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
      width: TRAY_PANEL_WIDTH_HOME, height: 1,
    });
    trayPanelHandle = panel;
  } catch { /* fallback to popover */ }

  if (!panel) {
    const popover = new Deno.BrowserWindow({
      title: "", width: TRAY_PANEL_WIDTH_HOME, height: 1, frameless: true, noActivate: true,
    });
    trayPopoverWindow = popover;
    popover.navigate(`http://127.0.0.1:${port}/tray`);
    popover.hide();
    tray.addEventListener("click", () => {
      try {
        const bounds = tray.getBounds();
        if (bounds) popover.setPosition(bounds.x, bounds.y + bounds.height);
      } catch { /* ignore */ }
      popover.show(); popover.focus();
    });
    popover.addEventListener("blur", () => popover.hide());
  }

  // Dock menu (macOS-only)
  try {
    Deno.dock.setMenu([
      { item: { label: "Open Settings…", id: "settings", enabled: true } },
    ]);
    Deno.dock.addEventListener("menuclick", (e) => {
      if (e.detail.id === "settings") showTrayPanel("identity");
    });
  } catch { /* no-op elsewhere */ }

  startupWindow.hide();
  try { Deno.dock.setVisible(false); } catch { /* degrade */ }
}

// ===========================================================================
// Serve
// ===========================================================================

const serve = createServe({
  logger,
  tcp: { addr: "127.0.0.1", port: 0 },
});
serve.app.route("/", app as never);
await serve.beginServe();
const SERVE_PORT = serve.tcpPort;
log.info("HTTP server started", { port: SERVE_PORT });
setupWindowsAndTray(SERVE_PORT);

// ===========================================================================
// Custom URL scheme callback bridge (deno desktop has no NSAppleEventManager
// hook). OAUTH_REDIRECT_URI_DEFAULT is a custom scheme, not loopback — the
// system browser hands the callback to this app via `open`, which macOS
// only routes if CFBundleURLTypes is registered (see rebuild.sh) and this
// native bridge is polled for the pending kAEGetURL event.
// ===========================================================================

function resolveUrlBridgePath(): string {
  const name = "url-scheme-bridge.dylib";
  const devCandidate = `${import.meta.dirname}/${name}`;
  try {
    Deno.statSync(devCandidate);
    return devCandidate;
  } catch { /* not in dev tree, compiled bundle: dylib sits next to laufey_webview */ }
  const execDir = Deno.execPath().replace(/\/[^/]+$/, "");
  return `${execDir}/${name}`;
}

try {
  const urlBridge = Deno.dlopen(resolveUrlBridgePath(), {
    url_register_handler: { parameters: [], result: "void" },
    url_scheme_pending: { parameters: [], result: "pointer" },
    url_bridge_free_string: { parameters: ["pointer"], result: "void" },
  });
  urlBridge.symbols.url_register_handler();
  const poll = setInterval(() => {
    const ptr = urlBridge.symbols.url_scheme_pending();
    if (!ptr) return;
    const urlStr = new Deno.UnsafePointerView(ptr as NonNullable<typeof ptr>).getCString();
    urlBridge.symbols.url_bridge_free_string(ptr);
    log.info("url scheme callback received", { url: urlStr });
    const u = new URL(urlStr);
    const code = u.searchParams.get("code");
    const state = u.searchParams.get("state");
    const iss = u.searchParams.get("iss");
    if (!code || !state || !iss) return;
    processOAuthCallback(code, state, iss).then((result) => {
      if (!result.ok) log.error("oauth: url scheme callback failed", { error: result.error });
    });
  }, 500);
  Deno.unrefTimer?.(poll);
  log.info("url scheme bridge loaded");
} catch (e) {
  log.warn("url scheme bridge unavailable, custom-scheme OAuth callback will not work", {
    error: e instanceof Error ? e.message : String(e),
  });
}

log.info("App ready");

// Signal handlers — ONLY in CLI
function shutdown(): void {
  stopBidder();
  serve.shutdown();
  Deno.exit();
}
Deno.addSignalListener("SIGINT", shutdown);
Deno.addSignalListener("SIGTERM", shutdown);
