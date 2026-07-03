// Portable Compute Provider — Linux container / headless server
//
// Thin CLI entrypoint composing ABC-layered packages:
//   app-attest-none          — software keys (portable)
//   secret-store-chain       — darwin → gnome-keyring → filesystem fallback
//   atproto-oauth-fetch      — ATProto OAuth (PAR + PKCE + DPoP)
//   badge-blue-keys-atproto  — attestation→DID association records

import { Command } from "@publicdomainrelay/cli-args-env";
import { createStructuredLogger, type StructuredLoggerInterface } from "@publicdomainrelay/logger";
import { createServe, type ServeHandle } from "@publicdomainrelay/serve";
import { Hono } from "@hono/hono";
import {
  createAppAttestService, createRichKeychainStore,
} from "@publicdomainrelay/app-attest-none";
import { createFilesystemKeychainStore, defaultHomeDir } from "@publicdomainrelay/secret-store-filesystem";
import { createGnomeKeychainStore } from "@publicdomainrelay/secret-store-gnome";
import { createWin32KeychainStore } from "@publicdomainrelay/secret-store-win32";
import { buildStandardChain } from "@publicdomainrelay/secret-store-chain";
import type { AppAttestService } from "@publicdomainrelay/app-attest-abc";
import { createOAuthFlow, type ParState } from "@publicdomainrelay/atproto-oauth-fetch";
import type { OAuthFlow } from "@publicdomainrelay/atproto-oauth-abc";
import type { OAuthSession } from "@publicdomainrelay/atproto-oauth-common";
import {
  OAUTH_CLIENT_ID_DEFAULT, OAUTH_REDIRECT_URI_DEFAULT,
} from "@publicdomainrelay/atproto-oauth-common";
import { createAssociationService } from "@publicdomainrelay/badge-blue-keys-atproto";
import type { AssociationService } from "@publicdomainrelay/badge-blue-keys-abc";
import { BADGE_BLUE_KEYS_NSID, type BadgeBlueKeysSession } from "@publicdomainrelay/badge-blue-keys-common";
import {
  TRAY_STYLE, TRAY_HTML,
} from "./tray-ui.ts";

import cliArgsEnv from "./cli-args-env.json" with { type: "json" };

// Market bidder — dynamic imports in startBidder()
import { loadOrCreateMarketKeypair, type MarketKeypair } from "@publicdomainrelay/market-bidder-keys";
import type { MarketBidderProviderRef } from "@publicdomainrelay/market-bidder-abc";
import type { RelayRef } from "@publicdomainrelay/serve";
import systemctlShimSource from "../../hono-compute-provider/lib/compute-provider-local/systemctl-shim.ts" with { type: "text" };

// ===========================================================================
// Config resolution
// ===========================================================================

let runtimeConfig: Record<string, unknown> | null = null;
try {
  runtimeConfig = (await import("./config.json", { with: { type: "json" } })).default;
} catch { /* optional */ }

const { options } = await new Command(
  "CONFIG_PATH_HONO_DESKTOP",
  cliArgsEnv,
  runtimeConfig,
).resolve();

const serviceName = (options.serviceName as string) ?? "hono-desktop";
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
const OFFERING_REFRESH_MS = ((options.offeringRefreshSec as number) ?? 300) * 1000;
const SKIP_MARKET = (options.skipMarket as boolean) ?? false;
const HEADLESS_BIDDER = (options.startBidder as boolean) ?? false;
const PRIVATE_KEY_HEX = options.privateKeyHex as string | undefined;
const HOSTNAME = (options.hostname as string) || "0.0.0.0";
const PORT = (options.port as number) || 0;

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

// ===========================================================================
// Services — portable attest + platform-native secret store chain
// ===========================================================================

const storageDir = (options.storageDir as string) || undefined;

// Build secret store chain: win32 CredMan → gnome-keyring → filesystem
const gnomeStore = createGnomeKeychainStore({ logger });
const win32Store = createWin32KeychainStore({ logger });
const fsStore = createFilesystemKeychainStore({ storageDir, logger });

// Probe platform stores for availability
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

const attest: AppAttestService = createAppAttestService({ keychain: secretStore, logger });
const keychain = createRichKeychainStore(secretStore, { logger });

const oauth: OAuthFlow = createOAuthFlow({
  clientId: OAUTH_CLIENT_ID,
  redirectUri: OAUTH_REDIRECT_URI,
  scope: OAUTH_SCOPE,
}) as never;

const assoc: AssociationService = createAssociationService();

// ===========================================================================
// Application state
// ===========================================================================

let oauthSession: OAuthSession | null = null;
let persistentKeyId: string | null = null;
let associationRecordUri: string | null = null;
let oauthServerNonce: string | null = null;
let oauthInFlight = false;
let oauthError: string | null = null;
let parState: ParState | null = null;

let marketBidder: { beginServe(): Promise<void>; shutdown(): void } | null = null;
let marketKeypair: MarketKeypair | null = null;
let bidderRelay: RelayRef | null = null;
let bidderServe: ServeHandle | null = null;
let bidderStarted = false;

// ===========================================================================
// Provider state (4 toggles)
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
  return (options.statePath as string) || `${defaultHomeDir()}/.compute-provider-state.json`;
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
// Open URL — platform-aware, falls back to logging
// ===========================================================================

function openUrl(url: string): void {
  const cmd = Deno.build.os === "darwin" ? "open" : "xdg-open";
  new Deno.Command(cmd, { args: [url] }).spawn().status.then((s) => {
    if (!s.success) log.info("browser open failed, navigate manually", { url });
  }).catch(() => {
    log.info("navigate to this URL to continue", { url });
  });
}

// ===========================================================================
// Headless bidder — start without OAuth, using local PDS + direct keypair
// ===========================================================================

async function startBidderHeadless(): Promise<void> {
  // Local-dev fetch patching: *.localhost DNS doesn't resolve + plc.directory
  // → local PLC. Same pattern as hono-bidder and request-vm-ssh.
  const isLocalDev = DISPATCHER_HOST.includes("localhost") || DISPATCHER_HOST.startsWith("127.");
  const _plcHost = (() => { try { return new URL(PLC_DIRECTORY_URL).hostname; } catch { return PLC_DIRECTORY_URL; } })();
  const isLocalPlc = _plcHost === "localhost" || _plcHost.startsWith("127.") || _plcHost === "0.0.0.0";
  if (isLocalDev || isLocalPlc) {
    const patchPort = DISPATCHER_HOST.includes(":") ? DISPATCHER_HOST.split(":").pop()! : "80";
    const realFetch = globalThis.fetch;
    globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
      let url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const m = url.match(/^https:\/\/([^/]+)(\/.*)?$/);
      if (m && m[1].endsWith(".localhost")) {
        let host = m[1];
        if (!host.includes(":")) host = `${host}:${patchPort}`;
        url = `http://${host}${m[2] ?? ""}`;
        return realFetch(url, init);
      }
      if (isLocalPlc && url.startsWith("https://plc.directory/")) {
        url = PLC_DIRECTORY_URL + url.slice("https://plc.directory".length);
        return realFetch(url, init);
      }
      return realFetch(input as string | URL | Request, init);
    }) as typeof fetch;
  }

  const [
    { Secp256k1Keypair },
    { createBadgeBlueSigner },
    { createPlcDirectoryClient },
    { createATProto, createLocalPDSAgent },
    { createXrpcRelay },
    { createMarketBidder },
    { createComputeProviderHooks },
    { createLocalComputeProvider },
    { createOidcProvisioningEnricher },
    { createRbacProvisioner },
  ] = await Promise.all([
    import("@atproto/crypto"),
    import("@publicdomainrelay/market-atproto"),
    import("../../atproto-market/lib/did-plc/mod.ts"),
    import("@publicdomainrelay/atproto-helpers"),
    import("../../atproto-market/lib/xrpc-relay/mod.ts"),
    import("../../atproto-market/lib/market-bidder/mod.ts"),
    import("../../atproto-market/lib/market-bidder-compute/mod.ts"),
    import("../../hono-compute-provider/lib/compute-provider-local/mod.ts"),
    import("../../hono-compute-provider/lib/oidc-issuer-hono/mod.ts"),
    import("../../hono-compute-provider/lib/rbac-atproto/mod.ts"),
  ]);

  const keypair = await Secp256k1Keypair.create({ exportable: true });
  const did = keypair.did();

  const pdsAgent = await createLocalPDSAgent({
    logger: createStructuredLogger("headless-pds"),
    keypair,
    serve: createServe({ logger }),
    plcDirectoryUrl: PLC_DIRECTORY_URL,
    dispatcherHost: DISPATCHER_HOST,
  });
  await pdsAgent.beginServe();

  const _privHexBytes = await keypair.export();
  const privHex = Array.from(_privHexBytes).map((b: number) => b.toString(16).padStart(2, "0")).join("");
  const badgeBlueSigner = await createBadgeBlueSigner({ privateKeyHex: privHex });
  const plcClient = createPlcDirectoryClient({ plcDirectoryUrl: PLC_DIRECTORY_URL });

  const atproto = await createATProto({
    logger,
    badgeBlueSigner,
    plcDirectory: plcClient,
    agent: pdsAgent,
  });

  bidderRelay = createXrpcRelay({
    logger, dispatcherHost: DISPATCHER_HOST,
    signer: atproto.signer,
    keypair: { did: () => did, sign: keypair.sign.bind(keypair) },
  });

  bidderServe = createServe({
    logger,
    tcp: { addr: "127.0.0.1", port: PORT },
    relays: [bidderRelay],
  });

  // Container image pre-build
  if (providerState.containersEnabled) {
    try {
      const cacheDir = `${defaultHomeDir()}/.cache/pdr-compute`;
      await Deno.mkdir(cacheDir, { recursive: true });
      await Deno.writeTextFile(`${cacheDir}/systemctl-shim-ubuntu.ts`, systemctlShimSource);
      const { createContainerBackend } = await import("../../hono-compute-provider/lib/container-backend-container/mod.ts");
      const backend = createContainerBackend();
      const imgTag = "container-runner-ubuntu:latest";
      if (!(await backend.imageExists(imgTag))) {
        const { buildContainerImage } = await import("../../hono-compute-provider/lib/compute-provider-local/mod.ts");
        await buildContainerImage(backend, "ubuntu");
        log.info("headless: container image built");
      }
    } catch (e) {
      log.warn("headless: container init skipped", { error: String(e) });
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

  const providers: MarketBidderProviderRef[] = [
    createComputeProviderHooks({ provider: localComputeProvider }),
  ];

  marketBidder = await createMarketBidder({
    logger, serve: bidderServe, atproto, relay: bidderRelay, providers,
    skipServeBegin: true,
    offeringRefreshMs: OFFERING_REFRESH_MS > 0 ? OFFERING_REFRESH_MS : undefined,
    acceptScope: providerState.acceptScope ?? undefined,
  });
  await marketBidder.beginServe();
  await bidderServe.beginServe();

  // Offering record
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
    log.info("headless: offering created", { endpointUrl });
  } catch (e) {
    log.warn("headless: offering create failed", { error: String(e) });
  }

  bidderStarted = true;

  // Machine-readable line for test harnesses to parse
  console.log(JSON.stringify({
    event: "bidder_ready",
    did,
    proxyRef: bidderRelay?.proxyRef,
    servePort: bidderServe.tcpPort,
  }));
}

// ===========================================================================
// Market bidder lifecycle
// ===========================================================================

async function startBidder(): Promise<void> {
  if (SKIP_MARKET) { log.info("bidder: skipped (skip-market)"); return; }
  if (!oauthSession) { log.warn("bidder: no oauth session"); return; }
  if (bidderStarted) { log.info("bidder: already running"); return; }
  try {
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
    marketKeypair = keypair;

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
          return r.ok ? await r.json() as Record<string, unknown> : null; }
        const r = await fetch(`${PLC_DIRECTORY_URL}/${encodeURIComponent(did)}`);
        if (!r.ok) return null; return await r.json() as Record<string, unknown>;
      } catch { return null; } } },
    };
    const atproto = await createDesktopATProto(logger, oauthAgent, badgeBlueSigner, idResolver as never, plcClient);

    bidderRelay = createXrpcRelay({
      logger, dispatcherHost: DISPATCHER_HOST,
      signer: atproto.signer,
      keypair: { did: keypair.did.bind(keypair), sign: keypair.sign.bind(keypair) },
    });

    bidderServe = createServe({
      logger,
      tcp: { addr: "127.0.0.1", port: 0 },
      relays: [bidderRelay],
    });

    // Container runtime init — only if containers enabled and container CLI available
    if (providerState.containersEnabled) {
      try {
        const p = new Deno.Command("container", { args: ["system", "start"] }).spawn();
        const status = await p.status;
        if (status.success) {
          log.info("bidder: container system start ok");
          const cacheDir = `${defaultHomeDir()}/.cache/pdr-compute`;
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
        }
      } catch (e) {
        log.warn("bidder: container init skipped (container CLI not available)", { error: String(e) });
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

    const providers: MarketBidderProviderRef[] = [
      createComputeProviderHooks({ provider: localComputeProvider }),
    ];

    marketBidder = await createMarketBidder({
      logger, serve: bidderServe, atproto, relay: bidderRelay, providers,
      skipServeBegin: true,
      offeringRefreshMs: OFFERING_REFRESH_MS > 0 ? OFFERING_REFRESH_MS : undefined,
      acceptScope: providerState.acceptScope ?? undefined,
    });
    await marketBidder.beginServe();
    await bidderServe.beginServe();

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

    // Create bidderAssociation reverse pointer for vouch graph traversal.
    if (associationRecordUri && oauthSession) {
      try {
        const BIDDER_ASSOCIATION_NSID = "com.publicdomainrelay.temp.market.bidderAssociation";
        await atproto.createRecord(BIDDER_ASSOCIATION_NSID, {
          $type: BIDDER_ASSOCIATION_NSID,
          operatorDid: oauthSession.did,
          associationProof: {
            $type: "com.atproto.repo.strongRef",
            uri: associationRecordUri,
            cid: "",
          },
          createdAt: new Date().toISOString(),
        });
        log.info("bidder: bidderAssociation created", { operatorDid: oauthSession.did });
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
    marketKeypair = null;
  }
}

function stopBidder(): void {
  if (!bidderStarted) return;
  try { marketBidder?.shutdown(); bidderRelay?.close(); bidderServe?.shutdown(); } catch (e) { log.warn("bidder: stop error", { error: String(e) }); }
  marketBidder = null; bidderRelay = null; bidderServe = null; bidderStarted = false;
  log.info("bidder: stopped");
}

// ===========================================================================
// Persistent key + session restore (async init)
// ===========================================================================

function toBadgeSession(s: OAuthSession): BadgeBlueKeysSession {
  return { did: s.did, pds: s.pds, accessJwt: s.accessJwt, dpopKeyPair: s.dpopKeyPair, dpopPublicJwk: s.dpopPublicJwk };
}

async function initKeysAndSession(): Promise<void> {
  persistentKeyId = keychain.getDeviceKeyId();
  if (persistentKeyId) {
    log.info("persistent device key loaded", { keyId: persistentKeyId });
  } else {
    try {
      persistentKeyId = await attest.generateKey();
      keychain.saveDeviceKeyId(persistentKeyId).then((ok) =>
        log.info("device key generated and saved", { keyId: persistentKeyId, ok }),
      ).catch((e) => log.error("failed to save device key", { error: String(e) }));
    } catch (e) {
      log.error("failed to generate persistent key", { error: String(e) });
    }
  }

  const saved = await keychain.loadSession();
  if (!saved) {
    log.info("no saved session, skipping restore");
    return;
  }
  log.info("saved session loaded, validating", { did: saved.did, handle: saved.handle });
  try {
    await oauth.validateSession(saved);
    oauthSession = saved;
    log.info("session restored and validated", { did: saved.did, handle: saved.handle });
    assoc.findOrCreateRecord(toBadgeSession(saved), persistentKeyId!).then((uri) => {
      associationRecordUri = uri;
    }).catch((e) => log.warn("findOrCreateRecord after restore failed", { error: String(e) }));
  } catch (e) {
    log.warn("session expired, attempting refresh", { error: String(e) });
    try {
      const refreshed = await oauth.refreshSession(saved);
      oauthSession = refreshed;
      await keychain.saveSession(refreshed);
      assoc.findOrCreateRecord(toBadgeSession(refreshed), persistentKeyId!).then((uri) => {
        associationRecordUri = uri;
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

// -- GET routes --

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

app.get("/api/state", (_c) => {
  return json({
    ...providerState,
    oauthInFlight, oauthError, persistentKeyId, associationRecordUri,
    session: oauthSession ? { handle: oauthSession.handle, did: oauthSession.did } : null,
    bidder: {
      running: bidderStarted,
      skipMarket: SKIP_MARKET,
      proxyRef: bidderRelay?.proxyRef ?? null,
      signerDid: marketKeypair?.did() ?? null,
    },
  });
});

app.get("/tray", () =>
  new Response(TRAY_HTML.replace("__APP_TOKEN__", APP_TOKEN),
    { headers: { "content-type": "text/html; charset=utf-8" } }));

// Root: landing page or OAuth callback
app.get("/", (c) => {
  const code = c.req.query("code");
  const state = c.req.query("state");
  const iss = c.req.query("iss");

  // OAuth callback
  if (code && state && iss && parState && state === parState.state) {
    return handleOAuthCallback(code, state, iss);
  }

  // Landing page: redirect to tray UI
  return Response.redirect("/tray", 302);
});

async function handleOAuthCallback(code: string, state: string, iss: string): Promise<Response> {
  try {
    const result = await oauth.handleCallback(
      code, state, iss, parState!.state, parState!.codeVerifier,
      parState!.dpopKeyPair, parState!.dpopPublicJwk, oauthServerNonce,
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
    if (providerState.dispatchingEnabled && !bidderStarted) {
      startBidder().catch((e) => log.error("bidder: post-login auto-start failed", { error: String(e) }));
    }
    assoc.findOrCreateRecord(toBadgeSession(oauthSession), persistentKeyId!).then((uri) => {
      associationRecordUri = uri;
    }).catch((e) => log.warn("findOrCreateRecord after login failed", { error: String(e) }));
    return new Response(
      `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Authenticated</title><style>body{font-family:system-ui,sans-serif;background:#1e1e2e;color:#cdd6f4;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center}.ok{color:#a6e3a1;font-size:24px;margin-bottom:12px}</style></head><body><div><div class="ok">Authenticated</div><p>Signed in as <strong>@${result.handle}</strong></p><p>You may close this window and return to the app.</p></div></body></html>`,
      { headers: { "content-type": "text/html; charset=utf-8" } });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    oauthInFlight = false; oauthError = msg;
    log.error("oauth: callback error", { error: msg });
    return new Response(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Auth Error</title><style>body{font-family:system-ui,sans-serif;background:#1e1e2e;color:#f38ba8;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center}</style></head><body><div><h2>Authentication Error</h2><p>${msg}</p></div></body></html>`, { status: 500, headers: { "content-type": "text/html; charset=utf-8" } });
  }
}

// -- POST routes (CSRF-protected) --

app.post("/api/atproto/start-oauth", async (c) => {
  if (c.req.header("X-App-Token") !== APP_TOKEN) return json({ error: "unauthorized" }, 401);
  try {
    const body = await c.req.json().catch(() => ({}));
    const handle = String(body.handle ?? "").trim();
    if (!handle) return json({ error: "handle required" }, 400);
    oauthInFlight = true; oauthError = null;
    const result = await oauth.startAuth(handle);
    parState = result.parState as ParState;
    openUrl(result.authUrl);
    return json({ ok: true, did: result.did });
  } catch (e) {
    oauthInFlight = false; oauthError = e instanceof Error ? e.message : String(e);
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
    persistentKeyId = await attest.generateKey();
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
  openUrl(target);
  return json({ ok: true });
});

app.post("/api/state", async (c) => {
  if (c.req.header("X-App-Token") !== APP_TOKEN) return json({ error: "unauthorized" }, 401);
  const body = await c.req.json().catch(() => ({}));
  const allowed: (keyof ProviderState)[] = ["dispatchingEnabled", "workersEnabled", "containersEnabled", "acceptScope"];
  const oldWorkers = providerState.workersEnabled;
  const oldContainers = providerState.containersEnabled;
  const oldAcceptScope = providerState.acceptScope;
  for (const k of allowed) {
    if (k in body) providerState[k] = body[k] as never;
  }

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
// Headless bidder entrypoint — no tray, no OAuth, no web UI
// ===========================================================================

if (HEADLESS_BIDDER) {
  function headlessShutdown() {
    stopBidder();
    Deno.exit();
  }
  Deno.addSignalListener("SIGINT", headlessShutdown);
  Deno.addSignalListener("SIGTERM", headlessShutdown);
  await startBidderHeadless();
  // idle until killed
  await new Promise<void>(() => {});
}

// ===========================================================================
// Serve
// ===========================================================================

const serve = createServe({
  logger,
  tcp: { addr: HOSTNAME, port: PORT },
});
serve.app.route("/", app as never);
await serve.beginServe();
const SERVE_PORT = serve.tcpPort;
log.info("HTTP server started", { port: SERVE_PORT, hostname: HOSTNAME });

// Initialize keys and restore session
await initKeysAndSession();

log.info("App ready", { attestSupported: attest.isSupported(), port: SERVE_PORT });
log.info(`Open http://localhost:${SERVE_PORT}/tray to manage`);

// ===========================================================================
// Signal handlers
// ===========================================================================

function shutdown(): void {
  stopBidder();
  serve.shutdown();
  Deno.exit();
}
Deno.addSignalListener("SIGINT", shutdown);
Deno.addSignalListener("SIGTERM", shutdown);
