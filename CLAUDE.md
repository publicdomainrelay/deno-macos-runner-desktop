# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Custom Deno binary — required

Stock `deno` does **not** work for `deno desktop`. Use the patched build.

**When npm dependencies are imported** (any `@noble/*`, `@atproto/*`, etc.), the **release** build is required — the debug build panics at `libs/node_resolver/analyze.rs:488` with `debug_assert!(false)` on CJS-like npm packages. Without npm deps, the debug build is fine.

```sh
~/src/deno-fix/target/release/deno
```

Fork: https://github.com/johnandersen777/deno
Branch: `fix/desktop-macos-entitlements-provisioning`
Patch location: `cli/tools/desktop.rs`

What the patch fixes: `deno desktop` normally sets the shell-script launcher as `CFBundleExecutable`. The patch renames the compiled dylib to `libruntime.dylib` (laufey auto-discovers it) and removes the shell script.

To rebuild the patched deno:
```sh
cd ~/src/deno-fix && source ~/.cargo/env && cargo build -p deno --release
```

### npm packages + `deno compile`

`deno desktop` panics when compiling npm packages with native addons or
complex module graphs (`cbor-x`, `bs58`, `@peculiar/x509` at top level).
**Do not add npm dependencies to deno.json** unless tested with
`deno desktop --no-check` first. JSR packages are fine. This is why the
market bidder uses dynamic imports inside `startBidder()` — the module
graph analyzer never walks `@atproto/*` npm deps at compile time.

## Build & run

```sh
./rebuild.sh    # or: deno task build
```

- **macOS**: kills prior instances, `deno desktop --no-check --allow-all
  hono-macos-runner-desktop/mod.ts` → `hono-macos-runner-desktop.app`,
  launches it. Logs: `/tmp/deno-macos-runner-desktop.log`.
- **Other OS**: `deno compile hono-desktop/mod.ts` → `dist/hono-desktop`.

`--no-check` required: TS annotations valid at runtime trip Deno's checker
under the desktop compile path. Use `deno check` directly for typechecking.

## Entrypoints

| Entrypoint | Purpose |
|-----------|---------|
| `hono-macos-runner-desktop/mod.ts` | macOS native tray app (Deno.Tray + Deno.BrowserWindow WebView) |
| `hono-desktop/mod.ts` | Cross-platform headless Hono server (`--start-bidder` mode) |

Both compose the same ABC-layered packages. No platform attestation
anywhere — Linux and Windows have no App Attest equivalent, so the key
surface is identical across OSes (see `device-key-*`).

## Architecture

```
hono-macos-runner-desktop/mod.ts (CLI)
  ├── createServe (127.0.0.1:random) — HTTP API + tray UI + OAuth callback
  ├── Deno.BrowserWindow + Deno.Tray + tray.attachPanel — menu bar UI
  └── ABC packages:
        device-key-webcrypto     — software ECDSA P-256 keys (Web Crypto)
        secret-store-chain       — win32 CredMan → gnome-keyring → filesystem
        atproto-oauth-fetch      — ATProto OAuth (PAR + PKCE + DPoP)
        badge-blue-keys-atproto  — key→DID association records
        market-bidder-keys       — market signing keypair persistence
```

Market bidder pieces (xrpc-relay, market-bidder, compute provider) are
dynamic-imported from sibling repos (`atproto-market`, `hono-compute-provider`)
inside `startBidder()`.

**IPC pattern:** WebView calls `fetch('/api/...')` to the loopback server.
`win.bind()` does NOT work on the WKWebView backend — see NOTES.md.

## Layer map (ABC)

```
lib/common/device-key        device-key-common      DeviceKeyError
lib/common/atproto-oauth     atproto-oauth-common   OAuthSession, client id/redirect defaults
lib/common/badge-blue-keys   badge-blue-keys-common NSID, record shape, base58btc
lib/abc/device-key           device-key-abc         DeviceKeyService, KeychainStore (+ in-memory test double)
lib/abc/atproto-oauth        atproto-oauth-abc      OAuthFlow
lib/abc/badge-blue-keys      badge-blue-keys-abc    AssociationService
lib/device-key-webcrypto     device-key-webcrypto   createDeviceKeyService, createRichKeychainStore
lib/secret-store-filesystem  JSON keystore (~/.pdr-keys/keystore.json)
lib/secret-store-gnome       gnome-keyring via secret-tool CLI
lib/secret-store-win32       Windows CredMan via advapi32.dll FFI
lib/secret-store-chain       buildStandardChain — first available wins
lib/atproto-oauth-fetch      OAuth impl (PAR, PKCE, DPoP, dpopFetchWrapper)
lib/badge-blue-keys-atproto  association record create/find
lib/market-bidder-keys       loadOrCreateMarketKeypair (secp256k1 via @atproto/crypto)
```

## ATProto OAuth flow

1. App generates DPoP key pair (P-256 via Web Crypto)
2. PAR push → system browser to PDS authorization URL
3. Callback arrives at the loopback HTTP server (`GET /` with code/state/iss)
4. Code exchanged for DPoP-bound tokens; session saved via RichKeychainStore
5. On restart: session restored from secret store, validated, refreshed if stale

Client metadata served by the app at `/oauth-client-metadata.json`.
Redirect URI is loopback HTTP (`oauth-redirect-uri` option).

## Association record rkey

`com.publicdomainrelay.temp.badgeBlueKeys` record rkey is deterministic,
no attestation involved:

```
sha256(did + ":" + keyId) → first 24 bytes → base58btc → first 32 chars
```

Same did+keyId always produces the same rkey → deterministic getRecord
lookups. Auto-created on session restore if missing.

## Key persistence

Device key id stored under `device-key-id` in the secret store chain;
private JWK under `key:<keyId>`. Generated once via
`deviceKeys.generateKey()` (`soft-<uuid>` ids) only if missing. Regenerate
via Settings → Identity → Danger Zone (clears session + record).

## Loopback CSRF protection

Server binds `127.0.0.1:random` — any local process can reach it. Mutating
`/api/*` POST routes require `X-App-Token` header. Token is random hex
generated at startup, injected into TRAY_HTML via `__APP_TOKEN__`; the page
monkey-patches `window.fetch` to attach it.

## Tray icon

Import `TRAY_ICON_BASE64` from `icon.ts`, decode via `atob()` → Uint8Array,
pass to `tray.setIcon()`. Do NOT use `Deno.readFileSync` — path resolution
fails inside the compiled `.app` bundle.

## Integration test

`../atproto-market/test/bidder_cross_platform_integration_test.ts` drives
the full RFP → bid → accept → cloud-init flow against both bidder variants
and imports this repo's `market-bidder-keys` + `secret-store-*` packages.
The tray entrypoints themselves need a native window and cannot run under
`Deno.test`.

## Multi-agent fan-out investigation pattern

When a hard bug spans multiple subsystems (webview rendering, CSS
transitions, native window resize, Deno runtime), launch 3-5 subagents in
parallel, each researching a different angle, then synthesize.

Use when: bug involves 3+ interacting layers; 2+ fix attempts failed; the
at-fault subsystem is unknown. Not for: single-file fixes or known root
causes. Give each agent a concrete question with file paths, function
names, and search terms — not "look into this bug." After they return,
prefer root causes that multiple agents identified independently. See
NOTES.md "Panel width transition — grey area fix" for a worked example.
