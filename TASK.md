# TASK: ATProto OAuth + DeviceCheck BadgeBlue Keys

## What we're building

A macOS desktop app (Deno desktop runtime + BrowserWindow webview) that:

1. Generates hardware-bound keys via Apple's DeviceCheck `DCAppAttestService` (Secure Enclave)
2. Authenticates users via ATProto OAuth (PKCE + PAR + DPoP)
3. Creates `com.publicdomainrelay.temp.badgeBlueKeys` records in the user's ATProto repo
4. Each record binds a DeviceCheck attestation to the user's DID

## Architecture

```
┌──────────────────────────────────────────────────────┐
│ Deno Desktop App (macOS .app bundle)                 │
│                                                      │
│  ┌─────────────┐  ┌──────────────────────────────┐  │
│  │ BrowserWindow│  │ HTTP Server (127.0.0.1:PORT) │  │
│  │ (webview)    │  │                              │  │
│  │             │  │ POST /api/generate-key       │  │
│  │ Section 1-3 │  │ POST /api/attest-key         │  │
│  │ DeviceCheck │  │ POST /api/generate-assertion │  │
│  │ key ops     │  │                              │  │
│  │             │  │ POST /api/atproto/start-oauth│  │
│  │ Section 4   │  │ GET  /api/atproto/session    │  │
│  │ ATProto     │  │ POST /api/atproto/create-    │  │
│  │ OAuth +     │  │       key-record             │  │
│  │ BadgeBlue   │  │ POST /api/atproto/regenerate │  │
│  │ Keys        │  │       -key                   │  │
│  └─────────────┘  │                              │  │
│                    │ OAuth callback: GET /?code=  │  │
│  devicecheck_      │   &state=&iss=              │  │
│  bridge.dylib ────┤                              │  │
│  (FFI to DCApp    └──────────────────────────────┘  │
│   AttestService)                                     │
└──────────────────────────────────────────────────────┘
```

## OAuth Flow (system browser + loopback redirect)

1. User enters handle (or clicks Bluesky chip) → clicks "Associate with ATProto Account"
2. Server resolves handle → DID → PDS → Auth Server
3. Server does PAR (Pushed Authorization Request) with PKCE + DPoP, gets `request_uri`
4. Server opens **system browser** via `open` command to `authorization_endpoint?client_id=...&request_uri=...`
5. User authenticates on PDS in system browser
6. PDS redirects to `http://127.0.0.1:PORT/?code=...&state=...&iss=...`
7. App HTTP server catches callback, exchanges code for tokens (DPoP with nonce retry), stores session
8. Server returns "Authenticated — close this window" page
9. Webview polls `GET /api/atproto/session` every 2s → detects session → shows logged-in state
10. User clicks "Create BadgeBlue Key"
11. Server generates DeviceCheck attestation bound to DID, creates ATProto record

## Identity resolution chain

1. HTTP well-known: `https://{handle}/.well-known/atproto-did`
2. Fallback: Bluesky directory `https://bsky.social/xrpc/com.atproto.identity.resolveHandle`
3. DID → PLC directory → DID doc → PDS endpoint
4. PDS → `/.well-known/oauth-protected-resource` → Auth Server
5. Auth Server → `/.well-known/oauth-authorization-server` → endpoints

## DPoP nonce handling

- PAR: first attempt without nonce → server may 400 with `DPoP-Nonce` header → retry with nonce
- Token exchange: uses nonce from PAR response → server may 400 with `use_dpop_nonce` → retry
- getSession: uses stored nonce → server may 401 with `use_dpop_nonce` → retry

## Key persistence

- DeviceCheck key generated ONCE at app startup (`persistentKeyId`)
- Stored in memory for session lifetime
- Reused for all badge blue key records (same hardware key, different DID challenges)
- "Regenerate Key" button creates fresh key

## Build

```bash
cd ~/src/publicdomainrelay/deno-macos-runner-desktop
./rebuild.sh
# Uses custom deno binary: ~/src/deno-fix/target/debug/deno
# Flags: --allow-ffi --allow-net --allow-read --allow-env --allow-write --allow-run --no-check
# --allow-run required for system browser open
# --no-check required because TypeScript annotations in JS file
```

## Verification

```bash
# From log output after creating a record:
deno run --allow-net verify-record.ts at://did:plc:.../com.publicdomainrelay.temp.badgeBlueKeys/...
```

## Known issues / TODO

- [ ] System browser redirect lands in browser, not back in app. Research custom URL scheme 
      (`com.publicdomainrelay.macos-app-attest://callback`) for proper desktop app OAuth.
      Requires: Info.plist CFBundleURLTypes + Deno desktop URL event handling.
- [ ] --no-check needed because TypeScript type annotations (interface, Promise<...>)
      in @ts-nocheck file. Clean up annotations or fix tsconfig.
- [ ] Window height hardcoded at 980px — may need adjustment for new sections.
- [ ] Tray icon PNG not found at build time (tray-icon.png missing from dist/).
- [ ] fetchSessionInfo DPoP retry — currently retries on use_dpop_nonce only.
      Could add retry on the main createRecord call too.

## Test account

Handle: aliceoa.bsky.social
DID: did:plc:lpfuqerea3deuoyrn7ojser4

## File map

```
main.ts              — Desktop app (BrowserWindow + HTTP server + ATProto OAuth)
rebuild.sh           — Build + codesign + launch
verify-record.ts     — Standalone attestation verifier
tests/main_test.ts   — Deno.test API + identity integration tests
tests/webview-ui.spec.ts — Playwright UI tests
tests/applescript-test.sh — macOS GUI automation
app.entitlements     — macOS entitlements (App Attest, network, etc.)
devicecheck_bridge.dylib — FFI bridge to DCAppAttestService
```
