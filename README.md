# macOS App Attest — Deno Desktop App

Uses Apple's DCAppAttestService (DeviceCheck framework) from a Deno desktop app
via FFI. All app logic in TypeScript (`main.ts`).

## Prerequisites

- Deno 2.9+ (`deno desktop` available)
- macOS 11+ (App Attest requires Secure Enclave — Macs with T2 or Apple Silicon)
- Xcode CLI tools (for clang, frameworks)

## Quick start

```sh
# 1. Build the FFI bridge dylib
./build_bridge.sh

# 2. Run the desktop app
deno desktop main.ts

# 3. Build standalone binary
deno desktop main.ts --output ./dist/macOS-App-Attest.app

# 4. Re-sign with entitlements (required for App Attest)
codesign -f -s - --entitlements app.entitlements dist/macOS-App-Attest.app
```

## Files

| File | Role |
|------|------|
| `main.ts` | TypeScript app: FFI bindings, HTTP server, web UI, BrowserWindow, tray, dock |
| `devicecheck_bridge.m` | Objective-C bridge: wraps DCAppAttestService async APIs with sync C functions |
| `devicecheck_bridge.dylib` | Compiled universal binary (arm64 + x86_64) |
| `build_bridge.sh` | Compiles the bridge |
| `deno.json` | Project config with desktop block |
| `app.entitlements` | macOS entitlements for App Attest (`com.apple.developer.devicecheck.app-attest-opt-in`) |

## Architecture

```
┌─────────────────────────────────────────┐
│  Deno Desktop App                       │
│  ┌───────────────────────────────────┐  │
│  │  Webview (HTML/JS UI)             │  │
│  │  bindings.generateKey()           │  │
│  │  bindings.attestKey(id, challenge)│  │
│  │  bindings.generateAssertion(...)  │  │
│  └──────────┬────────────────────────┘  │
│             │ win.bind() (in-process)    │
│  ┌──────────▼────────────────────────┐  │
│  │  Deno Runtime (TypeScript)        │  │
│  │  Attestation API layer            │  │
│  └──────────┬────────────────────────┘  │
│             │ Deno.dlopen (FFI)          │
│  ┌──────────▼────────────────────────┐  │
│  │  devicecheck_bridge.dylib (C)     │  │
│  │  dc_generate_key()                │  │
│  │  dc_attest_key()                  │  │
│  │  dc_generate_assertion()          │  │
│  └──────────┬────────────────────────┘  │
│             │ Objective-C                │
│  ┌──────────▼────────────────────────┐  │
│  │  DCAppAttestService (Apple)       │  │
│  │  Secure Enclave + Apple servers   │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

## App Attest flow

1. **Generate Key** — creates hardware-bound key pair in Secure Enclave
2. **Attest Key** — Apple signs an attestation proving the key is genuine
3. **Generate Assertion** — signs arbitrary data, verifiable by any server

Used for: anti-fraud, device trust, replay prevention, bot detection.

## Entitlements

The app needs `com.apple.developer.devicecheck.app-attest-opt-in` with the
`CDhash` key. Without this entitlement, `DCAppAttestService.isSupported` returns
`false`.

`deno desktop` does not currently embed custom entitlements during build. After
building, re-sign:

```sh
codesign -f -s - --entitlements app.entitlements dist/macOS-App-Attest.app
```

For distribution with a Developer ID:

```sh
codesign -f -s "Developer ID Application: Your Name (TEAMID)" \
  --entitlements app.entitlements \
  --options runtime \
  dist/macOS-App-Attest.app
```

## Limitations

- **macOS only** — DCAppAttestService is Apple-platform-specific
- **Requires Secure Enclave** — not available in VMs (unless T2/SEP passthrough)
- **Requires code signature** — the app must be signed for attestation to work
- App Attest requires network access to Apple's attestation servers
