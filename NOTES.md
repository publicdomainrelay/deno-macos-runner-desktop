# NOTES.md — macOS App Attest Deno Desktop

## Project

Deno desktop app calling Apple DeviceCheck DCAppAttestService via FFI.
App uses restricted entitlement `com.apple.developer.devicecheck.app-attest-opt-in`.
All app logic in TypeScript (`main.ts`). Native bridge in ObjC (`devicecheck_bridge.m`).

## Files in this directory

| File | Purpose |
|------|---------|
| `main.ts` | TypeScript app: FFI, HTTP server, web UI, BrowserWindow, tray, dock |
| `devicecheck_bridge.m` | ObjC bridge wrapping DCAppAttestService → sync C functions |
| `devicecheck_bridge.dylib` | Compiled universal binary (arm64 + x86_64) |
| `build_bridge.sh` | Compiles ObjC bridge to dylib |
| `deno.json` | Deno config + desktop block (bundle ID, sign identity) |
| `app.entitlements` | macOS entitlements for App Attest |
| `embedded.provisionprofile` | macOS dev provisioning profile (copied from Apple Developer) |
| `NOTES.md` | This file |

## Architecture

```
Page (HTML served by Deno.serve, JS served as /app.js)
  → fetch('POST', '/api/generate-key')          → { keyId }
  → fetch('POST', '/api/attest-key', body)       → { hex, length }
  → fetch('POST', '/api/generate-assertion', body) → { hex, length }
  → fetch('GET',  '/api/logs')                   → { entries }
  → fetch('GET',  '/api/health')                 → { ok }
    ↓ HTTP (same-origin, 127.0.0.1 loopback)
Deno.serve handler (routes by method + path)
  → sha256 via Web Crypto
  → generateKey() → attestKey() → generateAssertion()
    ↓ Deno.dlopen (FFI)
devicecheck_bridge.dylib (ObjC)
  → DCAppAttestService.sharedService
    ↓
Secure Enclave + Apple attestation servers
```

IPC is plain HTTP `fetch()` from the page to `Deno.serve` — the pattern shown
in the [Deno desktop docs](https://docs.deno.com/runtime/desktop/serving/).
No `win.bind()`, no `window.bindings`, no `win.executeJs`, no polling, no
timeouts. The page's own `<script>` (served as `/app.js`, not inline) wires
button click handlers with `addEventListener`; each handler `await`s a fetch
and updates the DOM with the result.

`win.bind()` registrations are kept (lines ~317-361) but the page never calls
`bindings.<name>()` — those are a no-op on the webview (WKWebView) backend.

## Webview IPC — what failed and why

Three approaches were attempted. Only the third works on the **webview (WKWebView)**
backend. The **CEF backend** presumably supports `win.bind()` → `bindings.<name>()`
(the documented primary IPC), but CEF was not tested.

### 1. `win.bind()` → `bindings.<name>()` from the page

Registered callbacks via `win.bind("generateKey", fn)` on the Deno side, then
called `await bindings.generateKey()` from the page's `<script>`.

**Result:** `Error: No callback bound for: generateKey`

**Root cause:** The `bindings` namespace works in the **executeJs isolated world**
(proved by diagnostics: `typeof window.bindings` → `"function"`, and
`executeJs("bindings.generateKey()")` succeeded). But the **page's main world**
does not see the registered callbacks — the lookup in `windowBindCallbacks`
(Maps keyed by `windowId`) fails. The exact mismatch (different windowId, or
different JS context) is inside the laufey crate and was not explored further
because `fetch()` solved it.

### 2. executeJs polling bridge (`window._call` / `window._result`)

Original code in `main.ts` had a `setInterval(50ms)` that polled `window._call`
via `win.executeJs`, dispatched to `BINDING_HANDLERS`, and wrote the result to
`window._result`. The page set `window._call = {id, name, args}` and polled
`window._result`.

**Result:** `bridgeCall` was always `undefined`. No call ever completed.

**Root cause:** `executeJs` runs in an **isolated world** — it shares the DOM
but NOT JavaScript globals. The page script writes to main-world `window._call`;
the polling loop reads isolated-world `window._call` (always `null`). The two
worlds' `window` objects are different.

### 3. `fetch()` to `Deno.serve` (CURRENT — WORKS)

The page uses `fetch('/api/<endpoint>', {method:'POST', body:...})` to call
Deno-side functions. Same-origin HTTP over the `127.0.0.1` loopback that
`Deno.serve` binds to. The handler routes by method + path and calls the FFI
functions directly.

**Result:** Full end-to-end flow works. No races, no world isolation, no
timeouts. This is the exact pattern from the Deno desktop docs — their
"Hello desktop" example uses `onclick="fetch('/api/hello')"`.

**JS is served as `/app.js` NOT inline in HTML.** The original page had an
inline `<script>` (5811 chars) that produced `SyntaxError: Unexpected EOF`
in the WKWebView engine (despite passing `node --check`). Serving the same
JS as an external file with MIME `application/javascript` fixed this — the
error was likely caused by `\/` escape sequences in string literals that
are valid in sloppy-mode V8 but rejected by JSC's strict-mode parser for
`<script>` elements.

## Problem: AMFI rejects restricted entitlements

### Symptom

`deno desktop main.ts` builds app. Signing with Apple Development cert + entitlements.
On launch, `amfid` kills process:

```
amfid: laufey_webview not valid:
  AppleMobileFileIntegrityError Code=-413 "No matching profile found"
taskgated-helper: Disallowing laufey_webview because no eligible provisioning profiles found
```

### Root cause

Two problems:

1. **Shell script as CFBundleExecutable.** `deno desktop` creates shell script
   launcher (`Contents/MacOS/<AppName>`) that execs `laufey_webview --runtime <dylib>`.
   Shell script cannot be codesigned with entitlements. AMFI evaluates main
   executable (shell script), finds no valid signature/entitlements, rejects
   provisioning profile match.

2. **Provisioning profile + entitlements never embedded.** `deno desktop` signs
   with laufey's browser entitlements only. User's `app.entitlements` ignored.
   `embedded.provisionprofile` not copied into bundle. No way to supply
   restricted entitlements to build.

### Fix (in `~/src/deno-fix/cli/tools/desktop.rs`)

Three changes to Deno source:

**A. `render_macos_info_plist` — CFBundleExecutable to laufey**

```diff
-fn render_macos_info_plist(app_name, bundle_id, has_icon)
+fn render_macos_info_plist(app_name, bundle_id, has_icon, executable_name)

-  <string>{app_name}</string>   <!-- shell script -->
+  <string>{executable_name}</string>  <!-- laufey_webview -->
```

Args: pass `laufey_executable_name` instead of `app_name`.

**B. `package_macos_app_bundle` — remove shell script, add profile + entitlements**

- Copy compiled dylib as `libruntime.dylib` (not `<app>.dylib`).
  laufey_webview auto-discovers `libruntime.dylib` in `Contents/MacOS/`.
  No `--runtime` flag needed.
- Remove shell script launcher generation entirely.
- Detect `embedded.provisionprofile` in source dir → copy to `Contents/`.
- Detect `app.entitlements` (or `entitlements.plist`) in source dir.
- Pass user entitlements to `codesign_macos_bundle`.

**C. `codesign_macos_bundle` — accept user entitlements**

```diff
-fn codesign_macos_bundle(app_bundle, identity)
+fn codesign_macos_bundle(app_bundle, identity, user_entitlements: Option<&Path>)
```

- Sign each Mach-O in `Contents/MacOS/` with `user_entitlements`.
- Sign main bundle with `user_entitlements` (fallback: laufey browser
  entitlements, then no entitlements).
- Updated call in `make_self_extracting_macos` to pass `None`.

## Apple Developer setup

### Step 1: Register App ID

At https://developer.apple.com/account/resources/identifiers/bundleId/add/bundle

- Description: `macOS App Attest v2`
- Bundle ID: `com.publicdomainrelay.macos-app-attest2` (Explicit)
- Capabilities: CHECK BOTH `App Attest` AND `App Attest Opt-In`
  (Must check at creation time — adding later via edit did not propagate
  to provisioning profile entitlements)

### Step 2: Create provisioning profile

At https://developer.apple.com/account/resources/profiles/add

- Type: macOS App Development
- App ID: `com.publicdomainrelay.macos-app-attest2`
- Certificate: John Andersen (John's MacBook Air) (Development)
- Devices: John's MacBook Air
- Name: `macOS App Attest v2 Dev`

Download → renames to UUID.mobileprovision → copy to project as `embedded.provisionprofile`.

### Step 3: Verify profile entitlements

```sh
security cms -D -i <profile> | plutil -p - | grep -A2 app-attest
# Must show: com.apple.developer.devicecheck.app-attest-opt-in => ["CDhash"]
```

### Step 4: Entitlements file

`app.entitlements`:
```xml
<key>com.apple.application-identifier</key>
<string>8YNHGS3252.com.publicdomainrelay.macos-app-attest2</string>
<key>com.apple.developer.team-identifier</key>
<string>8YNHGS3252</string>
<key>com.apple.developer.devicecheck.app-attest-opt-in</key>
<array><string>CDhash</string></array>
```

## Build & Run

### 1. Build bridge dylib

```sh
./build_bridge.sh
```

### 2. Build desktop app with patched Deno

```sh
# Use locally built deno from ~/src/deno-fix
~/src/deno-fix/target/debug/deno desktop main.ts
```

Patched deno output:
```
Embedded embedded.provisionprofile
Codesigning bundle with identity "Apple Development: John Andersen (C46CT949V3)"
./dist/macOS-App-Attest.app/Contents/MacOS/libruntime.dylib: replacing existing signature
./dist/macOS-App-Attest.app/Contents/MacOS/laufey_webview: replacing existing signature
./dist/macOS-App-Attest.app: replacing existing signature
Bundle ./dist/macOS-App-Attest.app
```

### 3. Copy + sign bridge dylib post-build

```sh
cp devicecheck_bridge.dylib dist/macOS-App-Attest.app/Contents/MacOS/
codesign --force --sign "Apple Development: John Andersen (C46CT949V3)" \
  dist/macOS-App-Attest.app/Contents/MacOS/devicecheck_bridge.dylib
codesign --force --sign "Apple Development: John Andersen (C46CT949V3)" \
  --entitlements app.entitlements \
  dist/macOS-App-Attest.app
```

### 4. Launch

One-shot build+sign+launch:

```sh
./rebuild.sh
```

Or step by step:

```sh
open dist/macOS-App-Attest.app
```

Logs appear in `~/logs/app-attest/<iso8601>.ndjson` (one file per launch).
The app logs to both console and file; the in-app Logs panel reads the
in-memory ring buffer (last 500 entries) via `GET /api/logs`.

### 5. Verify

```sh
codesign -d --entitlements - dist/macOS-App-Attest.app/Contents/MacOS/laufey_webview
# Must show: com.apple.developer.devicecheck.app-attest-opt-in => ["CDhash"]
#           com.apple.application-identifier => 8YNHGS3252.com.publicdomainrelay.macos-app-attest2

pgrep -ilf laufey_webview
# Must show process running (not killed by AMFI)
```

## Bundle structure (after fix)

```
macOS-App-Attest.app/
  Contents/
    Info.plist          → CFBundleExecutable = laufey_webview
    embedded.provisionprofile
    MacOS/
      laufey_webview    → main executable (signed with user entitlements)
      libruntime.dylib  → compiled Deno code (auto-discovered by laufey)
      devicecheck_bridge.dylib → FFI bridge (copied post-build, signed)
    Resources/
      .deno-desktop-app → build marker
```

## macOS version requirement

App Attest on macOS was announced at WWDC 2026 and requires **macOS 27+**.
On macOS 26.x and earlier, `DCAppAttestService.isSupported` returns `false` unconditionally
regardless of hardware, entitlements, or signing. Everything else in this project
(AMFI, signing, FFI bridge, provisioning profile) is working correctly on macOS 26.5.1
with an M5 MacBook Air — it just needs macOS 27 to actually run attestation.

See: https://developer.apple.com/forums/thread/831492

## What didn't work

- **`win.bind()` → `bindings.<name>()` from page main world**: Callbacks
  registered but lookup fails ("No callback bound"). Works from executeJs
  isolated world; page's main world can't reach them. Switched to `fetch()`.
- **executeJs polling bridge** (`window._call`/`window._result`): executeJs
  runs in isolated world; can't read page's `window._call`. Abandoned.
- **Inline `<script>` in HTML template**: Produced `SyntaxError: Unexpected EOF`
  in WKWebView engine (node --check passed on same source). Served JS as
  external `/app.js` instead — fixed.
- **Editing App ID post-creation**: Adding capability checkboxes after App ID
  was registered did not propagate to provisioning profile entitlements.
  Must set both checkboxes at creation time.
- **Ad-hoc signing (`-s -`) with restricted entitlements**: AMFI rejects.
  Must use real Apple Development/Developer ID certificate.
- **Deno `deno.json` `macos.codesignIdentity`**: Works. Passed to build.
  CLI flag `--codesign-identity` not implemented upstream (only config file).
- **CEF backend**: Not tested. Might work differently with AMFI and/or support
  `bindings.<name>()` from the page's main world.

## Key insight

macOS `amfid` validates provisioning profiles against app bundle's main
executable (`CFBundleExecutable` in Info.plist). When main executable is
a shell script (no code signature), provisioning profile match fails.
Making `laufey_webview` the main executable fixes this because:
1. laufey_webview is a Mach-O binary that can be codesigned
2. laufey_webview auto-discovers `libruntime.dylib` in its `Contents/MacOS/`
3. AMFI finds matching provisioning profile for signed binary with correct
   `application-identifier` entitlement

## Patched Deno source

Fork: https://github.com/johnandersen777/deno
Branch: `fix/desktop-macos-entitlements-provisioning`

Changes in `~/src/deno-fix/cli/tools/desktop.rs` (search for `NOTE` comments):

- `render_macos_info_plist` — added `executable_name` param
- `package_macos_app_bundle` — libruntime.dylib, no shell script, profile + entitlements detection
- `codesign_macos_bundle` — user_entitlements param, signs Mach-O files with user entitlements
- Test at line ~5133 updated for new `render_macos_info_plist` signature

To rebuild patched Deno:
```sh
cd ~/src/deno-fix
source ~/.cargo/env
cargo build -p deno
```

## ATProto OAuth + DPoP

### Custom URL Scheme for OAuth Callback

Deno desktop doesn't expose Apple Events (`NSAppleEventManager`). Workaround:
added `url_register_handler` / `url_scheme_pending` to `devicecheck_bridge.dylib`.

`url_register_handler` installs handler for `kInternetEventClass / kAEGetURL`
on the main queue. `main.ts` polls `url_scheme_pending` every 500ms; when the
OAuth callback fires, the handler stores the URL in a `@synchronized`-protected
static `url_pending` buffer.

`CFBundleURLTypes` injected post-build via PlistBuddy (see `rebuild.sh`) because
`deno desktop` has no pre-build hook for this.

### OAuth Client Registration — Why Fedproxy Is Required

bsky.social rejects `http://localhost` client type when `redirect_uris` contains
a custom URI scheme (not loopback). That client type is restricted to loopback
redirects only. To use `application_type: "native"` with a custom scheme, the
client metadata must be served at a stable HTTPS URL.

**Runtime requirement:** `rebuild.sh` starts:
1. `python3 -m http.server 9877` serving `/tmp/attest-meta/oauth-client-metadata.json`
2. SSH tunnel: `ssh -R attest:80:127.0.0.1:9877 johnandersen777.bsky.social@fedproxy.com -p 2222`
   → public HTTPS URL: `https://attest--johnandersen777-bsky-social.fedproxy.com`

Key: `~/.ssh/id_ed25519` must be registered with `johnandersen777.bsky.social` on fedproxy.

### Redirect URI Scheme Format

bsky.social requires the scheme to be the reversed FQDN of the `client_id` host
(RFC 8252 §7.1) and uses a single slash (`:/<path>` not `://<host>/<path>`).

Correct: `com.fedproxy.attest--johnandersen777-bsky-social:/callback`

Rejected:
- `pdrattest://` — no dots in scheme
- `pdrattest.app://` — double slash
- any scheme not matching reversed `client_id` host

### DPoP `ath` Claim

Resource server requests require `ath = base64url(SHA-256(access_token))` in
the DPoP proof JWT. Token endpoint requests do NOT include `ath`. The distinction
matters — bsky returns 401 if `ath` is present at token endpoint or missing at
resource endpoint.

`createDpopProof(method, url, nonce?, accessToken?)` — pass `accessToken` for
resource requests, omit for token endpoint.

### Session Persistence (Keychain)

OAuth session (DPoP private key JWK + access token + refresh token + DID) stored
in macOS Keychain via `keychain_save` / `keychain_load` FFI calls.

- Account name: `oauth-session`
- Service: `com.publicdomainrelay.macos-app-attest`
- Accessibility: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`

On startup, `loadSession` reads from Keychain and restores the DPoP key pair via
`crypto.subtle.importKey`. If valid session found, OAuth flow is skipped.

### Key Auto-Creation

On session detect (both fresh OAuth and Keychain restore), `createKey()` is
called automatically with `service: '*'`. A `keyCreated` flag prevents duplicate
creates in the same session. The manual "Create BadgeBlue Key" button was removed.
