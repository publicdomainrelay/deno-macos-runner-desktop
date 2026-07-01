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

### Fedproxy Skill

Full fedproxy documentation copied into `docs/fedproxy/`:
- `SKILL.md` — overview, mental model, service naming, workflow
- `references/tunnel-setup.md` — step-by-step tunnel setup
- `references/atproto-records.md` — ssh-public-key record schema
- `ssh-config-example` — SSH config snippet for persistent tunnels

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

On session detect (both fresh OAuth and Keychain restore), `createAssociationRecord()`
is called automatically. The record uses a deterministic `did:key:z...` rkey
derived from the Secure Enclave credential cert's public key (see below).
Auto-created if `getRecord` returns 404.

## FFI size_t* out-param is broken across Deno FFI

Multiple attempts to pass a `size_t*` output parameter through the FFI boundary
failed. Every approach produced garbled data on readback:

| Approach | Result |
|----------|--------|
| inline `new Uint8Array(lenBuf.buffer)` | garbled length (GC'd before FFI write?) |
| `allocSizeT()` + `readSizeT()` (same as attestKey) | garbled length |
| raw `new ArrayBuffer(8)` + DataView + Uint8Array ref | garbled length |
| embed 8-byte LE length prefix in malloc'd buffer | `ptr + 8n` BigInt arithmetic → TypeError |
| `readCStr` from null-terminated return (`keychain_load_str`) | **WORKS** |

The `size_t*` out-param works for `dc_attest_key` and `dc_generate_assertion`
but fails for `keychain_load` — likely a Deno FFI calling-convention edge case
on arm64 macOS. The fix: `keychain_load_str` returns `char*` null-terminated,
JS reads with `readCStr(ptr)`, frees with `dc_free_string(ptr)`. Same proven
pattern as `generateKey()`. **Never add new `size_t*` out-param FFI symbols.**

## npm packages panic deno compile

`deno desktop` (Deno 2.9.0) panics at `libs/node_resolver/analyze.rs:488` when
compiling with npm packages that have native addons (`cbor-x`, `cbor-extract`,
etc.) or complex module graphs. `@peculiar/x509` imported at top-level also
triggers the panic. JSR packages are safe. **Do not add npm deps to deno.json**
without testing `deno desktop --no-check main.ts` first.

Inline replacements used:
- **base58btc**: ~10-line encoder (not cryptography — just an encoding)
- **CBOR attestation parser**: CborDecoder class adapted from verify-record.ts
- **X.509 SPKI extraction**: hand-rolled ASN.1 TLV navigator → Web Crypto
  `importKey("spki")` + `exportKey("raw")`

## Association record rkey = did:key from credential cert

The badgeBlueKeys record uses a deterministic rkey derived from the Secure
Enclave credential cert's public key (not a random TID):

1. `attestKey(keyId, SHA-256(did))` → CBOR attestation blob
2. `CborDecoder` → extract `attStmt.x5c[0]` (DER-encoded credential cert)
3. `extractSpkiDer()` — ASN.1 TLV navigation past Certificate → tbsCertificate
   → version/serial/signature/issuer/validity/subject → SPKI SEQUENCE
4. `crypto.subtle.importKey("spki", spkiDer, {name:"ECDSA",namedCurve:"P-256"},...)`
5. `crypto.subtle.exportKey("raw", cryptoKey)` → 65-byte uncompressed public key
6. Prepend P-256 multicodec varint (0x80 0x24 = 0x1200)
7. base58btc encode → `did:key:z...` (101 chars)

Same keyId always produces same rkey. Valid ATProto rkey per spec:
allowed chars `A-Za-z0-9._-:~`, max 512 chars. Colon (from `did:key:`) is
explicitly permitted. Auto-created on session restore if getRecord returns 404.

## Loopback CSRF protection

`X-App-Token` header required on all mutating POST routes. Token = `randomHex(24)`
generated per launch, injected into both HTML templates via `__APP_TOKEN__`
placeholder, monkey-patched into `window.fetch` by tray/settings page JS.
Checked once at top of POST branch in handler.

## Tray icon from icon.ts

Import `TRAY_ICON_BASE64` from `icon.ts`, decode `atob()` → Uint8Array, pass
to `tray.setIcon()`. Do NOT use `Deno.readFileSync("tray-icon.png")` — path
resolution fails in compiled `.app` bundle.

## Key + session persistence

- Device key: `KC_DEVICE_KEY_ID = "device-key-id"` → Keychain via `keychainSave`/`keychainLoad`
- OAuth session: `KC_SESSION_KEY = "oauth-session"` → Keychain with DPoP JWK + tokens
- Both restored on startup. Session validated via getSession; refreshed if expired.
- Regenerate (Settings → Danger Zone) clears both + creates new key.
- `rebuild.sh` now `pkill -f "macOS-App-Attest"` before build to ensure clean restart.

## Panel width transition — grey area fix (2026-06-30)

### Problem

Switching between Home (320px) and Settings/Identity (560px) panel widths showed
a grey area at the bottom of the native window during and after the CSS width
transition. The transition animates `.panel { width }` over 320ms via
`cubic-bezier(.4,0,.2,1)` while the navrail simultaneously expands/collapses
(0px ↔ 120px). The native WKWebView window height is set before the CSS
animation starts, but the content height changes mid-transition as text reflows
at intermediate widths, creating a mismatch.

### Root cause (2 bugs)

1. **Navrail transition not disabled during pre-measurement** — `showView()` in
   `tray-ui.ts` disabled `.panel`'s CSS transition to snap-measure-snap, but
   `.navrail` has its own `transition: width .32s ...` and was NOT disabled.
   `void panelEl.offsetHeight` forced reflow while navrail's computed width was
   still 0px (start of its own animation), so `document.body.scrollHeight`
   reflected the content area at full 560px. But after the navrail animation
   completes, the navrail takes 120px, leaving only 440px for the content area
   → text wraps more → actual height is taller than measured → grey area.

2. **`reportHeight()` fired during active CSS transition** — `render()` calls
   `reportHeight()` at the end of every render cycle, which schedules a
   `requestAnimationFrame` callback. During the 320ms width animation, each
   rAF (~16ms) reads `document.body.scrollHeight` at the intermediate animated
   width and sends another `POST /api/tray-resize` with a wrong intermediate
   height, overwriting the correct pre-measured value.

### Fix (commit e49177e)

Three-part fix in `hono-macos-runner-desktop/tray-ui.ts`:

1. **Disable navrail transition during pre-measurement** — set both
   `navrailEl.style.transition = 'none'` and `panelEl.style.transition = 'none'`
   before snapping to target width + measuring `scrollHeight`. This ensures the
   measurement reflects the final layout state (navrail at 120px, content area
   at 440px).

2. **Height lock during CSS animation** — after `sendResize(targetWidth, h)`,
   set `panelEl.style.height = h + 'px'` to lock the panel height to the
   pre-measured value. This prevents the CSS width animation from changing
   `document.body.scrollHeight`, so `reportHeight()` mid-transition sees the
   same height → dedup check prevents spurious resizes.

3. **`transitionend` cleanup** — add a `transitionend` listener on `panelEl`
   (filtered to `propertyName === 'width'`) that clears the height lock and
   calls `reportHeight()` for the exact final height. This corrects any
   sub-pixel rounding differences between the pre-measured and actual
   post-animation heights.

### Key learnings

- `element.addEventListener('transitionend', ...)` fires on every completed CSS
  transition on that element AND its descendants (events bubble). Filter on
  `ev.propertyName` to only respond to the specific property (e.g. `width`).
- `panelEl.offsetHeight` forces a synchronous reflow that includes the current
  computed state of ALL transitioning elements — if any descendant has an active
  CSS transition, its width reflects the *start* of its animation, not the final
  value. Must disable ALL transitioning elements' transitions during snap-measure.
- `panelEl.style.height = h + 'px'` + `transitionend` → clear height + `reportHeight()`
  is a clean pattern: the native window is set to the correct size before the
  animation, the height lock prevents intermediate states from triggering
  spurious resizes, and the final cleanup handles rounding.

### 5-agent fan-out investigation pattern

This fix was developed by launching 5 parallel subagents, each researching a
different angle of the problem:

| Agent | Research direction | Key finding |
|-------|-------------------|-------------|
| 1 | WKWebView viewport resize behavior | Known macOS bug: `scrollHeight` can return viewport size, not content size |
| 2 | CSS transition layout reflow timing | Navrail transition not disabled — measured at wrong content area width |
| 3 | Native WKWebView resize mechanics | `#[fast]` op → synchronous `setFrame:` — no Rust-side async delay |
| 4 | Deno desktop runtime source | Full call chain: JS fetch → V8 op → laufey C ABI → NSWindow setFrame |
| 5 | JS-driven resize alternatives | rAF stepping, ResizeObserver, Web Animations API trade-offs |

Agents 2 and 4 independently identified the navrail transition as the root
cause. All 5 agents converged on the same fix strategy (pre-measure at final
state + lock height + transitionend cleanup). The fan-out pattern works because
each agent explores a different subsystem (WebKit internals, CSS spec, Deno
runtime, native macOS APIs) — findings that would take 10+ sequential tool calls
to discover individually are surfaced in parallel.

## Rebuild stdout/stderr capture (2026-06-30)

`rebuild.sh` `open` command now captures app stdout/stderr to `/tmp/app.log`:

```sh
open dist/macOS-App-Attest.app --stdout /tmp/app.log --stderr /tmp/app.log
echo "App logs: /tmp/app.log"
```

This makes structured JSON logs (from `createLogger`) available for debugging
without needing to re-launch the app manually with stdout capture.

### DPoP nonce retry on PDS resource calls (2026-06-30, commit fecfda9)

`lib/badge-blue-keys-atproto/mod.ts` `createRecord()` and the `getRecord` call
inside `findOrCreateRecord()` now retry once with the server-supplied
`DPoP-Nonce` header on `use_dpop_nonce` errors. Previously these PDS resource
calls sent DPoP proofs with no nonce and never retried, causing every first
attempt to fail silently → `associationRecordUri` stayed `null` forever.
Pattern matches `lib/atproto-oauth-fetch/mod.ts` which already handled this
correctly for PAR/token/getSession/refresh.

Also: `findOrCreateRecord` now treats `400 { error: "RecordNotFound" }` the
same as HTTP 404 (PDS returns 400, not 404, when a record doesn't exist).

### OAuth error banner shows real error (2026-06-30, commit fecfda9)

`tray-ui.ts` banner was hardcoded to `"Couldn't connect identity — request
expired"` regardless of what actually failed. Now renders `"Couldn't connect
identity: " + d.oauthError` so the real failure reason is visible.

### Session restore logging (2026-06-30, commit fecfda9)

Added structured log entries for every branch in the session-restore path
(`hono-macos-runner-desktop/mod.ts`):
- `"no saved session found in keychain, skipping restore"` when keychain returns null
- `"saved session loaded from keychain, validating"` when found
- `"findOrCreateRecord after restore"` / `"findOrCreateRecord after refresh"` with result

And in `lib/app-attest-darwin/mod.ts`:
- `"keychain load returned no item"` when `keychain_load_str` returns null
- `"keychain load skipped, bridge not loaded"` when bridge not initialized

Previously: `if (!saved) return;` with no log → impossible to distinguish
"keychain empty" from "keychain read failed" from "session parse error".
