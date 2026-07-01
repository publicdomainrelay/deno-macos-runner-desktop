# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Custom Deno binary — required

Stock `deno` does **not** work. Use the patched build.

**When npm dependencies are imported** (any `@noble/*`, `@atproto/*`, etc.), the **release** build is required — the debug build panics at `libs/node_resolver/analyze.rs:488` with `debug_assert!(false)` on CJS-like npm packages. Without npm deps, the debug build is fine.

```sh
# With npm deps (market bidder enabled):
~/src/deno-fix/target/release/deno

# Without npm deps (clean):
~/src/deno-fix/target/debug/deno
```

Fork: https://github.com/johnandersen777/deno  
Branch: `fix/desktop-macos-entitlements-provisioning`  
Patch location: `cli/tools/desktop.rs`

What the patch fixes: `deno desktop` normally sets the shell-script launcher as `CFBundleExecutable`, which AMFI rejects when restricted entitlements (App Attest) are required. The patch renames the compiled dylib to `libruntime.dylib` (laufey auto-discovers it), removes the shell script, and threads `app.entitlements` + `embedded.provisionprofile` through the build.

To clone and build the patched deno from scratch:
```sh
git clone https://github.com/johnandersen777/deno ~/src/deno-fix
cd ~/src/deno-fix
git checkout fix/desktop-macos-entitlements-provisioning
# Install Rust if needed: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
cargo build -p deno
# Binary at: ~/src/deno-fix/target/debug/deno
```

To rebuild after making changes to the patch:
```sh
# Debug (fast compile, no npm deps support):
cd ~/src/deno-fix && source ~/.cargo/env && cargo build -p deno

# Release (needed for npm deps like @noble/curves):
cd ~/src/deno-fix && source ~/.cargo/env && cargo build -p deno --release
```

## Build & run

```sh
# 1. Build the FFI bridge (only needed when devicecheck_bridge.m changes)
./build_bridge.sh

# 2. Full build + sign + launch (always use this for launch/relaunch — never launch the app any other way)
./rebuild.sh
```

`rebuild.sh` does in order:
1. `deno desktop --no-check main.ts` (builds `dist/macOS-App-Attest.app`)
2. Copies + codesigns `devicecheck_bridge.dylib` into the bundle
3. PlistBuddy: injects `CFBundleURLTypes` for the custom OAuth callback scheme
4. Re-signs the whole bundle with `app.entitlements`
5. Starts the OAuth client metadata HTTP server on port 9877
6. Opens a fedproxy SSH tunnel (`attest` service → `https://attest--johnandersen777-bsky-social.fedproxy.com`)
7. Opens the app

The `--no-check` flag is required because TypeScript annotations in `main.ts` trigger type errors in Deno's checker but are valid at runtime.

## Architecture

```
main.ts (TypeScript, Deno runtime)
  ├── Deno.serve (127.0.0.1:random) — HTTP API + OAuth client metadata
  ├── Deno.BrowserWindow — webview UI (HTML/JS inline served as /app.js)
  ├── Deno.Tray — menu bar icon
  └── Deno.dlopen → devicecheck_bridge.dylib (Objective-C FFI)
        ├── DCAppAttestService — generate/attest/assert keys (Secure Enclave)
        ├── NSAppleEventManager — kAEGetURL handler for OAuth callback URL scheme
        └── Security framework — Keychain save/load/delete for session persistence
```

**IPC pattern:** Webview calls `fetch('/api/...')` to the `Deno.serve` loopback. `win.bind()` / `bindings.<name>()` does NOT work on the WKWebView backend — the page's main JS world cannot reach callbacks registered on the Deno side. See NOTES.md for full explanation.

## FFI symbols (`devicecheck_bridge.dylib`)

| Symbol | Purpose |
|--------|---------|
| `dc_generate_key` | Create Secure Enclave key, returns keyId string |
| `dc_attest_key` | Attest key with Apple, returns CBOR blob |
| `dc_generate_assertion` | Sign challenge, returns CBOR blob |
| `dc_last_error` / `dc_free_string` / `dc_free_buffer` | Error/memory management |
| `url_register_handler` | Register `kAEGetURL` Apple Event handler |
| `url_scheme_pending` | Poll for pending OAuth callback URL (500ms interval) |
| `keychain_save` / `keychain_load` / `keychain_delete` | Keychain CRUD (legacy — `keychain_load` out-param broken, see below) |
| `keychain_load_str` | **Preferred**: returns null-terminated C string, no size_t* out-param |

### `keychain_load_str` vs `keychain_load`

`keychain_load` passes a `size_t*` out-param through FFI to return the buffer
length. Every approach tried failed — inline Uint8Array GC'd, allocSizeT/
readSizeT unreliable, raw ArrayBuffer same result. The `size_t*` pointer
crossing the FFI boundary appears to be a Deno FFI bug or calling-convention
edge case on arm64 macOS.

`keychain_load_str` bypasses this entirely: returns a `char*` null-terminated
string. JS reads via `readCStr(ptr)` + frees with `dc_free_string(ptr)` —
the same proven pattern as `generateKey()`. Always use `keychain_load_str`
for new Keychain read paths; never add a new `size_t*` out-param FFI symbol.

### npm packages + `deno compile`

`deno desktop` panics at `libs/node_resolver/analyze.rs:488` when compiling
with npm packages that have native addons or complex module graphs
(`cbor-x`, `bs58`, etc.). `@peculiar/x509` imported at top-level also
triggers this. **Do not add npm dependencies to deno.json** unless tested
with `deno desktop --no-check main.ts` first. JSR packages are fine.

Workarounds used:
- **Base58**: ~10-line inline encoder (not crypto, just encoding)
- **CBOR x5c extraction**: CborDecoder class copied from verify-record.ts
- **X.509 SPKI extraction**: hand-rolled ASN.1 TLV navigator → Web Crypto
  `importKey("spki")` + `exportKey("raw")`

## ATProto OAuth flow

1. App generates DPoP key pair (P-256, ECDH + ECDSA via Web Crypto)
2. Fetches PDS auth server metadata → PAR endpoint
3. Pushes PAR request → gets `request_uri`
4. Opens system browser to PDS authorization URL
5. User approves → bsky.social fires the custom URI scheme callback:
   `com.fedproxy.attest--johnandersen777-bsky-social:/callback?code=...`
6. `NSAppleEventManager` handler stores URL; `url_scheme_pending()` poll picks it up
7. App exchanges code for tokens (DPoP-bound access token)
8. Session (DPoP key JWK + tokens + DID) saved to Keychain → restored on next launch

**Client ID:** `https://attest--johnandersen777-bsky-social.fedproxy.com/oauth-client-metadata.json`  
**Redirect URI:** `com.fedproxy.attest--johnandersen777-bsky-social:/callback`

The custom URI scheme must be the reversed FQDN of the `client_id` host (RFC 8252 §7.1). bsky.social enforces this.

## Fedproxy dependency

The OAuth client metadata must be served at a stable HTTPS URL (`http://localhost` client_id only allows loopback redirects). `rebuild.sh` starts:
- `python3 -m http.server 9877` serving `/tmp/attest-meta/oauth-client-metadata.json`
- SSH tunnel: `ssh -R attest:80:127.0.0.1:9877 johnandersen777.bsky.social@fedproxy.com -p 2222`

The fedproxy skill is in `.claude/skills/fedproxy/`. SSH key `~/.ssh/id_ed25519` must be registered for the `attest` service on fedproxy.com under `johnandersen777.bsky.social`.

## DPoP `ath` claim

Resource server requests (getSession, createRecord) require `ath = base64url(SHA-256(accessToken))` in the DPoP proof JWT. Token endpoint requests must NOT include `ath`. `createDpopProof` in `main.ts` takes an optional `accessToken` param — pass it for resource requests, omit for token endpoint.

## Association record rkey

The `com.publicdomainrelay.temp.badgeBlueKeys` record uses a deterministic
rkey derived from the Secure Enclave credential cert's public key:

```
attestKey(keyId, SHA-256(did)) → CBOR attestation
  → CborDecoder → attStmt.x5c[0] (credential cert DER)
  → extractSpkiDer() — ASN.1 TLV navigation past cert wrapper
  → crypto.subtle.importKey("spki", ...) → exportKey("raw")
  → prepend P-256 multicodec (0x80 0x24)
  → base58btc encode
  → "did:key:z..."
```

Result is ~101 chars — valid ATProto rkey (allowed chars `A-Za-z0-9._-:~`,
max 512). Same keyId always produces same rkey, enabling deterministic
getRecord lookups. Auto-created on session restore if missing.

## Key persistence

Device key (`KC_DEVICE_KEY_ID = "device-key-id"`) persisted in Keychain
alongside OAuth session. On startup, loaded via `keychainLoad(KC_DEVICE_KEY_ID)`.
Fresh key generated via `generateKey()` only if missing. Regenerate via
Settings → Identity → Danger Zone → Regenerate Key (clears session + record).

## Loopback CSRF protection

`Deno.serve` on `127.0.0.1:random` — any local process can reach it.
Mutating `/api/*` POST routes require `X-App-Token` header. Token is
`randomHex(24)` generated at startup, injected into TRAY_HTML/SETTINGS_HTML
via `__APP_TOKEN__` placeholder. Both pages monkey-patch `window.fetch` to
attach the header. Checked once at top of POST branch.

## Tray icon

Import `TRAY_ICON_BASE64` from `icon.ts`, decode via `atob()` → Uint8Array,
pass to `tray.setIcon()`. Do NOT use `Deno.readFileSync("tray-icon.png")` —
path resolution fails in compiled app bundle (`deno desktop` / `.app`).

## Apple Developer setup (one-time, already done)

- Bundle ID: `com.publicdomainrelay.macos-app-attest2`
- Team: `8YNHGS3252`
- Signing identity: `Apple Development: John Andersen (C46CT949V3)`
- `embedded.provisionprofile` → excluded from git, must be present locally (download from developer.apple.com → copy to repo root)
- App Attest requires **macOS 27+** — `DCAppAttestService.isSupported` returns false on macOS 26 regardless of hardware

## Verify record

`verify-record.ts` verifies a `com.publicdomainrelay.temp.badgeBlueKeys` AT Protocol record:

```sh
~/src/deno-fix/target/debug/deno run --allow-net verify-record.ts \
  at://did:plc:lpfuqerea3deuoyrn7ojser4/com.publicdomainrelay.temp.badgeBlueKeys/3mpikojqzow2i
```

DER parsing notes (bugs already fixed): CBOR-decoded byte slices must be copied before DER parsing (non-zero `byteOffset`); SPKI extraction returns the full `SubjectPublicKeyInfo` SEQUENCE; version `[0]` EXPLICIT must be fully skipped with `skip(readLength())`; P-384 intermediate CA is detected via OID bytes before defaulting to P-256.

## Multi-agent fan-out investigation pattern

When a hard bug spans multiple subsystems (webview rendering, CSS transitions,
native window resize, Deno runtime), launch 3-5 subagents in parallel, each
researching a different angle. Their findings come back as tool results you
can synthesize.

### When to use

- Bug involves 3+ interacting layers (e.g. CSS → JS → native → OS API)
- You've tried 2+ fix attempts and the problem persists
- You don't know which subsystem is at fault
- A single agent reading all relevant files would be >200 tool calls

### NOT for

- Simple typos, single-file fixes, known-good patterns
- When you already know the root cause

### Pattern

```
Agent 1: Research <runtime/platform> behavior (e.g. WKWebView viewport resize, macOS NSWindow setFrame)
Agent 2: Research <language/API> specs (e.g. CSS transition reflow timing, scrollHeight accuracy)
Agent 3: Read our <codebase> for the affected path (e.g. tray-ui.ts, mod.ts — find the full call chain)
Agent 4: Read our <platform source> for the native side (e.g. Deno desktop.rs, laufey lib.rs)
Agent 5: Research alternative approaches (e.g. JS-driven animation, ResizeObserver, Web Animations API)
```

### What we learned (panel width transition grey area, June 2026)

- 5 agents launched in parallel, each with different research direction
- Agents 2 and 4 independently found the same root cause (navrail transition not disabled during measurement)
- Agent 3 traced the full call chain from JS `fetch()` through Deno V8 ops to macOS `setFrame:`, confirming the native resize is synchronous (`#[fast]` op)
- Agent 1 found known WKWebView bugs (scrollHeight inaccuracy, viewport resize async pipeline)
- Agent 5 evaluated alternative approaches (rAF stepping, ResizeObserver, height lock)

All 5 converged on the same fix: disable navrail transition during pre-measurement + lock panel height during animation + transitionend cleanup.

**Result:** The fix worked on first try. Total wall-clock time: ~2 min (all agents ran in parallel). Without fan-out: would have been 15+ min of sequential reading/debugging across 6+ files in 3+ subsystems.

### Agent prompts — make them specific

Each agent needs a concrete research question and specific search terms, not
"look into this bug." Give them file paths, function names, and search queries.

Good: "Read `hono-macos-runner-desktop/mod.ts` lines 374-391, find the
`resizeTrayPanel` function. Trace how it calls `win.setSize()`. Read
`~/src/deno-fix/cli/tools/desktop.rs` and search for `set_size`."

Bad: "Look into the resize issue."

### Synthesis step

After all agents return, compare their findings:
- Which root causes did multiple agents independently identify?
- Which findings are complementary (non-overlapping)?
- Which findings contradict each other? (re-read the relevant code)
- Synthesize the simplest fix that addresses the root cause(s)

See NOTES.md "Panel width transition — grey area fix" for the full
implementation notes from this investigation.
