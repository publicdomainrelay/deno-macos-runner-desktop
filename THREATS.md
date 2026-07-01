# THREATS.md — macOS App Attest Desktop App

Threat model for `deno-macos-runner-desktop`: a Deno desktop app that holds a
Secure Enclave-backed DeviceCheck key, an ATProto OAuth session (DPoP-bound
tokens in Keychain), and binds an attestation to the user's DID via a public
ATProto record.

Scope: code in this dir only (`main.ts`, `devicecheck_bridge.m`, `verify-record.ts`,
`rebuild.sh`, `build_bridge.sh`, entitlements). Assumes single-user macOS
workstation, attacker has no physical/root access unless stated.

## Assets

- Secure Enclave App Attest key (`persistentKeyId`) — hardware-bound, not
  exportable, but usable via the bridge while the process is alive.
- ATProto OAuth session: `accessJwt`, `refreshJwt`, DPoP private key (JWK) —
  stored in macOS Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`).
- The user's ATProto repo write capability (scoped to
  `com.publicdomainrelay.temp.badgeBlueKeys?action=create`).
- `THREATS` below cover spoofing the DID-binding attestation, not the
  Secure Enclave itself (out of scope — Apple's TCB).

## Findings

### 1. Loopback HTTP server has no caller authentication (local CSRF / confused deputy) — FIXED

`Deno.serve({ port: 0, hostname: "127.0.0.1" }, handler)` exposed mutating
`/api/*` routes (`start-oauth`, `create-key-record`, `unlink`,
`regenerate-key`, `/api/state`) with no origin check, no CSRF token, no
`Sec-Fetch-Site` validation. Any local process — or any web page the user had
open, via `fetch()` to `http://127.0.0.1:<port>` (port randomized but
enumerable by scanning) — could trigger OAuth, mint a new DeviceCheck
attestation, and publish a public `badgeBlueKeys` record under the victim's
DID, all using the live in-memory session and hardware key.

Per the Deno desktop docs (`docs.deno.com/runtime/desktop/bindings`),
`win.bind()` IPC is in-process (no network surface at all) — the ideal fix —
but it's confirmed broken on this app's WKWebView backend (see `CLAUDE.md`),
so the HTTP server stays the active transport.

**Fix applied:** `main.ts` generates a random per-launch `APP_TOKEN`
(`randomHex(24)`) at startup. It's injected into `TRAY_HTML`/`SETTINGS_HTML`
via an `__APP_TOKEN__` placeholder substituted on `GET /tray` and
`GET /settings`, and both pages monkey-patch `window.fetch` to attach it as
`X-App-Token` on every outgoing request. The server checks
`req.headers.get("X-App-Token") !== APP_TOKEN` once, up front, for the whole
`POST` branch of `handler()` and returns `401` on mismatch — a process that
can reach the loopback port but never received the served HTML (and thus
never saw the token) can no longer call any mutating route. The unauthenticated
OAuth-callback `GET /` route is untouched (a real external browser redirect
has no way to carry this header) and remains protected by the existing
`state === oauthOngoingState` check.

### 2. Custom URL scheme (`pdrattest://`) has no app-level binding check

`devicecheck_bridge.m:124-164` (`url_register_handler` / `url_scheme_pending`)
accepts any `pdrattest://` (actually `com.fedproxy.attest--...:`) Apple Event
and stores it as pending, and `main.ts:1034-1073` blindly trusts
`state === oauthOngoingState` as the only check before exchanging the code.

This is standard RFC 8252 custom-scheme OAuth and the `state` check is the
correct mitigation for code interception by a second app registering the same
scheme — so this is **not flagged as exploitable** given the `state` binding,
but note: `oauthOngoingState` is a single global, not per-tab/per-window. If
two `Associate with ATProto Account` flows from two windows are started
concurrently, the second overwrites `oauthCodeVerifier` /
`oauthDpopKeyPair` for the first (denial of mismatched flow, not a
confidentiality issue — excluded per DOS exclusion).

### 3. `verifyAppAttestChain` is a stub — does not verify signatures — FIXED

`verifyAppAttestChain` previously only checked "cert present, issuer
present" and always `return true`. The credential-extension nonce check
(`includesBytes`, step 6) still bound the attestation to the challenge/DID,
but **without verifying the leaf cert was actually issued by Apple's pinned
root**, a self-signed cert chain with an attacker-fabricated credential
extension would have passed `verifyBadgeBlueKeysRecord`. This was the
highest-severity finding — it undermined the entire attestation guarantee the
project exists to provide.

**Fix applied:** replaced the hand-rolled DER walker (`extractSpkiFromCert`,
`derOid`, `parseCertExtensions`) with `@peculiar/x509` (`npm:@peculiar/x509`,
added to `deno.json` imports + `nodeModulesDir: "auto"`). `parseCert` now
returns an `X509Certificate` plus its extensions map (unchanged shape for
callers). `verifyAppAttestChain` now: (1) rejects chains shorter than 2
certs, (2) checks every cert's `notBefore`/`notAfter` against `now`, (3)
walks leaf → intermediate verifying each cert's signature against the next
cert's public key via `cert.verify({ publicKey, signatureOnly: true })`, (4)
verifies the final intermediate is signed by `APPLE_ROOT_CERT` (the pinned
PEM, parsed once at module load via `pemToDer`). Any failure returns a
specific `reason` string surfaced in the `INVALID:` CLI output instead of a
silent `true`. Verified the module resolves (`deno cache`) and runs cleanly
against malformed input without crashing.

### 4. Entitlements weaken the hardened runtime — accepted tradeoff, documented

`app.entitlements:13-18` sets:
```
com.apple.security.cs.allow-jit
com.apple.security.cs.allow-unsigned-executable-memory
com.apple.security.cs.disable-executable-page-protection
```
These disable hardened-runtime code-injection protections (allow loading
unsigned/JIT'd code, writable+executable pages) for an app that holds live
OAuth tokens and a DeviceCheck key handle. They materially increase the
blast radius of any RCE in this process (e.g. a parser bug in
`verify-record.ts` or in the webview JS surface) since standard W^X /
code-signing process-injection defenses are off.

**Decision:** keep all three. They're required for Deno's V8 JIT to run at
all under the hardened runtime — without them the app fails to launch, not
just degrades. No code change; this finding is recorded as an accepted
tradeoff specific to embedding a JIT-ing JS runtime in a hardened-runtime
macOS app, not a fixable bug. If a future Deno desktop release supports a
no-JIT/interpreter-only mode for `deno desktop` builds, revisit dropping
these.

### 5. `keychain_save` accessibility class allows access whenever device unlocked

`devicecheck_bridge.m:188`: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
This is reasonable (no iCloud sync, no background access) but means any other
process running as the same macOS user, with Keychain access entitlement or
via `security` CLI prompts, can read the stored DPoP private key + refresh
token while the screen is unlocked — standard same-user Keychain ACL
behavior, not a code defect, noted for completeness since the asset (account
takeover via refresh-token theft) is high value. No fix needed beyond what's
already in place (`ThisDeviceOnly`, no `kSecAttrAccessGroup` sharing).

## Out of scope / explicitly not flagged

- DCAppAttestService internals — Apple's TCB.
- `rebuild.sh` hardcoded codesign identity / team ID — local dev tooling, not
  shipped.
- DOS via the `setInterval(..., 500)` URL-scheme poll or log flush timers.
- Keychain secrets at rest — handled by macOS, not this app's code.
