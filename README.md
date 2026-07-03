# deno-macos-runner-desktop

Bidder desktop tray UI.

## Build

```sh
deno task build
```

- **macOS**: `deno desktop --no-check hono-macos-runner-desktop/mod.ts` → `.app` bundle
- **Other**: `deno compile hono-desktop/mod.ts` → binary in `dist/`

Custom Deno binary at `~/src/deno-fix/target/release/deno` required. Set
`DENO_BIN` to override.

## Entrypoints

| Entrypoint | Purpose |
|-----------|---------|
| `hono-macos-runner-desktop/mod.ts` | macOS native (tray + WebView) |
| `hono-desktop/mod.ts` | Cross-platform headless Hono server |

Both entrypoints share the same portable key + secret-store surface:
software ECDSA P-256 device keys (`device-key-webcrypto`) and the
win32 CredMan → gnome-keyring → filesystem secret-store chain. No
platform attestation (App Attest / DeviceCheck) — Linux and Windows have
no equivalent primitive, so the surface stays identical across OSes.
