#!/usr/bin/env bash

cd ~/src/publicdomainrelay/deno-macos-runner-desktop
# Kill previous running instance(s) so the new build replaces it.
# Matches both the launcher path and the laufey_webview helper. Escalate
# SIGTERM -> SIGKILL and wait until no process remains before continuing,
# otherwise a surviving instance leaves an extra (offscreen) tray + windows.
kill_app() {
  local pat="macOS-App-Attest|laufey_webview"
  pgrep -f "$pat" >/dev/null 2>&1 || return 0
  pkill -TERM -f "$pat" 2>/dev/null || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    pgrep -f "$pat" >/dev/null 2>&1 || return 0
    sleep 0.3
  done
  pkill -KILL -f "$pat" 2>/dev/null || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    pgrep -f "$pat" >/dev/null 2>&1 || return 0
    sleep 0.3
  done
}
kill_app
# Clear macOS saved window state so relaunch does not restore stray Settings
# windows from the killed instance.
rm -rf "$HOME/Library/Saved Application State/com.publicdomainrelay.macos-app-attest2.savedState" 2>/dev/null || true
~/src/deno-fix/target/release/deno desktop --allow-ffi --allow-net --allow-read --allow-env --allow-write --allow-run --allow-sys --no-check hono-macos-runner-desktop/mod.ts
cp devicecheck_bridge.dylib dist/macOS-App-Attest.app/Contents/MacOS/

# Inject custom URL scheme into Info.plist
INFO_PLIST=dist/macOS-App-Attest.app/Contents/Info.plist
/usr/libexec/PlistBuddy -c "Delete :CFBundleURLTypes" "$INFO_PLIST" 2>/dev/null || true
/usr/libexec/PlistBuddy -c "Add :CFBundleURLTypes array" "$INFO_PLIST"
/usr/libexec/PlistBuddy -c "Add :CFBundleURLTypes:0 dict" "$INFO_PLIST"
/usr/libexec/PlistBuddy -c "Add :CFBundleURLTypes:0:CFBundleURLName string com.fedproxy.attest--johnandersen777-bsky-social" "$INFO_PLIST"
/usr/libexec/PlistBuddy -c "Add :CFBundleURLTypes:0:CFBundleURLSchemes array" "$INFO_PLIST"
/usr/libexec/PlistBuddy -c "Add :CFBundleURLTypes:0:CFBundleURLSchemes:0 string com.fedproxy.attest--johnandersen777-bsky-social" "$INFO_PLIST"

codesign --force --sign "Apple Development: John Andersen (C46CT949V3)" \
  dist/macOS-App-Attest.app/Contents/MacOS/devicecheck_bridge.dylib
codesign --force --sign "Apple Development: John Andersen (C46CT949V3)" \
  --entitlements app.entitlements \
  --options runtime \
  dist/macOS-App-Attest.app

# Start OAuth client metadata server + fedproxy tunnel
pkill -f "python3 -m http.server 9877" 2>/dev/null || true
pkill -f "fedproxy.com" 2>/dev/null || true
mkdir -p /tmp/attest-meta
cat > /tmp/attest-meta/oauth-client-metadata.json << 'METAEOF'
{
  "client_id": "https://attest--johnandersen777-bsky-social.fedproxy.com/oauth-client-metadata.json",
  "application_type": "native",
  "dpop_bound_access_tokens": true,
  "redirect_uris": ["com.fedproxy.attest--johnandersen777-bsky-social:/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "atproto repo:com.publicdomainrelay.temp.badgeBlueKeys?action=create",
  "token_endpoint_auth_method": "none",
  "client_name": "macOS App Attest"
}
METAEOF
(cd /tmp/attest-meta && python3 -m http.server 9877 &>/tmp/attest-meta-server.log &)
sleep 1
ssh -NnT -p 2222 \
  -o UserKnownHostsFile=/dev/null \
  -o StrictHostKeyChecking=no \
  -o PasswordAuthentication=no \
  -i ~/.ssh/id_ed25519 \
  -R attest:80:127.0.0.1:9877 \
  johnandersen777.bsky.social@fedproxy.com \
  &>/tmp/fedproxy-tunnel.log &
sleep 2
echo "Fedproxy tunnel status: $(cat /tmp/fedproxy-tunnel.log)"

# Insurance: ensure nothing came back to life during the build before launching.
kill_app
open dist/macOS-App-Attest.app --stdout /tmp/app.log --stderr /tmp/app.log
echo "App logs: /tmp/app.log"
