cd ~/src/publicdomainrelay/deno-macos-runner-desktop
~/src/deno-fix/target/debug/deno desktop --allow-ffi --allow-net --allow-read --allow-env --allow-write --allow-run --no-check main.ts
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

open dist/macOS-App-Attest.app
