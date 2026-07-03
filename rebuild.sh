#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
DENO="${DENO_BIN:-$HOME/src/deno-fix/target/release/deno}"

# Kill previous running instance(s) so the new build replaces it.
kill_app() {
  local pat="deno-macos-runner-desktop|laufey_webview"
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

if [[ "$(uname)" == "Darwin" ]]; then
  echo "=== macOS: building .app bundle ==="
  kill_app
  # deno desktop creates <name>.app in the current directory
  rm -rf deno-macos-runner-desktop.app
  "$DENO" desktop --no-check --allow-all hono-macos-runner-desktop/mod.ts
  APP=$(find . -maxdepth 1 -name "*.app" -type d | head -1)
  if [ -z "$APP" ]; then
    echo "ERROR: .app bundle not found after build" >&2
    exit 1
  fi
  echo "=== Built: $APP ==="
  # Insurance: ensure nothing came back to life during the build before launching.
  kill_app
  open "$APP" --stdout /tmp/deno-macos-runner-desktop.log --stderr /tmp/deno-macos-runner-desktop.log
  echo "App logs: /tmp/deno-macos-runner-desktop.log"
else
  echo "=== Cross-platform: compiling hono-desktop binary ==="
  rm -f dist/hono-desktop
  mkdir -p dist
  "$DENO" compile --allow-all --output dist/hono-desktop hono-desktop/mod.ts
  echo "=== Built: dist/hono-desktop ==="
fi
