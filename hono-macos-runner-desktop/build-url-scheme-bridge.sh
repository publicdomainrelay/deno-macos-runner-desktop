#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT="$SCRIPT_DIR/url-scheme-bridge.dylib"

ARCHS=("arm64" "x86_64")
OBJ_FILES=()

for arch in "${ARCHS[@]}"; do
  OBJ="$SCRIPT_DIR/url-scheme-bridge_${arch}.o"
  clang -c \
    -arch "$arch" \
    -fobjc-arc \
    -fmodules \
    -isysroot "$(xcrun --sdk macosx --show-sdk-path)" \
    -mmacosx-version-min=11.0 \
    -o "$OBJ" \
    "$SCRIPT_DIR/url-scheme-bridge.m"
  OBJ_FILES+=("$OBJ")
done

clang -shared \
  -arch arm64 -arch x86_64 \
  -fobjc-arc \
  -framework Foundation \
  -framework AppKit \
  -mmacosx-version-min=11.0 \
  -o "$OUTPUT" \
  "${OBJ_FILES[@]}"

rm -f "${OBJ_FILES[@]}"

echo "Built: $OUTPUT"
lipo -info "$OUTPUT"
