#!/bin/bash
set -euo pipefail

# Build the DeviceCheck bridge dylib for macOS App Attest
# Requires: Xcode CLI tools (clang, frameworks)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT="$SCRIPT_DIR/devicecheck_bridge.dylib"

echo "Building DeviceCheck bridge..."

# Build for both arm64 and x86_64 (universal)
ARCHS=("arm64" "x86_64")
OBJ_FILES=()

for arch in "${ARCHS[@]}"; do
  OBJ="$SCRIPT_DIR/devicecheck_bridge_${arch}.o"
  echo "  Compiling for $arch..."

  clang -c \
    -arch "$arch" \
    -fobjc-arc \
    -fmodules \
    -isysroot "$(xcrun --sdk macosx --show-sdk-path)" \
    -mmacosx-version-min=11.0 \
    -o "$OBJ" \
    "$SCRIPT_DIR/devicecheck_bridge.m"

  OBJ_FILES+=("$OBJ")
done

# Link universal dylib
echo "  Linking universal dylib..."
clang -shared \
  -arch arm64 -arch x86_64 \
  -fobjc-arc \
  -framework Foundation \
  -framework DeviceCheck \
  -framework AppKit \
  -framework Security \
  -mmacosx-version-min=11.0 \
  -o "$OUTPUT" \
  "${OBJ_FILES[@]}"

# Clean up intermediates
rm -f "${OBJ_FILES[@]}"

echo "Built: $OUTPUT"
echo "Architectures:"
lipo -info "$OUTPUT"
