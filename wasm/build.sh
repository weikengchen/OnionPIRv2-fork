#!/bin/bash
# Build the OnionPIR WASM client module.
# Prerequisites: emsdk installed and activated (source ~/emsdk/emsdk_env.sh)
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

# Check for Emscripten
if ! command -v emcc &>/dev/null; then
    echo "Error: emcc not found."
    echo "Install emsdk:"
    echo "  git clone https://github.com/emscripten-core/emsdk.git ~/emsdk"
    echo "  cd ~/emsdk && ./emsdk install latest && ./emsdk activate latest"
    echo "Then activate:"
    echo "  source ~/emsdk/emsdk_env.sh"
    exit 1
fi

echo "Using emcc: $(which emcc)"
emcc --version | head -1

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

echo "Configuring with emcmake cmake..."
emcmake cmake "$SCRIPT_DIR" \
    -DCMAKE_BUILD_TYPE=Release

echo "Building with emmake make..."
NPROC=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
emmake make -j"$NPROC" onionpir_client

echo ""
echo "Build complete!"
echo "  JS:   $BUILD_DIR/onionpir_client.js"
echo "  WASM: $BUILD_DIR/onionpir_client.wasm"
echo ""
echo "Usage in browser:"
echo "  import createOnionPirModule from './onionpir_client.js';"
echo "  const Module = await createOnionPirModule();"
echo "  const client = new Module.OnionPirClient(65536);"
