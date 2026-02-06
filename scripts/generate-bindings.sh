#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> Building UniFFI library..."
cargo build -p libveritas-uniffi

DYLIB="target/debug/liblibveritas_uniffi.dylib"
if [ ! -f "$DYLIB" ]; then
  echo "error: $DYLIB not found" >&2
  exit 1
fi

echo "==> Generating Swift bindings..."
cargo run --bin uniffi-bindgen generate \
  --library "$DYLIB" \
  --language swift \
  --out-dir bindings/uniffi/bindings/swift

echo "==> Generating Kotlin bindings..."
cargo run --bin uniffi-bindgen generate \
  --library "$DYLIB" \
  --language kotlin \
  --out-dir bindings/uniffi/bindings/kotlin

echo "==> Generating Python bindings..."
cargo run --bin uniffi-bindgen generate \
  --library "$DYLIB" \
  --language python \
  --out-dir bindings/uniffi/bindings/python

echo "==> Building WASM package..."
CC="${CC:-/opt/homebrew/opt/llvm/bin/clang}" \
AR="${AR:-/opt/homebrew/opt/llvm/bin/llvm-ar}" \
wasm-pack build bindings/wasm/ \
  --target nodejs \
  --out-dir ../../examples/js/pkg \
  --out-name libveritas

echo "==> Done."
echo "  Swift:  bindings/uniffi/bindings/swift/"
echo "  Kotlin: bindings/uniffi/bindings/kotlin/"
echo "  Python: bindings/uniffi/bindings/python/"
echo "  WASM:   examples/js/pkg/"
