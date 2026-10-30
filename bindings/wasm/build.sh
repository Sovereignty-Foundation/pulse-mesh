#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Proprietary
# Copyright (c) 2026 Sovereignty Foundation
# Build the codec for the browser: cargo (wasm32) + wasm-bindgen (web target).
#   ./build.sh [out-dir]      default out-dir: ./pkg
# Requires: rustup target wasm32-unknown-unknown; wasm-bindgen-cli at the
# exact version pinned in Cargo.toml (`cargo install wasm-bindgen-cli --version <v>`).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
OUT="${1:-pkg}"
PIN=$(sed -n 's/^wasm-bindgen = "=\(.*\)"/\1/p' Cargo.toml)
HAVE=$(wasm-bindgen --version | awk '{print $2}')
[ "$PIN" = "$HAVE" ] || { echo "wasm-bindgen-cli $HAVE does not match the pinned crate $PIN" >&2; exit 1; }
cargo build --release --target wasm32-unknown-unknown
wasm-bindgen --target web --out-dir "$OUT" --out-name pulse_wasm target/wasm32-unknown-unknown/release/pulse_wasm.wasm
ls -la "$OUT"
