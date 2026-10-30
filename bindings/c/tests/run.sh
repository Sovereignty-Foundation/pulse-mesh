#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Proprietary
#
# tests/run.sh — build the C FFI crate, compile + run the smoke test.
# Usage: ./tests/run.sh    (run from the crate root)
set -euo pipefail

CRATE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CRATE_DIR"

echo "==> cargo build --release"
cargo build --release

OUT_DIR="$CRATE_DIR/target/release"
INC_DIR="$CRATE_DIR/include"

# On macOS the dylib is libpulse_wire.dylib; on Linux it's libpulse_wire.so.
case "$(uname -s)" in
    Darwin) DYLIB_EXT="dylib" ;;
    Linux)  DYLIB_EXT="so" ;;
    *)      DYLIB_EXT="dylib" ;;  # default; adjust if porting
esac

if [[ ! -f "$OUT_DIR/libpulse_wire.$DYLIB_EXT" ]]; then
    echo "ERROR: $OUT_DIR/libpulse_wire.$DYLIB_EXT not found" >&2
    exit 1
fi

# Find a working C compiler. cc / clang on macOS, gcc on most Linux.
CC="${CC:-cc}"
echo "==> compiling tests/smoke.c with $CC"

# We link the staticlib (libpulse_wire.a) so the smoke binary is
# self-contained. Linking the dylib also works but introduces a
# DYLD_LIBRARY_PATH / LD_LIBRARY_PATH dependency for execution.
"$CC" -std=c11 -Wall -Wextra -Werror \
    -I "$INC_DIR" \
    "$CRATE_DIR/tests/smoke.c" \
    "$OUT_DIR/libpulse_wire.a" \
    -o "$OUT_DIR/smoke" \
    -lpthread -ldl

echo "==> running smoke test"
"$OUT_DIR/smoke"
