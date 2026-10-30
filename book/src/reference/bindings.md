# Language bindings

<p class="pm-kind"><b>Reference</b> · the codec bindings and the thin clients in the tree, by kind</p>

Pulse Mesh offers two different ways to use it from outside Rust, depending on whether you want to embed the codec/transport natively or just talk to a running daemon.

## Native bindings (compiled)

These wrap the wire codec and UDP transport directly, for embedding in another language's runtime. None are Cargo workspace members — build each from its own directory.

- **`bindings/c/`** — a C FFI (`cdylib`/`staticlib`) over `pulse-wire-udp`; see [C bindings](c.md).
- **`bindings/python/`** — a PyO3/maturin module named `pulse_wire`; see [Python bindings](python.md).
- **`bindings/node/`** — napi-rs bindings; see [Node bindings](node.md).

Build these with `maturin`/`napi`/the C toolchain plus `cbindgen`, from within their own directories — mixing their linker settings into the workspace-wide `cargo build --workspace` is exactly what the workspace exclusion avoids.

## Thin clients (pure-language, no compilation)

These talk to an already-running `mesh-hub` daemon over WebSocket — no native compilation step, no linking against the Rust codec:

- **`clients/pms-py-thin/`** (daemon repository) — Python package `pms`, exposing `Mesh`/`MeshEvent`/`attach`.
- **`clients/pms-node-thin/`** (daemon repository) — a single-dependency (`ws`) Node package, class `Mesh`.

Both discover the daemon via the `PMS_DAEMON` environment variable, defaulting to `ws://127.0.0.1:9876`; neither supports the Unix-domain-socket transport, only WebSocket. If you're prototyping a producer or consumer in Python or Node and don't need the raw codec, start here rather than with the native bindings — [Two programs talk through the daemon](/docs/daemon/examples/two-programs.html) runs both.

## WebAssembly

`bindings/wasm/` compiles the canonical codec (`pulse-canon`) to WebAssembly with `wasm-bindgen`. It exposes encode, decode, verify and content-address for envelopes, decode and build for 128-byte Pulses, and `check_fixture`, which re-runs a conformance fixture inside the browser. Build with `./build.sh` (the installed `wasm-bindgen` CLI must match the version pinned in its `Cargo.toml`); `node tests/smoke.mjs` verifies the build against every fixture under `pulse/pulse-spec/test-vectors/`. The Pulse Mesh website consumes this build for its in-page encoder and live visualizations.
