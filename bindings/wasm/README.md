# pulse-wasm — the canonical codec in the browser

`pulse-canon` compiled to WebAssembly with a small JavaScript surface: encode, decode, verify and content-address envelopes, decode and build 128-byte Pulses, and re-run the conformance fixtures with the reference implementation itself. Codec only: no ring, no store, no transport, no I/O.

## Build

```
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version <the version pinned in Cargo.toml>
./build.sh [out-dir]          # default out-dir: pkg/
```

`build.sh` refuses to run if the installed `wasm-bindgen` does not match the pinned crate version; the generated glue and the crate must agree exactly. The output is an ES module (`pulse_wasm.js`), the module (`pulse_wasm_bg.wasm`) and TypeScript declarations (`pulse_wasm.d.ts`).

## Packaging

`scripts/package/wasm.sh`, run from the repository root, runs `build.sh` into `target/package/stage/wasm/`, writes a private `package.json` beside the output (name `pulse-wire-wasm`, the crate's version, `main` and `module` `pulse_wasm.js`, `types` `pulse_wasm.d.ts`) and packs it into `target/package/pulse-wire-wasm-<version>.tgz`; one package serves every platform. Node does not fetch `pulse_wasm_bg.wasm` by URL, so pass its bytes to `init()`, as `tests/smoke.mjs` does. `scripts/package/smoke.sh` installs the tarball into a fresh npm project and checks the specification's raw envelope fixture through it; `scripts/package/all.sh` builds and checks every binding's packages. Nothing is published or uploaded.

## Test

```
node tests/smoke.mjs
```

Re-runs every fixture under `pulse/pulse-spec/test-vectors/` through the wasm build, round-trips a typed envelope, checks that a tampered payload fails verification, and decodes the Pulse layout fixture.

## Use

```js
import init, * as pulse from './pulse_wasm.js';
await init();                                    // fetches pulse_wasm_bg.wasm next to the module
const bytes = pulse.envelope_encode(JSON.stringify({ type_name: 'demo/hello', payload_text: 'hello, pulse' }));
const env = JSON.parse(pulse.envelope_decode(bytes));   // id_hex, sizes, flags, payload tree, verified
pulse.envelope_verify(bytes);                            // true
```

Every function takes and returns plain data (byte arrays, strings, JSON text). `u64` fields are returned as decimal strings so nothing is lost in a JavaScript number. `pulse_wasm.d.ts` is the complete API.
