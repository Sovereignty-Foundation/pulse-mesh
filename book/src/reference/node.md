# Node bindings

<p class="pm-kind"><b>Reference</b> · the Node binding: what it wraps, how to build it and where to read its API</p>

The Node binding lives at `bindings/node/` — napi-rs bindings exposing `Pulse`, `Sender` (`bind`, `connect`, `send`, `sendTo`), `Receiver` (`bind`, `setReadTimeoutMs`, `recv`, `recvInto`), and the `PULSE_WIRE_SIZE`/`MAX_ENVELOPE`/`HEADER_BYTES` constants (see [Language bindings](bindings.md)).

Build and inspect it locally:

```
cd bindings/node
npm install
npm run build
node -e "console.log(Object.keys(require('./index.js')))"
```

The generated `index.d.ts` TypeScript declarations (produced by napi-rs from the Rust source) are the most direct API reference — they carry accurate signatures for every exported class and constant. `__test__/smoke.test.mjs` and `canonical_codec_cross_language.test.mjs` show real usage.
