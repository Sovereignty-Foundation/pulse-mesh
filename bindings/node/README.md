# pulse-wire (Node bindings)

Node.js bindings for the [Pulse Mesh](https://pulse-mesh.net/) standard, built with [napi-rs](https://napi.rs). The native module wraps the `pulse-wire-udp` transport (`Pulse`, `Sender`, `Receiver`, `bindPair`), the canonical envelope codec (`encodeEnvelope`, `decodeEnvelope`, `envelopeId`) and `Channel`, messages between processes on one host over the shared-memory ring and envelope store. It is the Python binding's surface in JavaScript: a channel's writer and reader may be in either language.

> Part of the Pulse Mesh workspace: see the [book](https://pulse-mesh.net/docs/) for the architecture and the [Node bindings reference](https://pulse-mesh.net/docs/reference/node.html).

## Build

```
npm ci
npm run build          # napi build --platform --release: the module, index.js and index.d.ts
```

`npm run build` writes `index.<platform>-<arch>.node` beside `index.js`, which loads it. It also regenerates `index.js` and `index.d.ts` from the Rust source, so the declarations follow the code; `__test__/typings.test.mjs` fails when the two disagree. The package is built for `aarch64-apple-darwin`, `x86_64-apple-darwin`, `aarch64-unknown-linux-gnu` and `x86_64-unknown-linux-gnu` (`napi.triples.additional` in `package.json`); `index.js` loads the module for each.

## Packaging

`scripts/package/node.sh`, run from the repository root, builds the modules and packs them with `index.js`, `index.d.ts`, `README.md` and `package.json` into `target/package/pulse-wire-<version>.tgz` (`npm pack`; the package stays private): darwin arm64 natively and darwin x64 cross-compiled on a Mac, linux arm64 and x64 (glibc) in Docker. Each module is built by `npm run build` into a directory of its own, so `index.js` and `index.d.ts` here are not rewritten, and the script fails if napi's copies of them differ from these. `scripts/package/smoke.sh` installs the tarball into a fresh npm project, on this host and in Docker for Linux, and runs an envelope and loopback round trip through `require('pulse-wire')`; `scripts/package/all.sh` builds and checks every binding's packages. Nothing is published or uploaded.

## UDP: `Sender`, `Receiver`, `bindPair`

The examples are ES modules (top-level `await`); `require('pulse-wire')` gives the same names.

```js
import { Pulse, Instruction, Sender, Receiver } from 'pulse-wire';

const rx = Receiver.bind('127.0.0.1:9000');
const tx = Sender.bind('127.0.0.1:0');
tx.connect('127.0.0.1:9000');

const pulse = new Pulse();
pulse.instruction = Instruction.Data;
tx.send(process.hrtime.bigint(), pulse, Buffer.from('hello'));

const frame = await rx.recvAsync(1000);   // { pulseBytes, envelope, seq, sendNs, peer }, or null
```

A received frame is `{ pulseBytes, envelope, seq, sendNs, peer }`; `Pulse.fromBytes(frame.pulseBytes)` gives the typed Pulse. `recvInto(buf)` writes the envelope into a caller-owned Buffer instead of allocating one.

### Waiting without blocking the event loop

`recv()` and `recvInto()` wait on the calling thread, which in Node is the event loop: no timer, I/O callback or promise runs until a frame comes or the read timeout (`setReadTimeoutMs`) passes, and the timeout throws. They are kept for code that wants exactly that.

`recvAsync(timeoutMs?)` waits on a thread of the receiver's own and returns a promise of the frame, or of `null` if none came within `timeoutMs` milliseconds. Without `timeoutMs` it waits as long as `setReadTimeoutMs` says, and without that until a frame comes; a pending receive with no limit keeps Node running. `recvAsync(0)` takes a frame already queued and waits for none. Receives asked for together settle in order, each with the next frame. The waits do not use libuv's thread pool, so receives waiting never hold up `fs`, `dns` or `crypto` calls.

While a `recvAsync` has not settled, `recv()` and `recvInto()` on the same receiver throw an error with code `Busy` rather than wait on the event loop for it.

### One socket for sending and receiving

`bindPair(localAddr)` binds one UDP socket and returns `{ sender, receiver }` sharing it, so datagrams leave from the port their replies come back to. A program behind a home router (NAT) needs this: the router lets a reply through only to the port the request left from, and often only from the address it was sent to, so a program that sends on one socket and listens on another never hears its replies. A peer that answers should reply with its own pair's sender to `frame.peer`, the address the request came from.

```js
import { bindPair } from 'pulse-wire';

const { sender, receiver } = bindPair('0.0.0.0:0');
sender.sendTo(sendNs, pulse, Buffer.from('task'), '203.0.113.7:41001');
const reply = await receiver.recvAsync(5000);   // the reply, through the router
```

## Channel: messages over shared memory

`Channel` carries messages one way between processes on the same host over Pulse's shared-memory ring and envelope store, with no socket in the path. A channel named `name` is a ring `/name` and an envelope store `/name-e`. The writer stores each message as one envelope and publishes a Data pulse naming it, as the hub runtime broadcasts an envelope; the reader reads the ring's positions in order and fetches the envelope each pulse names. Messages arrive in order and none is dropped: the writer waits while the reader has `min(capacity, storeSlots)` messages unread.

- One writer and one reader per channel. For two directions, use two channels.
- A message is an array of Buffers (or one Buffer). Its framed size, 4 bytes for the frame count and 4 for each frame's length plus the frames, is at most `Channel.maxPayload()` bytes, so that its envelope fits the store's 64 KB entry. A larger message throws `EnvelopeTooLarge` and nothing is sent.
- Names are at most 29 bytes with their leading slash, so the store's name fits macOS's 31-byte limit; a longer name throws `InvalidArg`.
- `Channel.open(name, timeoutMs = 10000)`, `send(frames, timeoutMs = 5000)` and `recv(timeoutMs?)` wait on the event loop. `send` throws `Timeout` if the reader leaves no room in time; `recv` returns `null` when nothing comes in time (no `timeoutMs`: no limit).
- `recvAsync(timeoutMs?)` waits on a thread of the channel's own and returns a promise of the next message, or of `null` when nothing comes in time. While it waits, `recv` throws `Busy`; `close`, `pending` and the other accessors still answer at once.
- Once the writer has closed the channel and every message has been read, `recv` throws and `recvAsync` rejects with code `ChannelClosed`.
- The writer's `close()` removes both names; `Channel.create` also removes any left by an earlier run. Close each end when done with it: an end dropped without `close()` is released only when it is garbage-collected.

```js
import { Channel } from 'pulse-wire';

// Process A: the writer.
const tx = Channel.create('jobs', 4096, 256);
tx.send([Buffer.from('header'), Buffer.from('body')]);
tx.close();

// Process B: the reader. Waits up to 10 s for the writer to create the channel.
const rx = Channel.open('jobs', 10_000);
const frames = await rx.recvAsync(1000);   // [<Buffer header>, <Buffer body>], or null
rx.close();
```

Each store entry takes 64 KB of shared memory, so the default 256-entry store is about 16 MB per channel.

## Envelope codec

`encodeEnvelope`, `decodeEnvelope` and `envelopeId` are the canonical `PulseEnvelope` codec of chapter 3 of the specification, the Rust codec itself, so their bytes are the Rust and Python bindings'.

```js
import { encodeEnvelope, decodeEnvelope, envelopeId } from 'pulse-wire';

const bytes = encodeEnvelope({ envelopeType: 0, typeName: 'demo/hello', payload: Buffer.from('hi') });
const env = decodeEnvelope(bytes);   // { id, envelopeType, typeName, payload, origin, monotonicNanos, flags }
envelopeId({ envelopeType: 0, typeName: 'demo/hello', payload: Buffer.from('hi') }).equals(env.id);   // true
```

An envelope is described as `{ envelopeType, typeName?, payload, origin?, monotonicNanos?, flags? }`. `payload` is a Buffer for a raw payload, or an array of envelopes described the same way for a nested one; a decoded nested envelope's `payload` is the array of its decoded children. The id is always computed from the type, the type name and the payload. `decodeEnvelope` refuses bytes that are not exactly one canonical envelope (`InvalidArg`) and any envelope, nested ones included, whose stated id is not its content's (`EnvelopeIdMismatch`).

## Errors

Every error the binding throws or rejects with has a `code`, one of the values of the exported `ErrorCode`: `InvalidArg` and `GenericFailure` (napi's own, which the earlier API's errors keep), `Timeout`, `Busy`, `ChannelClosed`, `EnvelopeTooLarge` and `EnvelopeIdMismatch`.

```js
import { ErrorCode } from 'pulse-wire';

try {
  rx.recv(1000);   // rx: a Channel's reader end
} catch (err) {
  if (err.code === ErrorCode.ChannelClosed) { /* the writer is done */ }
}
```

## Tests

```
npm ci
cargo build && cp target/debug/libpulse_wire.dylib index.darwin-arm64.node   # or: npm run build:debug
npm test
```

`scripts/gate.sh --full` runs them as `bindings-node-test`, after `bindings-node` lints the crate. They cover the UDP loopback and the `Sender` type checks (`smoke.test.mjs`), `recvAsync` and `bindPair` (`recv_async.test.mjs`), `Channel` in one process and with a forked reader (`channel.test.mjs`), the binding's codec against every vector in `pulse/pulse-spec/test-vectors/` and against the pure-JavaScript codec (`envelope.test.mjs`), that pure-JavaScript codec against the Rust and Python layouts and the vectors (`canonical_codec_cross_language.test.mjs`), and `index.d.ts` against the module's exports (`typings.test.mjs`).
