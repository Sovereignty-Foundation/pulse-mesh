# pulse-wire (Python bindings)

Python bindings for the [Pulse Mesh](https://pulse-mesh.net/) `pulse-wire-udp` transport, built with [PyO3](https://pyo3.rs). The native module wraps `Pulse`, `Sender`, and `Receiver` so Python callers can drive Pulse Mesh's framed UDP traffic without dropping into Rust, `PulseEnvelope`, the canonical envelope codec, and `Channel`, messages between processes on one host over shared memory. `pulse_wire.pyi` types all of it.

> Part of the Pulse Mesh workspace — see the [book](https://pulse-mesh.net/docs/) for architecture and the full [Python bindings reference](https://pulse-mesh.net/docs/reference/python.html).

## Build

maturin does not build this crate from inside the tree; cargo does, as the gate does. From this directory, for the `python3` on your path:

```
PYO3_PYTHON=$(command -v python3) cargo build --release
mkdir -p target/module
cp target/release/libpulse_wire.dylib target/module/pulse_wire.so   # libpulse_wire.so on Linux
PYTHONPATH=target/module python3 -c "import pulse_wire"
```

For installable wheels, see Packaging below.

## Packaging

`scripts/package/wheels.sh`, run from the repository root, builds the wheels into `target/package/`: for macOS (on a Mac, one per local CPython 3, tagged with the deployment target the module was linked for, e.g. `macosx_11_0_arm64`) and `manylinux_2_28` aarch64 and x86_64 for CPython 3.10 to 3.13, the Linux ones in Docker. It does not use maturin: cargo builds the extension for one interpreter at a time, as the gate does, and `scripts/package/wheel.py` writes the wheel around it, with `pulse_wire.pyi` and `py.typed`. `scripts/package/smoke.sh` installs each wheel into a fresh virtual environment, on this host or in the manylinux image, and runs an envelope and loopback round trip; `scripts/package/all.sh` builds and checks every binding's packages. Nothing is published or uploaded.

## Usage

```python
import time
import pulse_wire as pw

rx = pw.Receiver.bind("127.0.0.1:9000")
tx = pw.Sender.bind("127.0.0.1:0")
tx.connect("127.0.0.1:9000")

pulse = pw.Pulse()
pulse.instruction = pw.Instruction.DATA
tx.send(time.time_ns(), pulse, b"hello")

received_pulse, envelope, meta = rx.recv()
assert envelope == b"hello"
```

`Sender`/`Receiver` also expose `send_to`, `send_buffer` (from any buffer-protocol object, with no Python `bytes` in between), and `recv_into` (writes the envelope into a caller-owned buffer) — see the module's own docstrings (`help(pulse_wire)`) for the full signatures.

## One socket for sending and receiving

`pulse_wire.bind_pair(local_addr)` binds one UDP socket and returns a `(Sender, Receiver)` pair that shares it, so datagrams leave from the port their replies come back to. A program behind a home router (NAT) needs this: the router lets a reply through only to the port the request left from, and often only from the address it was sent to, so a program that sends on one socket and listens on another never hears its replies. A peer that answers should reply with its own pair's sender to `meta.peer`, the address the request came from.

```python
tx, rx = pulse_wire.bind_pair("0.0.0.0:0")
tx.send_to(send_ns, pulse, b"task", "203.0.113.7:41001")
pulse, envelope, meta = rx.recv()   # the reply, through the router
```

## Channel: messages over shared memory

`Channel` carries messages one way between processes on the same host over Pulse's shared-memory ring and envelope store, with no socket in the path. A channel named `name` is a ring `/name` and an envelope store `/name-e`. The writer stores each message as one envelope and publishes a Data pulse naming it, as the hub runtime broadcasts an envelope; the reader reads the ring's positions in order and fetches the envelope each pulse names. Messages arrive in order and none is dropped: the writer waits while the reader has `min(capacity, store_slots)` messages unread.

- One writer and one reader per channel. For two directions, use two channels. Each end is for one thread at a time.
- A message is a list of byte frames (or one `bytes`-like object). Its framed size, 4 bytes for the frame count and 4 for each frame's length plus the frames, is at most `Channel.MAX_PAYLOAD` bytes, so that its envelope fits the store's 64 KB entry. A larger message raises `EnvelopeTooLarge` (a `ValueError`) and nothing is sent.
- Names are at most 29 bytes with their leading slash, so the store's name fits macOS's 31-byte limit; a longer name raises `ValueError`.
- `send` and `recv` release the GIL while they wait. `send` raises `TimeoutError` if the reader leaves no room within `timeout_s`; `recv` returns `None` when nothing comes within `timeout_s` (`None` waits without limit) and raises `ChannelClosed` (an `EOFError`) once the writer has closed the channel and every message has been read.
- The writer's `close()` (or the end of its `with` block) removes both names; `Channel.create` also removes any left by an earlier run.

```python
import pulse_wire as pw

# Process A: the writer.
with pw.Channel.create("jobs", capacity=4096, store_slots=256) as tx:
    tx.send([b"header", b"body"])

# Process B: the reader. Waits up to 10 s for the writer to create the channel.
with pw.Channel.open("jobs", timeout_s=10.0) as rx:
    frames = rx.recv(timeout_s=1.0)   # [b"header", b"body"], or None
```

Each store entry takes 64 KB of shared memory, so the default 256-entry store is about 16 MB per channel.

A C program can be either end of a channel: the C binding's `pms_channel_*` functions speak the same names, envelopes and framing, one frame per message (see its README). A C reader refuses a message that is not one frame (a list of several, or an empty list), so send it single `bytes` objects.

## Envelopes: the canonical codec

`PulseEnvelope` is the canonical envelope of chapter 3 of the specification, as `pulse_canon::PulseEnvelope` is in Rust: a numeric type, an optional type name, a payload, and a 16-byte content id computed from those three, plus an origin, a monotonic time and flags that the id leaves out. Its bytes are the cross-language wire format, the bytes `pulse-canon` itself writes.

```python
import pulse_wire as pw

env = pw.PulseEnvelope(0x0001, "trace/event", b"payload", origin=bytes(16), flags=pw.EnvelopeFlags.BROADCAST)
wire = env.to_bytes()                      # canonical bytes
same = pw.PulseEnvelope.from_bytes(wire)   # decoded, and its id checked
assert same == env and same.id == env.id   # equality is the id's, as in Rust

batch = pw.PulseEnvelope.nested(0x0040, None, [env, same])
assert batch.children[0].type_name == "trace/event"

pulse = pw.Pulse()
pulse.instruction = pw.Instruction.DATA
pulse.set_envelope_id(env.id)              # the pulse names the envelope
assert pulse.envelope_id() == env.id
```

- The constructor takes `envelope_type` (0 to 65535), `type_name` (a `str` or `None`), `payload` (any bytes-like object), and optionally `origin` (16 bytes), `monotonic_nanos` and `flags` (`EnvelopeFlags` bits). Flags with a reserved bit (4 to 15) and an origin not of 16 bytes raise `ValueError`.
- `PulseEnvelope.nested(...)` takes a sequence of envelopes as the payload in place of bytes. `children` is that list, or `None` for a raw payload; `payload` is the payload's bytes as the id hashes them (for a nested payload, the child count and each child's canonical bytes).
- `PulseEnvelope.from_bytes(b)` refuses, with `EnvelopeDecodeError` (a `ValueError`), bytes that are not exactly one canonical envelope (truncated, malformed, a reserved flag bit, nesting deeper than 32 levels, bytes after the end) and bytes whose id, or any nested child's, is not the id of its content. Every `PulseEnvelope` therefore carries its content's id.
- Envelopes are immutable. Two are equal, and hash alike, when their ids are equal, so two that differ only in origin, time or flags are equal.
- `compute_envelope_id(envelope_type, type_name, payload)` is the id of a raw payload without making the envelope, and `ENVELOPE_ID_DOMAIN_TAG` is the tag the id's hash starts with.

## Type stubs

`pulse_wire.pyi`, beside `Cargo.toml`, declares every class, method, property, function, constant and exception the module exports, for type checkers and editors; `scripts/package/wheel.py` puts it in the wheel with the `py.typed` marker. A test compares it with the built module, name by name, member kind by member kind, and signature by signature, so it cannot fall behind the Rust source.

## Tests

```
pytest tests/
```

Covers loopback round-trips and the type stub against the built module (`test_loopback.py`), buffer-protocol sends (`test_send_buffer.py`), receives into a caller-owned buffer (`test_recv_into.py`), one socket for both directions (`test_bind_pair.py`), shared-memory channels between threads and processes, and with the C binding at the other end in either direction (`test_channel.py`), and the canonical envelope codec: a pure-Python codec and `PulseEnvelope` each held to every fixture in the specification's test vectors and to each other (`test_canonical_codec_cross_language.py`).

The C-binding tests build the C binding's library with cargo and compile its smoke program with `cc` (or `$CC`); they skip when the C binding is not beside this one.

## License

Proprietary. All rights reserved. See `LICENSE` at the repository root.
