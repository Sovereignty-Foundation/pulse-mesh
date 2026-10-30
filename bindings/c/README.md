# pulse-wire-c — the C binding

A C FFI layer over the [Pulse Mesh](https://pulse-mesh.net/) `pulse-wire-udp` transport and the shared-memory channel, built as `libpulse_wire.a` (static) and `libpulse_wire.dylib` / `libpulse_wire.so` (shared). It is also the foundation for bindings from Java (JNI), Go (cgo) and C++.

> Part of the Pulse Mesh workspace — see the [book](https://pulse-mesh.net/docs/) for architecture and the [C bindings reference](https://pulse-mesh.net/docs/reference/c.html).

## Build

```
cargo build --release
```

`build.rs` runs cbindgen on a build after `src/lib.rs` or `cbindgen.toml` changes and writes `include/pulse_wire.h`, the API reference: every function's contract, its status codes and its safety rules are in its comment there. The header is kept in the tree so a C consumer needs no Rust toolchain, and the gate fails when it is not what cbindgen generates. Link the static library with `-lpthread -ldl`, as `tests/run.sh` does.

## Conventions

- Every fallible function returns a `pms_status`: `PMS_OK` (0) or an error code, with a message from `pms_last_error()`, thread-local and valid until the next `pms_*` call on the thread.
- Handles (`pms_sender*`, `pms_receiver*`, `pms_channel*`) are caller-owned; release each with its `pms_*_destroy` or `pms_channel_close`. Each is for one thread at a time; distinct handles may be used on distinct threads.
- `pms_pulse` is a 128-byte value type the caller allocates; read and write it through the `pms_pulse_*` accessors. Buffers are the caller's; the library never frees them.

## Pulses and UDP

`pms_sender_bind`, `pms_sender_connect`, `pms_sender_send` and `pms_sender_send_to` send framed datagrams of a Pulse and an envelope of at most `PMS_MAX_ENVELOPE` (1315) bytes; `pms_receiver_bind`, `pms_receiver_set_read_timeout_ms` and `pms_receiver_recv_into` receive them into a caller's buffer. The `pms_pulse_get_*` / `pms_pulse_set_*` accessors cover the instruction, scope, time, chain step, `origin_id` and `envelope_ref`, the 16-byte content id of the envelope the Pulse names (all zeros names none).

## One socket for sending and receiving

`pms_bind_pair(local_addr, &sender, &receiver)` binds one UDP socket and returns a sender and a receiver that share it, so datagrams leave from the port their replies come back to. A program behind a home router (NAT) needs this: the router lets a reply through only to the port the request left from, and often only from the address it was sent to. A peer that answers replies with its own pair's sender to the `out_peer` address its receiver reported. The two handles are released separately, in either order.

```c
pms_sender* tx = NULL;
pms_receiver* rx = NULL;
if (pms_bind_pair("0.0.0.0:0", &tx, &rx) != PMS_OK) {
    fprintf(stderr, "%s\n", pms_last_error());
}
pms_sender_send_to(tx, send_ns, &pulse, task, task_len, "203.0.113.7:41001", NULL);
pms_receiver_recv_into(rx, buf, sizeof buf, &pulse, &len, NULL, NULL, peer, sizeof peer);
pms_sender_destroy(tx);
pms_receiver_destroy(rx);
```

## Channel: messages over shared memory

A channel carries messages one way between processes on the same host over Pulse's shared-memory ring and envelope store, with no socket in the path. It is the Python binding's `Channel`, with the same names, envelopes and framing, so either end may be a Python program. A channel named `name` is a ring `/name` and an envelope store `/name-e`; messages arrive in order and none is dropped.

- `pms_channel_create(name, capacity, store_slots, &ch)` makes the writer end: a ring of `capacity` slots and a store of `store_slots` entries of 64 KB each. Objects an earlier run left under the names are removed first. The writer waits while the reader has `min(capacity, store_slots)` messages unread.
- `pms_channel_open(name, &ch)` attaches the reader end, retrying for up to 10 seconds while the writer has not created it (`PMS_ERR_TIMEOUT` after that).
- `pms_channel_send(ch, data, len)` sends one message of one frame, `len` bytes, at most `pms_channel_max_len()` (just under 64 KB; `PMS_ERR_ENVELOPE_TOO_LARGE` beyond). It waits up to 5 seconds for the reader to leave room, then returns `PMS_ERR_TIMEOUT` with nothing sent. The 10- and 5-second waits are the Python binding's defaults.
- `pms_channel_recv(ch, buf, cap, &len, timeout_ms)` receives the next message, waiting up to `timeout_ms` (0: return at once; `PMS_CHANNEL_WAIT_FOREVER`: no limit). It returns `PMS_ERR_TIMEOUT` when nothing came in time, `PMS_ERR_CLOSED` once the writer has closed the channel and every message has been read, and `PMS_ERR_BUFFER_TOO_SMALL` when the message is longer than `cap`: then `len` is its length and it stays unread, so the next call with a buffer that large receives it. A message of more or fewer than one frame, which only a Python writer sends (a list of several frames, or an empty list), is consumed and reported as `PMS_ERR_DECODE`.
- `pms_channel_pending(ch)` is the number of messages sent and not yet read.
- `pms_channel_close(ch)` releases either end. The writer's close removes both names; a reader still attached reads what was sent and then gets `PMS_ERR_CLOSED`.
- One writer and one reader per channel; for two directions, use two channels. Names are at most 29 bytes with their leading slash, so the store's name fits macOS's 31-byte limit.

```c
/* Process A: the writer. */
pms_channel* tx = NULL;
pms_channel_create("jobs", 4096, 256, &tx);
pms_channel_send(tx, (const unsigned char*)"job 1", 5);
pms_channel_close(tx);

/* Process B: the reader. */
pms_channel* rx = NULL;
pms_channel_open("jobs", &rx);
unsigned char buf[65536];
size_t len = 0;
while (pms_channel_recv(rx, buf, sizeof buf, &len, 1000) == PMS_OK) {
    /* buf[0..len] is one message */
}
pms_channel_close(rx);
```

A writer that closes before its reader has attached removes the channel from under it; wait until `pms_channel_pending` is 0 before closing when the reader may start late.

## Tests

```
tests/run.sh
```

Builds the release library and runs `tests/smoke.c`: Pulse field round-trips (`envelope_ref` included), a UDP loopback round-trip and its error paths, a `pms_bind_pair` request and reply on loopback, a channel in one process (order, the size limit, a too-small buffer that leaves the message unread, timeouts, the wrong end, the writer's close), and a channel between two processes, the smoke binary running itself as the reader. With arguments the binary is one end of a channel (`smoke channel-read <name>`, `smoke channel-write <name> <hex>...`); the Python binding's tests run it that way against a Python writer and a Python reader.
