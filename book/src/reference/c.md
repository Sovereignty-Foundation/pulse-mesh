# C bindings

<p class="pm-kind"><b>Reference</b> · the C binding: what it wraps, how to build it and where to read its API</p>

The C binding lives at `bindings/c/` — a `cdylib`/`staticlib` FFI layer over `pulse-wire-udp` (see [Language bindings](bindings.md)). `build.rs` runs `cbindgen` to regenerate the header from the Rust source, which is the actual API reference:

```
cd bindings/c
cargo build --release
cat include/pulse_wire.h
```

The header documents `pms_sender_bind`/`pms_receiver_bind` (caller-owned handles), `pms_sender_send` / `pms_sender_send_to` / `pms_receiver_recv_into`, the matching `pms_*_destroy` calls, and the `pms_status` error enum plus thread-local `pms_last_error()`. `tests/smoke.c` and `tests/run.sh` show a minimal working call sequence end to end.
