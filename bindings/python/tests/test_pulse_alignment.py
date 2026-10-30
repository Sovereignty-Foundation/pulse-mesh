# SPDX-License-Identifier: LicenseRef-Proprietary
# Copyright (c) 2026 Sovereignty Foundation
"""Every Pulse the binding hands out is safe to use, wherever Python puts it.

The Rust `Pulse` is `align(64)`. Stored inside the Python object, which
CPython aligns to 16 bytes, it was misaligned: a debug build of the
extension (what `maturin develop` builds) aborted with "misaligned pointer
dereference" at the first `Pulse()`, and a release build read and wrote
misaligned memory. These tests make Pulses through every path the binding
has (the constructor, `from_bytes`, `recv` and `recv_into`), many at once
so that they sit at many addresses, and read and write every field of each.
Run against a debug build, they abort on the old storage. The static
assertion beside `PyPulse` in `src/lib.rs` refuses the old storage in any
build.
"""

import time

import pulse_wire as pw

# Enough live objects that the allocator puts them at every offset its
# alignment allows.
COUNT = 512


def _exercise(p, i):
    """Write every field of `p` from `i`, then read each back."""
    p.instruction = pw.Instruction.DATA
    p.scope = i
    p.monotonic_nanos = 1_000_000 + i
    p.chain_step = 2_000_000 + i
    p.origin_id = bytes([i % 256]) * 16
    p.envelope_ref = bytes([1 + i % 255]) * 16  # never all zeros
    assert p.instruction == pw.Instruction.DATA
    assert p.scope == i
    assert p.monotonic_nanos == 1_000_000 + i
    assert p.chain_step == 2_000_000 + i
    assert p.origin_id == bytes([i % 256]) * 16
    assert p.envelope_ref == bytes([1 + i % 255]) * 16
    assert p.has_envelope()
    assert p.origin_id_hex == f"{i % 256:02x}" * 16
    assert "Pulse" in repr(p)
    raw = p.as_bytes()
    assert len(raw) == pw.PULSE_WIRE_SIZE
    assert pw.Pulse.from_bytes(raw).as_bytes() == raw


def test_constructed_pulses_are_usable():
    pulses = [pw.Pulse() for _ in range(COUNT)]
    for i, p in enumerate(pulses):
        assert p.scope == 0 and p.origin_id == b"\x00" * 16
        _exercise(p, i)
    # Nothing written to one Pulse reached another.
    for i, p in enumerate(pulses):
        assert p.scope == i


def test_pulses_from_bytes_are_usable():
    template = pw.Pulse()
    pulses = []
    for i in range(COUNT):
        template.scope = i
        pulses.append(pw.Pulse.from_bytes(template.as_bytes()))
    for i, p in enumerate(pulses):
        assert p.scope == i
        _exercise(p, i)


def test_received_pulses_are_usable():
    recv = pw.Receiver.bind("127.0.0.1:0")
    recv.set_read_timeout_ms(2000)
    sender = pw.Sender.bind("127.0.0.1:0")
    sender.connect(recv.local_addr())
    buf = bytearray(pw.MAX_ENVELOPE)
    got = []
    # Few enough per round that the socket's receive buffer holds them all.
    for round_start in range(0, COUNT, 32):
        for i in range(round_start, round_start + 32):
            p = pw.Pulse()
            p.scope = i
            sender.send(time.monotonic_ns(), p, b"x")
        for i in range(round_start, round_start + 32):
            if i % 2:
                pulse, _env, _meta = recv.recv()
            else:
                pulse, _n, _meta = recv.recv_into(buf)
            got.append(pulse)
    for i, p in enumerate(got):
        assert p.scope == i
        _exercise(p, i)


if __name__ == "__main__":
    tests = [
        test_constructed_pulses_are_usable,
        test_pulses_from_bytes_are_usable,
        test_received_pulses_are_usable,
    ]
    failed = 0
    for fn in tests:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    if failed:
        raise SystemExit(1)
