# SPDX-License-Identifier: LicenseRef-Proprietary
# Copyright (c) 2026 Sovereignty Foundation
"""Zero-allocation `send_buffer` tests for the pulse_wire Python bindings.

Covers the explicit buffer-protocol send path: bytes, bytearray, memoryview,
NumPy uint8 ndarray, plus error paths (non-contiguous, oversize).
"""

import time

import pulse_wire as pw

try:
    import numpy as np
    HAVE_NUMPY = True
except ImportError:
    HAVE_NUMPY = False


def _spin_up_pair():
    recv = pw.Receiver.bind("127.0.0.1:0")
    recv.set_read_timeout_ms(2000)
    sender = pw.Sender.bind("127.0.0.1:0")
    sender.connect(recv.local_addr())
    return sender, recv


def _make_pulse(scope=0):
    p = pw.Pulse()
    p.instruction = pw.Instruction.DATA
    p.scope = scope
    p.monotonic_nanos = time.monotonic_ns()
    return p


def test_send_buffer_with_bytes():
    sender, recv = _spin_up_pair()
    payload = b"plain bytes work"
    seq = sender.send_buffer(time.monotonic_ns(), _make_pulse(scope=1), payload)
    assert seq == 0
    _pulse, env, _meta = recv.recv()
    assert env == payload


def test_send_buffer_with_bytearray():
    sender, recv = _spin_up_pair()
    payload = bytearray(b"bytearray works too")
    sender.send_buffer(time.monotonic_ns(), _make_pulse(), payload)
    _pulse, env, _meta = recv.recv()
    assert env == bytes(payload)


def test_send_buffer_with_memoryview():
    sender, recv = _spin_up_pair()
    backing = bytearray(b"memoryview slice")
    sender.send_buffer(time.monotonic_ns(), _make_pulse(), memoryview(backing))
    _pulse, env, _meta = recv.recv()
    assert env == bytes(backing)


def test_send_buffer_zero_length():
    sender, recv = _spin_up_pair()
    sender.send_buffer(time.monotonic_ns(), _make_pulse(scope=42), b"")
    _pulse, env, _meta = recv.recv()
    assert env == b""


def test_send_buffer_with_numpy_uint8():
    if not HAVE_NUMPY:
        print("  (skipped: numpy not installed)")
        return
    sender, recv = _spin_up_pair()
    arr = np.arange(256, dtype=np.uint8)
    sender.send_buffer(time.monotonic_ns(), _make_pulse(scope=3), arr)
    _pulse, env, _meta = recv.recv()
    assert env == bytes(arr)


def test_send_buffer_round_trip_send_to_recv_into_numpy():
    """Full zero-allocation round trip: NumPy send -> NumPy recv_into."""
    if not HAVE_NUMPY:
        print("  (skipped: numpy not installed)")
        return
    sender, recv = _spin_up_pair()

    out = np.frombuffer(b"\xde\xad\xbe\xef" * 64, dtype=np.uint8)  # 256 B
    sender.send_buffer(time.monotonic_ns(), _make_pulse(scope=7), out)

    inb = np.zeros(pw.MAX_ENVELOPE, dtype=np.uint8)
    pulse, n, meta = recv.recv_into(inb)

    assert n == len(out)
    assert pulse.scope == 7
    assert (inb[:n] == out).all()
    assert meta.seq == 0


def test_send_buffer_too_large_rejected():
    sender, _recv = _spin_up_pair()
    # Build an oversized bytearray (avoids np.zeros if numpy missing)
    too_big = bytearray(pw.MAX_ENVELOPE + 1)
    try:
        sender.send_buffer(time.monotonic_ns(), _make_pulse(), too_big)
    except ValueError:
        return
    raise AssertionError("expected ValueError for oversize envelope")


def test_send_buffer_non_contiguous_numpy_rejected():
    if not HAVE_NUMPY:
        print("  (skipped: numpy not installed)")
        return
    sender, _recv = _spin_up_pair()
    arr = np.zeros((4, 32), dtype=np.uint8)
    sliced = arr[:, ::2]   # strided
    assert not sliced.flags["C_CONTIGUOUS"]
    try:
        sender.send_buffer(time.monotonic_ns(), _make_pulse(), sliced)
    except (BufferError, TypeError, ValueError):
        return
    raise AssertionError("expected error for non-contiguous buffer")


def test_send_buffer_to_overrides_destination():
    """send_buffer_to() with an explicit dest sends without a connect()."""
    recv_a = pw.Receiver.bind("127.0.0.1:0")
    recv_a.set_read_timeout_ms(2000)
    recv_b = pw.Receiver.bind("127.0.0.1:0")
    recv_b.set_read_timeout_ms(2000)

    sender = pw.Sender.bind("127.0.0.1:0")
    # No connect() — rely on per-call destination.
    sender.send_buffer_to(
        time.monotonic_ns(), _make_pulse(scope=1), b"to-A", recv_a.local_addr()
    )
    sender.send_buffer_to(
        time.monotonic_ns(), _make_pulse(scope=2), b"to-B", recv_b.local_addr()
    )

    _, env_a, _ = recv_a.recv()
    _, env_b, _ = recv_b.recv()
    assert env_a == b"to-A"
    assert env_b == b"to-B"


if __name__ == "__main__":
    tests = [
        test_send_buffer_with_bytes,
        test_send_buffer_with_bytearray,
        test_send_buffer_with_memoryview,
        test_send_buffer_zero_length,
        test_send_buffer_with_numpy_uint8,
        test_send_buffer_round_trip_send_to_recv_into_numpy,
        test_send_buffer_too_large_rejected,
        test_send_buffer_non_contiguous_numpy_rejected,
        test_send_buffer_to_overrides_destination,
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
