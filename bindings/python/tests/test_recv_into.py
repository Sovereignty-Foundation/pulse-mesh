# SPDX-License-Identifier: LicenseRef-Proprietary
# Copyright (c) 2026 Sovereignty Foundation
"""Zero-allocation `recv_into` tests for the pulse_wire Python bindings.

Covers writable buffer-protocol acceptors: bytearray, NumPy uint8 ndarray,
writable memoryview. Plus error paths (read-only buffer, undersized buffer).
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


def _send_one(sender, scope=7, payload=b"hello"):
    p = pw.Pulse()
    p.instruction = pw.Instruction.DATA
    p.scope = scope
    p.monotonic_nanos = time.monotonic_ns()
    sender.send(time.monotonic_ns(), p, payload)


def test_recv_into_bytearray():
    sender, recv = _spin_up_pair()
    payload = b"recv_into via bytearray"
    _send_one(sender, scope=11, payload=payload)

    buf = bytearray(pw.MAX_ENVELOPE)
    pulse, n, meta = recv.recv_into(buf)

    assert n == len(payload)
    assert bytes(buf[:n]) == payload
    assert pulse.scope == 11
    assert meta.seq == 0


def test_recv_into_reuse_buffer_no_realloc():
    """Pre-allocate once, recv N packets — buffer identity stays constant."""
    sender, recv = _spin_up_pair()
    buf = bytearray(pw.MAX_ENVELOPE)
    buf_id_before = id(buf)

    n_msgs = 20
    for i in range(n_msgs):
        _send_one(sender, scope=i, payload=f"msg-{i}".encode())

    received = []
    for _ in range(n_msgs):
        _pulse, n, meta = recv.recv_into(buf)
        received.append((meta.seq, bytes(buf[:n])))

    assert id(buf) == buf_id_before, "buffer identity changed"
    assert received == [(i, f"msg-{i}".encode()) for i in range(n_msgs)]


def test_recv_into_buffer_too_small_raises():
    sender, recv = _spin_up_pair()
    _send_one(sender, payload=b"x" * 200)

    small = bytearray(50)
    try:
        recv.recv_into(small)
    except ValueError:
        return
    raise AssertionError("expected ValueError for undersized buffer")


def test_recv_into_readonly_bytes_rejected():
    _, recv = _spin_up_pair()
    immutable = b"\x00" * pw.MAX_ENVELOPE
    try:
        recv.recv_into(immutable)
    except (BufferError, TypeError):
        return
    raise AssertionError("expected BufferError/TypeError for read-only bytes")


def test_recv_into_memoryview():
    sender, recv = _spin_up_pair()
    payload = b"via memoryview"
    _send_one(sender, scope=33, payload=payload)

    backing = bytearray(pw.MAX_ENVELOPE)
    view = memoryview(backing)
    _pulse, n, _meta = recv.recv_into(view)

    assert n == len(payload)
    assert bytes(backing[:n]) == payload, "writes did not land in the backing array"


def test_recv_into_numpy_zero_copy():
    if not HAVE_NUMPY:
        print("  (skipped: numpy not installed)")
        return
    sender, recv = _spin_up_pair()
    payload = b"\x01\x02\x03\x04\x05\x06\x07\x08" * 16  # 128 bytes
    _send_one(sender, scope=99, payload=payload)

    arr = np.zeros(pw.MAX_ENVELOPE, dtype=np.uint8)
    arr_data_ptr = arr.ctypes.data
    pulse, n, _meta = recv.recv_into(arr)

    assert n == len(payload)
    assert pulse.scope == 99
    assert bytes(arr[:n]) == payload
    # Confirm zero-copy: the ndarray's underlying buffer is the same one we
    # allocated; recv_into wrote into it, did not replace it.
    assert arr.ctypes.data == arr_data_ptr, "ndarray was reallocated"

    # And np.frombuffer over the slice is a true zero-copy view
    view = arr[:n]
    assert view.base is arr or view.base is arr.base, "expected ndarray view"


def test_recv_into_numpy_wrong_dtype_rejected():
    if not HAVE_NUMPY:
        print("  (skipped: numpy not installed)")
        return
    _, recv = _spin_up_pair()
    arr_i32 = np.zeros(pw.MAX_ENVELOPE // 4, dtype=np.int32)
    try:
        recv.recv_into(arr_i32)
    except (BufferError, TypeError):
        return
    raise AssertionError("expected BufferError/TypeError for non-u8 dtype")


def test_recv_into_numpy_non_contiguous_rejected():
    if not HAVE_NUMPY:
        print("  (skipped: numpy not installed)")
        return
    _, recv = _spin_up_pair()
    arr = np.zeros((4, pw.MAX_ENVELOPE), dtype=np.uint8)
    sliced = arr[:, ::2]  # strided, not C-contiguous
    assert not sliced.flags["C_CONTIGUOUS"]
    try:
        recv.recv_into(sliced)
    except (BufferError, TypeError, ValueError):
        return
    raise AssertionError("expected error for non-contiguous buffer")


if __name__ == "__main__":
    tests = [
        test_recv_into_bytearray,
        test_recv_into_reuse_buffer_no_realloc,
        test_recv_into_buffer_too_small_raises,
        test_recv_into_readonly_bytes_rejected,
        test_recv_into_memoryview,
        test_recv_into_numpy_zero_copy,
        test_recv_into_numpy_wrong_dtype_rejected,
        test_recv_into_numpy_non_contiguous_rejected,
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
