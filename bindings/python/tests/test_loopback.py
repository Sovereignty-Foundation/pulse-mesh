# SPDX-License-Identifier: LicenseRef-Proprietary
# Copyright (c) 2026 Sovereignty Foundation
"""Loopback round-trip tests for pulse_wire Python bindings.

Runs sender + receiver on 127.0.0.1, exchanges N pulses with envelopes,
and asserts every field round-trips byte-exact.
"""

import threading
import time

import pulse_wire as pw


def test_module_constants():
    assert pw.PULSE_WIRE_SIZE == 128
    assert pw.MAX_ENVELOPE > 0
    assert isinstance(pw.__version__, str)


def test_pulse_zero_init():
    p = pw.Pulse()
    assert p.instruction == pw.Instruction.NULL
    assert p.scope == 0
    assert p.monotonic_nanos == 0
    assert p.chain_step == 0
    assert p.origin_id == b"\x00" * 16
    assert p.envelope_ref == b"\x00" * 16
    assert not p.has_envelope()


def test_pulse_repr_and_hex_getters():
    """Friendly repr + hex-encoded getters added in the housekeeping fixup."""
    p = pw.Pulse()
    p.instruction = pw.Instruction.DATA
    p.monotonic_nanos = 12345
    p.origin_id = bytes(range(16))
    p.envelope_ref = bytes(range(15, -1, -1))

    # repr / str are user-facing — must mention key fields
    r = repr(p)
    assert "Pulse" in r
    assert "instruction=DATA" in r
    assert "0x0010" in r
    assert "12345" in r
    assert str(p) == r

    # hex getters yield 32-char strings
    assert len(p.origin_id_hex) == 32
    assert len(p.envelope_ref_hex) == 32
    assert p.origin_id_hex == "000102030405060708090a0b0c0d0e0f"
    assert p.envelope_ref_hex == "0f0e0d0c0b0a09080706050403020100"


def test_pulse_field_round_trip():
    p = pw.Pulse()
    p.instruction = pw.Instruction.DATA
    p.scope = 0xDEADBEEF
    p.monotonic_nanos = 12345678901234
    p.chain_step = 99
    p.origin_id = b"\x11" * 16
    assert p.instruction == pw.Instruction.DATA
    assert p.scope == 0xDEADBEEF
    assert p.monotonic_nanos == 12345678901234
    assert p.chain_step == 99
    assert p.origin_id == b"\x11" * 16


def test_pulse_bytes_round_trip():
    p = pw.Pulse()
    p.instruction = pw.Instruction.DATA
    p.scope = 7
    p.monotonic_nanos = 42
    p.origin_id = bytes(range(16))
    raw = p.as_bytes()
    assert len(raw) == 128
    p2 = pw.Pulse.from_bytes(raw)
    assert p2.instruction == p.instruction
    assert p2.scope == p.scope
    assert p2.monotonic_nanos == p.monotonic_nanos
    assert p2.origin_id == p.origin_id
    assert p2.as_bytes() == raw


def test_pulse_origin_id_wrong_length_rejected():
    p = pw.Pulse()
    try:
        p.origin_id = b"\x00" * 8
    except ValueError:
        return
    raise AssertionError("expected ValueError for 8-byte origin_id")


def test_pulse_from_bytes_wrong_length_rejected():
    try:
        pw.Pulse.from_bytes(b"\x00" * 64)
    except ValueError:
        return
    raise AssertionError("expected ValueError for 64-byte input")


def test_pulse_envelope_id_round_trip():
    p = pw.Pulse()
    assert p.envelope_id() is None
    envelope = pw.PulseEnvelope(0x0001, None, b"BBBB")
    p.set_envelope_id(envelope.id)
    assert p.envelope_id() == envelope.id
    assert p.envelope_ref == envelope.id
    assert p.has_envelope()
    # The instruction is the caller's to set.
    assert p.instruction == pw.Instruction.NULL
    p.set_envelope_id(bytearray(16))
    assert p.envelope_id() is None and not p.has_envelope()
    try:
        p.set_envelope_id(b"\x01" * 15)
    except ValueError:
        return
    raise AssertionError("expected ValueError for a 15-byte envelope id")


def test_loopback_round_trip():
    """Send N pulses + envelopes through 127.0.0.1, read them back."""
    recv = pw.Receiver.bind("127.0.0.1:0")
    recv.set_read_timeout_ms(2000)
    recv_addr = recv.local_addr()

    sender = pw.Sender.bind("127.0.0.1:0")
    sender.connect(recv_addr)

    n = 10
    sent = []
    for i in range(n):
        p = pw.Pulse()
        p.instruction = pw.Instruction.DATA
        p.scope = i
        p.monotonic_nanos = time.monotonic_ns()
        envelope = f"hello-{i}".encode()
        send_ns = p.monotonic_nanos
        seq = sender.send(send_ns, p, envelope)
        sent.append((seq, p.scope, p.monotonic_nanos, envelope))

    received = []
    for _ in range(n):
        pulse, envelope, meta = recv.recv()
        received.append((meta.seq, pulse.scope, pulse.monotonic_nanos, envelope))

    assert sent == received, f"mismatch:\nsent={sent}\nreceived={received}"


def test_recv_timeout_raises():
    recv = pw.Receiver.bind("127.0.0.1:0")
    recv.set_read_timeout_ms(50)
    try:
        recv.recv()
    except TimeoutError:
        return
    raise AssertionError("expected TimeoutError")


def test_threaded_sender_receiver():
    """Receiver in a background thread, main thread sends — confirms
    GIL is released around recv() so the producer can run concurrently.
    """
    recv = pw.Receiver.bind("127.0.0.1:0")
    recv.set_read_timeout_ms(2000)
    recv_addr = recv.local_addr()

    n = 50
    received = []

    def consumer():
        for _ in range(n):
            _pulse, env, meta = recv.recv()
            received.append((meta.seq, env))

    t = threading.Thread(target=consumer, daemon=True)
    t.start()

    sender = pw.Sender.bind("127.0.0.1:0")
    sender.connect(recv_addr)
    for i in range(n):
        p = pw.Pulse()
        p.instruction = pw.Instruction.DATA
        p.scope = i
        sender.send(time.monotonic_ns(), p, f"msg-{i}".encode())

    t.join(timeout=5)
    assert not t.is_alive(), "consumer thread did not finish in time"
    assert len(received) == n
    seqs = [s for s, _ in received]
    assert seqs == list(range(n)), f"out of order: {seqs}"
