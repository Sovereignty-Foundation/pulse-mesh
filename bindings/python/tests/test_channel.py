# SPDX-License-Identifier: LicenseRef-Proprietary
# Copyright (c) 2026 Sovereignty Foundation
"""Tests for pulse_wire.Channel: messages over the shared-memory ring and
envelope store.

Each test uses a fresh, short channel name (the store's name, the channel's
plus "-e", must fit macOS's 31-byte shared-memory name limit).

The tests at the end share a channel with the C binding's end of one, in
another process: the C smoke binary (../c/tests/smoke.c), built against the
C binding here, run as `smoke channel-read <name>` or
`smoke channel-write <name> <hex>...`.
"""

import json
import multiprocessing
import os
import pathlib
import shlex
import struct
import subprocess
import threading
import time

import pytest

import pulse_wire as pw


def fresh_name():
    # "/pwt" + pid + a per-test counter: well under 29 bytes.
    fresh_name.count += 1
    return f"pwt{os.getpid() % 100000}-{fresh_name.count}"


fresh_name.count = 0


def test_round_trip_multi_frame():
    name = fresh_name()
    with pw.Channel.create(name, capacity=64, store_slots=16) as tx:
        with pw.Channel.open(name) as rx:
            assert tx.is_writer and not rx.is_writer
            messages = [
                [b"header", b"", b"\x00\xff" * 100],
                [b"one"],
                [],
                [bytearray(b"bytearray"), memoryview(b"memoryview")],
            ]
            for frames in messages:
                tx.send(frames)
            tx.send(b"single bytes")
            for frames in messages:
                assert rx.recv(timeout_s=1.0) == [bytes(f) for f in frames]
            assert rx.recv(timeout_s=1.0) == [b"single bytes"]
            assert rx.recv(timeout_s=0) is None


def test_typed_buffer_frame():
    import numpy as np

    name = fresh_name()
    with pw.Channel.create(name, capacity=8, store_slots=8) as tx, pw.Channel.open(name) as rx:
        arr = np.arange(10, dtype=np.float32)
        tx.send([memoryview(arr)])
        (frame,) = rx.recv(timeout_s=1.0)
        assert frame == arr.tobytes()


def test_64000_byte_payload():
    name = fresh_name()
    payload = os.urandom(64_000)
    with pw.Channel.create(name, capacity=8, store_slots=8) as tx, pw.Channel.open(name) as rx:
        tx.send([payload])
        assert rx.recv(timeout_s=1.0) == [payload]


def test_max_payload_boundary():
    name = fresh_name()
    # One frame: 4 for the count + 4 for its length.
    biggest = pw.Channel.MAX_PAYLOAD - 8
    with pw.Channel.create(name, capacity=8, store_slots=8) as tx, pw.Channel.open(name) as rx:
        tx.send([b"x" * biggest])
        assert rx.recv(timeout_s=1.0) == [b"x" * biggest]
        with pytest.raises(pw.EnvelopeTooLarge):
            tx.send([b"x" * (biggest + 1)])


def test_too_large_raises_and_sends_nothing():
    name = fresh_name()
    with pw.Channel.create(name, capacity=8, store_slots=8) as tx, pw.Channel.open(name) as rx:
        with pytest.raises(pw.EnvelopeTooLarge, match="64 KB"):
            tx.send([b"x" * 70_000])
        with pytest.raises(ValueError):
            tx.send([b"x" * 40_000, b"y" * 40_000])
        assert tx.pending == 0
        assert rx.recv(timeout_s=0.05) is None
        tx.send([b"after"])
        assert rx.recv(timeout_s=1.0) == [b"after"]


def test_recv_timeout_returns_none():
    name = fresh_name()
    with pw.Channel.create(name) as tx, pw.Channel.open(name) as rx:
        t0 = time.monotonic()
        assert rx.recv(timeout_s=0.2) is None
        elapsed = time.monotonic() - t0
        assert 0.19 <= elapsed < 1.0
        assert tx.pending == 0


def test_name_too_long():
    with pytest.raises(ValueError, match="too long"):
        pw.Channel.create("x" * 29)
    with pytest.raises(ValueError, match="too long"):
        pw.Channel.open("/" + "x" * 29, timeout_s=0)
    # 28 bytes plus the slash: the store's 31-byte name fits.
    name = "c" * 22 + f"{os.getpid() % 1000000:06d}"
    with pw.Channel.create(name, capacity=4, store_slots=1) as tx:
        assert tx.name == "/" + name


def test_open_missing_times_out():
    with pytest.raises(TimeoutError):
        pw.Channel.open(fresh_name(), timeout_s=0.05)


def test_wrong_end_and_closed():
    name = fresh_name()
    tx = pw.Channel.create(name, capacity=8, store_slots=8)
    rx = pw.Channel.open(name)
    with pytest.raises(ValueError):
        rx.send([b"no"])
    with pytest.raises(ValueError):
        tx.recv(timeout_s=0)
    rx.close()
    rx.close()
    assert rx.closed
    with pytest.raises(ValueError):
        rx.recv(timeout_s=0)
    tx.close()


def test_writer_close_drains_then_raises():
    name = fresh_name()
    tx = pw.Channel.create(name, capacity=8, store_slots=8)
    rx = pw.Channel.open(name)
    tx.send([b"last"])
    tx.close()
    assert rx.recv(timeout_s=1.0) == [b"last"]
    with pytest.raises(pw.ChannelClosed):
        rx.recv(timeout_s=1.0)
    with pytest.raises(EOFError):
        rx.recv()
    rx.close()
    # The writer's close removed the names.
    with pytest.raises(TimeoutError):
        pw.Channel.open(name, timeout_s=0.05)


def test_send_stalls_without_reader():
    name = fresh_name()
    with pw.Channel.create(name, capacity=4, store_slots=4) as tx:
        for i in range(4):
            tx.send([bytes([i])], timeout_s=0.1)
        assert tx.pending == 4
        with pytest.raises(TimeoutError):
            tx.send([b"full"], timeout_s=0.05)


def test_backpressure_slow_reader():
    name = fresh_name()
    n = 100
    got = []
    with pw.Channel.create(name, capacity=8, store_slots=8) as tx, pw.Channel.open(name) as rx:

        def read():
            for _ in range(n):
                time.sleep(0.002)
                got.append(rx.recv(timeout_s=5.0))

        reader = threading.Thread(target=read)
        reader.start()
        for i in range(n):
            tx.send([struct.pack("<I", i), b"x" * (i * 300)], timeout_s=5.0)
            assert tx.pending <= 8
        reader.join(timeout=30)
    assert len(got) == n
    for i, frames in enumerate(got):
        assert frames == [struct.pack("<I", i), b"x" * (i * 300)]


def test_store_window_smaller_than_ring():
    # A ring bigger than the store: the store's slots bound the unread
    # messages, so no envelope is overwritten before it is read.
    name = fresh_name()
    with pw.Channel.create(name, capacity=64, store_slots=4) as tx, pw.Channel.open(name) as rx:
        for i in range(4):
            tx.send([bytes([i])], timeout_s=0.1)
        with pytest.raises(TimeoutError):
            tx.send([b"over"], timeout_s=0.05)
        for i in range(4):
            assert rx.recv(timeout_s=1.0) == [bytes([i])]
        tx.send([b"room"], timeout_s=0.1)
        assert rx.recv(timeout_s=1.0) == [b"room"]


def test_pulse_store_cursor_getter():
    p = pw.Pulse()
    assert p.store_cursor is None
    p.instruction = pw.Instruction.DATA
    assert p.store_cursor is None


def _reader_process(name, n, out):
    rx = pw.Channel.open(name, timeout_s=10.0)
    expected = 0
    ok = True
    for _ in range(n):
        frames = rx.recv(timeout_s=10.0)
        if frames is None or len(frames) != 2:
            ok = False
            break
        (seq,) = struct.unpack("<Q", frames[0])
        if seq != expected or frames[1] != b"m" * (seq % 512):
            ok = False
            break
        expected += 1
    out.put((ok, expected))
    rx.close()


def test_two_processes_in_order():
    name = fresh_name()
    n = 10_000
    ctx = multiprocessing.get_context("spawn")
    out = ctx.Queue()
    tx = pw.Channel.create(name, capacity=256, store_slots=64)
    proc = ctx.Process(target=_reader_process, args=(name, n, out))
    proc.start()
    try:
        for seq in range(n):
            tx.send([struct.pack("<Q", seq), b"m" * (seq % 512)], timeout_s=30.0)
        ok, count = out.get(timeout=60)
        proc.join(timeout=30)
    finally:
        if proc.is_alive():
            proc.kill()
        tx.close()
    assert ok and count == n, (ok, count)
    assert proc.exitcode == 0


# ─── with the C binding ───────────────────────────────────────────────────

C_BINDING = pathlib.Path(__file__).resolve().parents[2] / "c"


def _run(cmd, **kwargs):
    done = subprocess.run(cmd, capture_output=True, text=True, **kwargs)
    if done.returncode != 0:
        pytest.fail(f"{shlex.join(map(str, cmd))} exited {done.returncode}:\n{done.stdout}{done.stderr}")
    return done.stdout


@pytest.fixture(scope="module")
def c_smoke(tmp_path_factory):
    """The C smoke binary, built against a debug build of the C binding
    with the flags tests/run.sh there uses. A tree without the C binding
    beside this one (a wheel built elsewhere) skips."""
    manifest = C_BINDING / "Cargo.toml"
    if not manifest.is_file():
        pytest.skip("the C binding is not beside this one")
    _run(["cargo", "build", "--locked", "--manifest-path", manifest])
    metadata = json.loads(
        _run(["cargo", "metadata", "--format-version", "1", "--no-deps", "--manifest-path", manifest])
    )
    library = pathlib.Path(metadata["target_directory"]) / "debug" / "libpulse_wire.a"
    smoke = tmp_path_factory.mktemp("c") / "smoke"
    cc = shlex.split(os.environ.get("CC", "cc"))
    _run(
        [*cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", C_BINDING / "include",
         C_BINDING / "tests" / "smoke.c", library, "-o", smoke, "-lpthread", "-ldl"]
    )
    return smoke


def _messages():
    # The empty message, the largest, and many more than the 16-message
    # window, most longer than the C reader's first 16-byte buffer.
    return [
        b"",
        b"hello across languages",
        bytes(range(256)),
        os.urandom(pw.Channel.MAX_PAYLOAD - 8),
        *(struct.pack("<I", i) * (i % 97) for i in range(300)),
    ]


def test_python_writer_c_reader(c_smoke, tmp_path):
    name = fresh_name()
    messages = _messages()
    out = tmp_path / "read.hex"
    with pw.Channel.create(name, capacity=64, store_slots=16) as tx, open(out, "wb") as sink:
        reader = subprocess.Popen([c_smoke, "channel-read", name], stdout=sink, stderr=subprocess.PIPE)
        try:
            for message in messages:
                tx.send(message, timeout_s=10.0)
            # Closed only once read, so the reader attaches before the close
            # removes the names; then it drains and sees the channel closed.
            deadline = time.monotonic() + 10.0
            while tx.pending and time.monotonic() < deadline:
                time.sleep(0.001)
            assert tx.pending == 0
        except BaseException:
            reader.kill()
            raise
    _, err = reader.communicate(timeout=30)
    assert reader.returncode == 0, err.decode()
    lines = out.read_text().split("\n")
    assert lines.pop() == ""
    assert [bytes.fromhex(line) for line in lines] == messages


def test_c_writer_python_reader(c_smoke):
    name = fresh_name()
    # Less than the largest message: a hex argument of one stays under
    # Linux's 128 KB limit for a single argument.
    messages = [m for m in _messages() if len(m) <= 50_000] + [b"z" * 50_000]
    writer = subprocess.Popen(
        [c_smoke, "channel-write", name, *(m.hex() for m in messages)], stderr=subprocess.PIPE
    )
    got = []
    try:
        with pw.Channel.open(name, timeout_s=10.0) as rx:
            for _ in messages:
                got.append(rx.recv(timeout_s=10.0))
            with pytest.raises(pw.ChannelClosed):
                rx.recv(timeout_s=10.0)
    finally:
        try:
            _, err = writer.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            writer.kill()
            raise
    assert writer.returncode == 0, err.decode()
    assert got == [[m] for m in messages]


def test_c_reader_refuses_a_multi_frame_message(c_smoke, tmp_path):
    """The C binding receives one-frame messages; a Python list of two
    frames is consumed and reported, not delivered cut or joined."""
    name = fresh_name()
    out = tmp_path / "read.hex"
    with pw.Channel.create(name, capacity=8, store_slots=8) as tx, open(out, "wb") as sink:
        reader = subprocess.Popen([c_smoke, "channel-read", name], stdout=sink, stderr=subprocess.PIPE)
        try:
            tx.send(b"one", timeout_s=10.0)
            tx.send([b"two", b"frames"], timeout_s=10.0)
            _, err = reader.communicate(timeout=30)
        except BaseException:
            reader.kill()
            raise
    assert reader.returncode == 1
    assert "has 2 frames" in err.decode()
    assert out.read_text() == b"one".hex() + "\n"
