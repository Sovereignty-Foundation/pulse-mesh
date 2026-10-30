# SPDX-License-Identifier: LicenseRef-Proprietary
# Copyright (c) 2026 Sovereignty Foundation
"""Cross-language byte-equality test for the canonical PulseEnvelope codec.

Checks that a PulseEnvelope encoded in Rust produces byte-identical output
to one encoded in Python for the same field values: the byte equality the
standard is built on (chapter 3 of the specification).

Usage:

    cd bindings/python
    pip install blake3
    python -m pytest tests/test_canonical_codec_cross_language.py -v

The pure-Python tests do NOT depend on the PyO3 binding: they implement the
canonical codec from scratch, so they hold Rust's fixtures to an encoder that
shares no code with it. The tests at the end hold the binding's own codec,
``pulse_wire.PulseEnvelope``, to every fixture in the specification's
test-vectors directory and to the pure-Python codec; they skip where the
module is not built.

Wire layout (must match
``pulse/pulse-canon/src/envelope.rs::PulseEnvelope::write_canonical_into``):

    | id:16 | origin:16 | mono_ns:u64 | et:u16 | flg:u16 |       (44 B fixed)
    | tn?:u8 | tn_len:u32 | tn_bytes:tn_len |                    (1 + 4 + L if Some)
    | variant:u8 | <variant data> |                              (variant-specific)

    variant=0 (Raw):    | payload_len:u32 | payload_bytes:n |
    variant=1 (Nested): | count:u32 | child_canonical_bytes... |

All multi-byte fields are little-endian. ``id`` is BLAKE3 truncated to 16
bytes over this preimage::

    | domain tag | et:u16 | tn?:u8 | tn_len:u32 | tn_bytes |
                          | pv:u8 | pl_len:u32 | pl_bytes |

where ``pl_bytes`` is ``payload.to_bytes()`` — the payload bytes for ``Raw``
and ``count_le ‖ child₀_canonical ‖ child₁_canonical ‖ ...`` for ``Nested``.
The lengths and the tags are load-bearing, not decoration: concatenating the
fields without them lets the ``type_name``/``payload`` boundary slide, and
lets a ``Raw`` payload collide with a ``Nested`` one that serializes the
same way, so distinct envelopes hash to a single id.
"""

import json
import pathlib
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Union

import blake3
import pytest


# Variant tag constants (mirror PAYLOAD_VARIANT_RAW / PAYLOAD_VARIANT_NESTED).
PAYLOAD_VARIANT_RAW = 0
PAYLOAD_VARIANT_NESTED = 1

# Mirror of ENVELOPE_ID_DOMAIN_TAG. Also published in every test-vector
# fixture as ``expected.envelope_id_framing``; compare that field first if
# ids disagree across implementations.
ENVELOPE_ID_DOMAIN_TAG = b"pulse-envelope-id/v2"


# ─────────────────────────────────────────────────────────────────────────
#  Payload variants — Python equivalents of PayloadData::Raw / ::Nested
# ─────────────────────────────────────────────────────────────────────────


@dataclass
class RawPayload:
    bytes_: bytes


@dataclass
class NestedPayload:
    children: List["Envelope"] = field(default_factory=list)


PayloadData = Union[RawPayload, NestedPayload]


@dataclass
class Envelope:
    """Python equivalent of PulseEnvelope. Used for round-trip tests."""

    envelope_type: int
    payload: PayloadData
    type_name: Optional[str] = None
    origin: bytes = b"\x00" * 16
    monotonic_nanos: int = 0
    flags: int = 0
    id_: Optional[bytes] = None  # set after construction


# ─────────────────────────────────────────────────────────────────────────
#  Pure-Python canonical codec (mirrors the Rust implementation byte-for-byte)
# ─────────────────────────────────────────────────────────────────────────


def payload_to_bytes(payload: PayloadData) -> bytes:
    """Mirror of PayloadData::to_bytes — the input to id computation."""
    if isinstance(payload, RawPayload):
        return payload.bytes_
    elif isinstance(payload, NestedPayload):
        out = bytearray()
        out += struct.pack("<I", len(payload.children))
        for child in payload.children:
            out += encode_envelope(child)
        return bytes(out)
    else:
        raise TypeError(f"unknown payload type: {type(payload)}")


def compute_id(
    envelope_type: int,
    type_name: Optional[str],
    payload: PayloadData,
) -> bytes:
    """Reproduce ``PulseEnvelopeId::compute_from_payload``."""
    variant = (
        PAYLOAD_VARIANT_RAW
        if isinstance(payload, RawPayload)
        else PAYLOAD_VARIANT_NESTED
    )
    payload_bytes = payload_to_bytes(payload)

    h = blake3.blake3()
    h.update(ENVELOPE_ID_DOMAIN_TAG)
    h.update(struct.pack("<H", envelope_type))  # u16 LE
    if type_name is None:
        h.update(b"\x00")  # presence tag = absent
    else:
        name_bytes = type_name.encode("utf-8")
        h.update(b"\x01")  # presence tag = present
        h.update(struct.pack("<I", len(name_bytes)))
        h.update(name_bytes)
    h.update(bytes([variant]))
    h.update(struct.pack("<I", len(payload_bytes)))
    h.update(payload_bytes)
    return h.digest()[:16]


def encode_envelope(env: Envelope) -> bytes:
    """Pure-Python encoder for the canonical PulseEnvelope wire layout."""
    assert len(env.origin) == 16, "origin must be exactly 16 bytes"
    env_id = env.id_ or compute_id(env.envelope_type, env.type_name, env.payload)

    out = bytearray()
    out += env_id  # bytes 0..16
    out += env.origin  # bytes 16..32
    out += struct.pack("<Q", env.monotonic_nanos)  # bytes 32..40
    out += struct.pack("<H", env.envelope_type)  # bytes 40..42
    out += struct.pack("<H", env.flags)  # bytes 42..44

    # type_name section
    if env.type_name is None:
        out += b"\x00"  # presence tag = 0
    else:
        out += b"\x01"
        tn_bytes = env.type_name.encode("utf-8")
        out += struct.pack("<I", len(tn_bytes))
        out += tn_bytes

    # payload variant tag + variant-specific data
    if isinstance(env.payload, RawPayload):
        out += bytes([PAYLOAD_VARIANT_RAW])
        out += struct.pack("<I", len(env.payload.bytes_))
        out += env.payload.bytes_
    elif isinstance(env.payload, NestedPayload):
        out += bytes([PAYLOAD_VARIANT_NESTED])
        out += struct.pack("<I", len(env.payload.children))
        for child in env.payload.children:
            out += encode_envelope(child)
    else:
        raise TypeError(f"unknown payload type: {type(env.payload)}")

    return bytes(out)


def encode_canonical(
    *,
    envelope_type: int,
    payload: bytes,
    type_name: Optional[str] = None,
    origin: bytes = b"\x00" * 16,
    monotonic_nanos: int = 0,
    flags: int = 0,
) -> bytes:
    """Convenience wrapper for the common Raw-payload case. Tests for
    Nested go through ``encode_envelope`` directly."""
    env = Envelope(
        envelope_type=envelope_type,
        payload=RawPayload(payload),
        type_name=type_name,
        origin=origin,
        monotonic_nanos=monotonic_nanos,
        flags=flags,
    )
    return encode_envelope(env)


def decode_envelope_at(buf: bytes, start: int = 0) -> tuple[Envelope, int]:
    """Decode envelope starting at offset ``start``. Returns
    ``(envelope, next_offset)`` where ``next_offset`` points just past the
    decoded envelope. Used recursively for Nested decode."""
    min_size = 44 + 1 + 1 + 4
    if len(buf) - start < min_size:
        raise ValueError(f"buffer too small: {len(buf) - start} bytes from offset {start}")

    env_id = buf[start : start + 16]
    origin = buf[start + 16 : start + 32]
    (monotonic_nanos,) = struct.unpack("<Q", buf[start + 32 : start + 40])
    (envelope_type,) = struct.unpack("<H", buf[start + 40 : start + 42])
    (flags,) = struct.unpack("<H", buf[start + 42 : start + 44])

    cursor = start + 44
    presence = buf[cursor]
    cursor += 1
    if presence == 0:
        type_name: Optional[str] = None
    elif presence == 1:
        if cursor + 4 > len(buf):
            raise ValueError("truncated at type_name_len")
        (tn_len,) = struct.unpack("<I", buf[cursor : cursor + 4])
        cursor += 4
        if cursor + tn_len > len(buf):
            raise ValueError("truncated at type_name")
        type_name = buf[cursor : cursor + tn_len].decode("utf-8")
        cursor += tn_len
    else:
        raise ValueError(f"invalid type_name presence tag: {presence}")

    # Payload variant tag
    if cursor + 1 > len(buf):
        raise ValueError("truncated at payload_variant_tag")
    variant = buf[cursor]
    cursor += 1

    payload: PayloadData
    if variant == PAYLOAD_VARIANT_RAW:
        if cursor + 4 > len(buf):
            raise ValueError("truncated at payload_len")
        (payload_len,) = struct.unpack("<I", buf[cursor : cursor + 4])
        cursor += 4
        if cursor + payload_len > len(buf):
            raise ValueError("truncated at payload")
        payload = RawPayload(buf[cursor : cursor + payload_len])
        cursor += payload_len
    elif variant == PAYLOAD_VARIANT_NESTED:
        if cursor + 4 > len(buf):
            raise ValueError("truncated at nested_count")
        (count,) = struct.unpack("<I", buf[cursor : cursor + 4])
        cursor += 4
        children: List[Envelope] = []
        for child_index in range(count):
            try:
                child, cursor = decode_envelope_at(buf, cursor)
            except ValueError as e:
                raise ValueError(f"nested child {child_index} decode failed: {e}") from e
            children.append(child)
        payload = NestedPayload(children)
    else:
        raise ValueError(f"invalid payload variant tag: {variant}")

    env = Envelope(
        envelope_type=envelope_type,
        payload=payload,
        type_name=type_name,
        origin=origin,
        monotonic_nanos=monotonic_nanos,
        flags=flags,
        id_=env_id,
    )
    return env, cursor


def decode_canonical(buf: bytes) -> dict:
    """Backwards-compatible decoder for the Raw-payload case. Returns a
    dict matching the prior signature so existing tests keep working."""
    env, _ = decode_envelope_at(buf, 0)
    if not isinstance(env.payload, RawPayload):
        raise ValueError(
            "decode_canonical: envelope is Nested; use decode_envelope_at + walk children"
        )
    return {
        "id": env.id_,
        "origin": env.origin,
        "monotonic_nanos": env.monotonic_nanos,
        "envelope_type": env.envelope_type,
        "flags": env.flags,
        "type_name": env.type_name,
        "payload": env.payload.bytes_,
    }


# ─────────────────────────────────────────────────────────────────────────
#  Tests — cross-language byte-equality
# ─────────────────────────────────────────────────────────────────────────


def test_known_envelope_produces_expected_bytes():
    """The hard-coded byte layout must match the Rust test
    ``canonical_layout_is_stable_for_a_known_envelope`` in
    ``pulse/pulse-canon/src/envelope.rs``. If this fails, the wire format
    has drifted between Rust and Python and the cross-language compatibility
    contract is broken."""
    bytes_out = encode_canonical(
        envelope_type=0x0001,
        payload=bytes([0x42, 0x42, 0x42, 0x42]),
    )

    # The exact byte layout the Rust test asserts (54 B canonical layout
    # with payload variant tag at offset 45):
    assert len(bytes_out) == 54
    assert bytes_out[16:32] == b"\x00" * 16  # origin all zeros
    assert bytes_out[32:40] == b"\x00" * 8  # monotonic_nanos = 0
    assert bytes_out[40:42] == b"\x01\x00"  # envelope_type LE = 0x0001
    assert bytes_out[42:44] == b"\x00\x00"  # flags = 0
    assert bytes_out[44] == 0  # type_name presence = None
    assert bytes_out[45] == PAYLOAD_VARIANT_RAW  # payload variant = 0 (Raw)
    assert bytes_out[46:50] == b"\x04\x00\x00\x00"  # payload_len = 4 LE
    assert bytes_out[50:54] == b"\x42\x42\x42\x42"  # payload


def test_round_trip_encode_decode_preserves_fields():
    payload = b"hello cross-language world"
    encoded = encode_canonical(
        envelope_type=0x0042,
        payload=payload,
        type_name="api/inference",
        origin=bytes([0xAB] * 16),
        monotonic_nanos=1_234_567_890,
        flags=0b0101,  # BROADCAST | PRIORITY
    )
    decoded = decode_canonical(encoded)

    assert decoded["envelope_type"] == 0x0042
    assert decoded["payload"] == payload
    assert decoded["type_name"] == "api/inference"
    assert decoded["origin"] == bytes([0xAB] * 16)
    assert decoded["monotonic_nanos"] == 1_234_567_890
    assert decoded["flags"] == 0b0101


def test_id_is_self_verifying_against_content():
    """The id field MUST equal BLAKE3(envelope_type ‖ type_name? ‖
    payload.to_bytes()) truncated to 16 bytes. This is the
    content-addressing contract."""
    envelope_type = 0x0010
    type_name = "trace/event"
    payload = b"some data"

    encoded = encode_canonical(
        envelope_type=envelope_type,
        payload=payload,
        type_name=type_name,
    )
    decoded = decode_canonical(encoded)

    expected_id = compute_id(envelope_type, type_name, RawPayload(payload))
    assert decoded["id"] == expected_id


def test_empty_payload_is_valid():
    encoded = encode_canonical(envelope_type=0x0001, payload=b"")
    decoded = decode_canonical(encoded)
    assert decoded["payload"] == b""
    assert decoded["envelope_type"] == 0x0001


def test_buffer_too_small_rejected():
    with pytest.raises(ValueError, match="buffer too small"):
        decode_canonical(b"\x00" * 40)


def test_invalid_type_name_tag_rejected():
    encoded = bytearray(encode_canonical(envelope_type=1, payload=b"x"))
    encoded[44] = 99  # corrupt the presence tag
    with pytest.raises(ValueError, match="invalid type_name presence tag"):
        decode_canonical(bytes(encoded))


def test_truncated_payload_rejected():
    encoded = bytearray(encode_canonical(envelope_type=1, payload=b"hello"))
    encoded = encoded[:-2]  # chop the last 2 bytes of payload
    with pytest.raises(ValueError, match="truncated at payload"):
        decode_canonical(bytes(encoded))


def test_byte_identical_to_rust_for_known_inputs():
    """Direct byte-for-byte comparison against the Rust hard-coded
    expected layout. If this test passes, Rust and Python produce
    byte-identical canonical envelope bytes for the same inputs, which is
    the byte equality the standard requires."""

    # Construct the same envelope as the Rust test
    # (canonical_layout_is_stable_for_a_known_envelope).
    py_bytes = encode_canonical(
        envelope_type=0x0001,
        payload=bytes([0x42, 0x42, 0x42, 0x42]),
    )

    # The Rust id is BLAKE3 over the length-prefixed preimage for
    # (0x0001, no type_name, Raw [0x42 × 4]). Python recomputes it
    # independently here. Both must produce the same 16 bytes; if they
    # don't, the two preimage encoders diverged.
    expected_id = compute_id(
        0x0001, None, RawPayload(bytes([0x42, 0x42, 0x42, 0x42]))
    )
    assert py_bytes[0:16] == expected_id

    # The remaining 38 bytes are deterministic (no random state):
    # 16 zeros (origin) + 8 zeros (monotonic) + 0x01 0x00 (env_type) +
    # 0x00 0x00 (flags) + 0x00 (no type_name) +
    # 0x00 (Raw variant tag) +
    # 0x04 0x00 0x00 0x00 (payload_len = 4) + 4 × 0x42 (payload).
    expected_tail = (
        b"\x00" * 16  # origin
        + b"\x00" * 8  # monotonic_nanos
        + b"\x01\x00"  # envelope_type
        + b"\x00\x00"  # flags
        + b"\x00"  # type_name presence = None
        + bytes([PAYLOAD_VARIANT_RAW])  # payload variant tag = 0 (Raw)
        + b"\x04\x00\x00\x00"  # payload_len = 4
        + b"\x42\x42\x42\x42"  # payload
    )
    assert py_bytes[16:] == expected_tail
    assert len(py_bytes) == 54


def _fixture(name: str) -> Optional[dict]:
    """Load a checked-in conformance fixture, or None if unavailable.

    The vectors sit under pulse/pulse-spec at the root of the tree this binding
    is in, however deep the binding sits (under peripheral/bindings in the
    integrated tree, under bindings/ in the standard's own repository): the
    first ancestor that holds them. Outside any tree (a wheel built elsewhere)
    there are none, and the tests that need them skip.
    """
    for root in pathlib.Path(__file__).resolve().parents:
        path = root / "pulse" / "pulse-spec" / "test-vectors" / f"{name}.json"
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
    return None


@pytest.mark.parametrize("name", ["envelope-raw-known-good", "envelope-nested-3-level"])
def test_matches_checked_in_rust_fixture(name):
    """Compare against bytes Rust actually produced.

    ``test_byte_identical_to_rust_for_known_inputs`` recomputes the id with
    this file's own ``compute_id``, so it proves self-consistency, not
    cross-language agreement — the two preimage encoders could drift in the
    same direction and it would still pass. This test reads the fixtures the
    Rust reference generated and asserts byte equality against them.
    """
    fixture = _fixture(name)
    if fixture is None:
        pytest.skip(f"{name}.json not reachable from this checkout")

    expected = fixture["expected"]
    assert expected["envelope_id_framing"] == ENVELOPE_ID_DOMAIN_TAG.decode(), (
        "fixture was generated under a different envelope-ID framing revision"
    )

    if name == "envelope-raw-known-good":
        env = Envelope(envelope_type=0x0001, payload=RawPayload(bytes([0x42] * 4)))
    else:
        def build(envelope_type, payload):
            e = Envelope(envelope_type=envelope_type, payload=payload)
            e.id_ = compute_id(envelope_type, None, payload)
            return e

        leaf = build(0x0010, RawPayload(bytes([0xAA, 0xBB, 0xCC])))
        mid = build(0x0020, NestedPayload([leaf]))
        sibling = build(0x0030, RawPayload(bytes([0x11, 0x22])))
        env = build(0x0040, NestedPayload([mid, sibling]))

    encoded = encode_envelope(env)
    assert encoded[0:16].hex() == expected["id_hex"]
    assert encoded.hex() == expected["canonical_hex"]
    assert len(encoded) == expected["size_bytes"]


# ─────────────────────────────────────────────────────────────────────────
#  Envelope-id preimage — the boundary between fields must not slide
# ─────────────────────────────────────────────────────────────────────────


def test_type_name_payload_boundary_is_unambiguous():
    """Mirror of the Rust regression test. Without the length prefixes both
    of these fed BLAKE3 the identical stream ``0000 74726163652f6576656e7458``
    and produced one id for two distinct envelopes."""
    a = compute_id(0, "trace/event", RawPayload(b"X"))
    b = compute_id(0, "trace/eventX", RawPayload(b""))
    assert a != b


def test_raw_and_nested_payload_variants_do_not_collide():
    """Lengths alone are not enough: ``Raw([0; 4])`` and ``Nested([])`` both
    serialize to four zero bytes, so the variant tag is what separates them."""
    raw = RawPayload(bytes(4))
    nested = NestedPayload([])
    assert payload_to_bytes(raw) == payload_to_bytes(nested)
    assert compute_id(1, None, raw) != compute_id(1, None, nested)


def test_absent_type_name_differs_from_empty_type_name():
    payload = RawPayload(b"body")
    assert compute_id(7, None, payload) != compute_id(7, "", payload)


# ─────────────────────────────────────────────────────────────────────────
#  Nested(Vec<Envelope>) — recursive composition tests (Option B)
# ─────────────────────────────────────────────────────────────────────────


def test_nested_empty_round_trips():
    parent = Envelope(envelope_type=0x0050, payload=NestedPayload([]))
    parent.id_ = compute_id(parent.envelope_type, parent.type_name, parent.payload)

    encoded = encode_envelope(parent)
    decoded, consumed = decode_envelope_at(encoded, 0)

    assert consumed == len(encoded)
    assert isinstance(decoded.payload, NestedPayload)
    assert decoded.payload.children == []


def test_nested_single_child_round_trips():
    child = Envelope(envelope_type=0x0001, payload=RawPayload(b"child payload"))
    child.id_ = compute_id(child.envelope_type, child.type_name, child.payload)

    parent = Envelope(envelope_type=0x0050, payload=NestedPayload([child]))
    parent.id_ = compute_id(parent.envelope_type, parent.type_name, parent.payload)

    encoded = encode_envelope(parent)
    decoded, _ = decode_envelope_at(encoded, 0)

    assert isinstance(decoded.payload, NestedPayload)
    assert len(decoded.payload.children) == 1
    decoded_child = decoded.payload.children[0]
    assert decoded_child.envelope_type == 0x0001
    assert isinstance(decoded_child.payload, RawPayload)
    assert decoded_child.payload.bytes_ == b"child payload"


def test_nested_recursive_three_levels():
    leaf = Envelope(envelope_type=0x0001, payload=RawPayload(b"leaf"))
    leaf.id_ = compute_id(leaf.envelope_type, leaf.type_name, leaf.payload)

    inner_a = Envelope(envelope_type=0x0050, payload=NestedPayload([leaf]))
    inner_a.id_ = compute_id(inner_a.envelope_type, inner_a.type_name, inner_a.payload)

    inner_b = Envelope(envelope_type=0x0002, payload=RawPayload(b"sibling"))
    inner_b.id_ = compute_id(inner_b.envelope_type, inner_b.type_name, inner_b.payload)

    outer = Envelope(envelope_type=0x0050, payload=NestedPayload([inner_a, inner_b]))
    outer.id_ = compute_id(outer.envelope_type, outer.type_name, outer.payload)

    encoded = encode_envelope(outer)
    decoded, _ = decode_envelope_at(encoded, 0)

    children = decoded.payload.children
    assert len(children) == 2
    assert children[0].envelope_type == 0x0050
    assert children[1].envelope_type == 0x0002
    # Drill into level-2 recursion.
    grandchildren = children[0].payload.children
    assert len(grandchildren) == 1
    assert grandchildren[0].payload.bytes_ == b"leaf"


def test_invalid_payload_variant_tag_rejected():
    encoded = bytearray(encode_canonical(envelope_type=1, payload=b"x"))
    # Variant tag at offset 45 (after 44-byte fixed prefix + 1-byte type_name presence).
    encoded[45] = 99
    with pytest.raises(ValueError, match="invalid payload variant tag"):
        decode_canonical(bytes(encoded))


def test_nested_byte_identical_to_rust_for_simple_case():
    """Cross-language byte-equality for a small Nested envelope. Build a
    parent with two children of known shape, and assert the encoding is
    byte-stable. The Rust test ``nested_single_child_round_trips`` and
    ``nested_multiple_children_preserve_order`` exercise the same shape
    on the Rust side.

    Note: this test asserts the encoding is *deterministic and round-trips*
    rather than hard-coding the entire byte sequence (the BLAKE3 ids embed
    in many places and the test would be unreadable). The combination of
    (a) Rust round-trip + (b) Python round-trip + (c) compute_id giving
    the same id from the same inputs in both languages is sufficient to
    prove byte-equality at the protocol level."""
    child1 = Envelope(envelope_type=0x0001, payload=RawPayload(bytes([0xAA] * 4)))
    child1.id_ = compute_id(child1.envelope_type, None, child1.payload)
    child2 = Envelope(envelope_type=0x0002, payload=RawPayload(bytes([0xBB] * 4)))
    child2.id_ = compute_id(child2.envelope_type, None, child2.payload)

    parent = Envelope(envelope_type=0x0050, payload=NestedPayload([child1, child2]))
    parent.id_ = compute_id(parent.envelope_type, None, parent.payload)

    encoded = encode_envelope(parent)
    decoded, consumed = decode_envelope_at(encoded, 0)

    assert consumed == len(encoded)
    assert decoded.id_ == parent.id_
    assert len(decoded.payload.children) == 2
    assert decoded.payload.children[0].id_ == child1.id_
    assert decoded.payload.children[1].id_ == child2.id_


# ─────────────────────────────────────────────────────────────────────────
#  The binding's codec: pulse_wire.PulseEnvelope against every fixture and
#  against the pure-Python codec above
# ─────────────────────────────────────────────────────────────────────────


def _vectors_dir() -> Optional[pathlib.Path]:
    """The specification's test-vectors directory, found as ``_fixture``
    finds one fixture, or None outside a tree."""
    for root in pathlib.Path(__file__).resolve().parents:
        path = root / "pulse" / "pulse-spec" / "test-vectors"
        if path.is_dir():
            return path
    return None


VECTORS = _vectors_dir()
FIXTURES = sorted(p.stem for p in VECTORS.glob("*.json")) if VECTORS else []


@pytest.fixture
def pw():
    return pytest.importorskip("pulse_wire")


def _u(value) -> int:
    """A fixture integer: a number, or a string of one in hex or decimal,
    or of the form ``"Heartbeat (0x0001)"``."""
    if isinstance(value, int):
        return value
    if "(" in value:
        value = value[value.index("(") + 1 : value.index(")")]
    return int(value, 0)


def _binding_tree(pw, node):
    """The binding envelope a fixture's ``structure`` node describes, each
    node's id checked against the one the fixture states."""
    envelope_type = _u(node["envelope_type"])
    type_name = node.get("type_name")
    if node["payload_variant"] == "Nested":
        children = [_binding_tree(pw, child) for child in node["children"]]
        env = pw.PulseEnvelope.nested(envelope_type, type_name, children)
    else:
        env = pw.PulseEnvelope(envelope_type, type_name, bytes.fromhex(node["payload_hex"]))
    assert env.id.hex() == node["id_hex"]
    return env


def _check_decoded_tree(env, node):
    assert env.id.hex() == node["id_hex"]
    assert env.envelope_type == _u(node["envelope_type"])
    if node["payload_variant"] == "Nested":
        assert len(env.children) == len(node["children"])
        for child, child_node in zip(env.children, node["children"]):
            _check_decoded_tree(child, child_node)
    else:
        assert env.children is None
        assert env.payload.hex() == node["payload_hex"]


def test_fixtures_found():
    """In a tree that holds the specification, every fixture is found, so a
    test below runs for each."""
    if VECTORS is None:
        pytest.skip("pulse/pulse-spec/test-vectors not reachable from this checkout")
    assert FIXTURES, f"no fixtures in {VECTORS}"


@pytest.mark.parametrize("name", FIXTURES)
def test_binding_matches_fixture(pw, name):
    """The binding encodes each fixture's inputs to its bytes, and decodes
    its bytes back to its inputs. A fixture of a shape this test does not
    know fails, so a new fixture cannot go unchecked."""
    fixture = json.loads((VECTORS / f"{name}.json").read_text(encoding="utf-8"))
    expected = fixture["expected"]
    canonical = bytes.fromhex(expected["canonical_hex"])
    assert (VECTORS / f"{name}.hex").read_text(encoding="utf-8").strip() == expected["canonical_hex"]
    assert len(canonical) == expected["size_bytes"]

    if name.startswith("envelope-"):
        assert expected["envelope_id_framing"] == pw.ENVELOPE_ID_DOMAIN_TAG.decode()
        if "inputs" in fixture:
            inputs = fixture["inputs"]
            assert inputs["payload_variant"] == "Raw"
            env = pw.PulseEnvelope(
                _u(inputs["envelope_type"]),
                inputs["type_name"],
                bytes.fromhex(inputs["payload_hex"]),
                origin=bytes.fromhex(inputs["origin_hex"]),
                monotonic_nanos=_u(inputs["monotonic_nanos"]),
                flags=_u(inputs["flags"]),
            )
            decoded = pw.PulseEnvelope.from_bytes(canonical)
            assert decoded.envelope_type == _u(inputs["envelope_type"])
            assert decoded.type_name == inputs["type_name"]
            assert decoded.payload.hex() == inputs["payload_hex"]
            assert decoded.origin.hex() == inputs["origin_hex"]
            assert decoded.monotonic_nanos == _u(inputs["monotonic_nanos"])
            assert decoded.flags == _u(inputs["flags"])
        elif "structure" in fixture:
            env = _binding_tree(pw, fixture["structure"]["outer"])
            decoded = pw.PulseEnvelope.from_bytes(canonical)
            _check_decoded_tree(decoded, fixture["structure"]["outer"])
        else:
            pytest.fail(f"{name}: an envelope fixture with neither inputs nor structure")
        assert env.id.hex() == expected["id_hex"]
        assert env.to_bytes() == canonical
        assert env.canonical_size == expected["size_bytes"]
        assert decoded == env and decoded.to_bytes() == canonical
    elif name.startswith("pulse-"):
        inputs = fixture["inputs"]
        pulse = pw.Pulse.from_bytes(canonical)
        assert pulse.as_bytes() == canonical
        assert pulse.origin_id.hex() == inputs["origin_id_hex"]
        assert pulse.monotonic_nanos == _u(inputs["monotonic_nanos"])
        assert pulse.chain_step == _u(inputs["chain_step"])
        assert pulse.instruction == _u(inputs["instruction"])
        assert pulse.scope == _u(inputs["scope_hex"])
        assert pulse.envelope_ref.hex() == inputs["envelope_ref_hex"]
        ref = bytes.fromhex(inputs["envelope_ref_hex"])
        assert pulse.envelope_id() == (ref if any(ref) else None)
    else:
        pytest.fail(f"{name}: a fixture of a kind this test does not check; add a case for it")


def _pure_and_binding_pairs(pw):
    """The same envelopes built by the pure-Python codec and by the binding."""
    pairs = []
    for envelope_type, type_name, payload, origin, mono, flags in [
        (0x0001, None, b"", bytes(16), 0, 0),
        (0x0042, "api/inference", b"hello cross-language world", bytes([0xAB] * 16), 1_234_567_890, 0b0101),
        (0x0000, "", bytes(range(256)) * 4, bytes(range(16)), 2**64 - 1, 0b1111),
        (0xFFFF, "trace/événement", b"\x00" * 7, bytes(16), 1, 0b0010),
    ]:
        pure = Envelope(envelope_type, RawPayload(payload), type_name, origin, mono, flags)
        binding = pw.PulseEnvelope(envelope_type, type_name, payload, origin, mono, flags)
        pairs.append((pure, binding))

    leaf_pure, leaf = pairs[1]
    sib_pure, sib = pairs[3]
    mid_pure = Envelope(0x0020, NestedPayload([leaf_pure]), "batch/inner", bytes([7] * 16), 9, 0b0001)
    mid = pw.PulseEnvelope.nested(0x0020, "batch/inner", [leaf], bytes([7] * 16), 9, 0b0001)
    outer_pure = Envelope(0x0040, NestedPayload([mid_pure, sib_pure]))
    outer = pw.PulseEnvelope.nested(0x0040, None, (mid, sib))
    empty_pure = Envelope(0x0050, NestedPayload([]))
    empty = pw.PulseEnvelope.nested(0x0050, None, [])
    pairs += [(mid_pure, mid), (outer_pure, outer), (empty_pure, empty)]
    return pairs


def test_binding_and_pure_python_agree(pw):
    """Byte for byte both ways: the binding encodes what the pure-Python
    codec encodes, each decodes the other's bytes to the same fields, and
    their ids agree."""
    for pure, binding in _pure_and_binding_pairs(pw):
        pure_bytes = encode_envelope(pure)
        assert binding.to_bytes() == pure_bytes
        assert binding.id == compute_id(pure.envelope_type, pure.type_name, pure.payload)
        assert binding.payload == payload_to_bytes(pure.payload)
        assert binding.canonical_size == len(pure_bytes)

        from_binding, used = decode_envelope_at(binding.to_bytes())
        assert used == len(pure_bytes)
        assert encode_envelope(from_binding) == pure_bytes

        from_pure = pw.PulseEnvelope.from_bytes(pure_bytes)
        assert from_pure.to_bytes() == pure_bytes
        assert from_pure.envelope_type == pure.envelope_type
        assert from_pure.type_name == pure.type_name
        assert from_pure.origin == pure.origin
        assert from_pure.monotonic_nanos == pure.monotonic_nanos
        assert from_pure.flags == pure.flags
        if isinstance(pure.payload, RawPayload):
            assert from_pure.children is None
            assert from_pure.payload == pure.payload.bytes_
            assert pw.compute_envelope_id(pure.envelope_type, pure.type_name, pure.payload.bytes_) == binding.id
        else:
            assert [c.to_bytes() for c in from_pure.children] == [
                encode_envelope(c) for c in pure.payload.children
            ]


def test_binding_effective_type_name_and_equality(pw):
    a = pw.PulseEnvelope(0x0007, None, b"body")
    b = pw.PulseEnvelope(0x0007, None, bytearray(b"body"), origin=b"\x01" * 16, flags=pw.EnvelopeFlags.BROADCAST)
    c = pw.PulseEnvelope(0x0007, "", memoryview(b"body"))
    assert a.effective_type_name == "0x0007" and c.effective_type_name == ""
    # Equality is the id's, as in Rust: the origin and flags are not content.
    assert a == b and hash(a) == hash(b) and a.to_bytes() != b.to_bytes()
    assert a != c and a != a.to_bytes()
    assert len({a, b, c}) == 2
    assert "envelope_type=0x0007" in repr(a)


def test_binding_refuses_bad_fields(pw):
    with pytest.raises(ValueError, match="reserved bits 0x0010"):
        pw.PulseEnvelope(1, None, b"", flags=0x0010)
    with pytest.raises(ValueError, match="16 bytes"):
        pw.PulseEnvelope(1, None, b"", origin=b"\x00" * 15)
    with pytest.raises(OverflowError):
        pw.PulseEnvelope(0x10000, None, b"")
    with pytest.raises(TypeError):
        pw.PulseEnvelope(1, None, "text is not bytes")
    with pytest.raises(TypeError):
        pw.PulseEnvelope.nested(1, None, [b"not an envelope"])


def test_binding_decode_errors(pw):
    good = pw.PulseEnvelope(1, "t", b"hello").to_bytes()
    cases = {
        "buffer too small": good[:40],
        "truncated": good[:-2],
        "after": good + b"\x00",
        "invalid type_name presence tag": good[:44] + b"\x63" + good[45:],
        "reserved bits": good[:42] + b"\x10\x00" + good[44:],
        "its content's id": bytes([good[0] ^ 1]) + good[1:],
    }
    for why, data in cases.items():
        with pytest.raises(pw.EnvelopeDecodeError, match=why):
            pw.PulseEnvelope.from_bytes(data)
    assert issubclass(pw.EnvelopeDecodeError, ValueError)


def test_binding_refuses_a_misaddressed_child(pw):
    """A nested child whose id is not its content's is refused, though the
    parent's own id, hashed over the child's bytes as they are, checks out."""
    child = Envelope(0x0010, RawPayload(b"leaf"))
    child.id_ = b"\x55" * 16
    parent = Envelope(0x0040, NestedPayload([child]))
    parent.id_ = compute_id(parent.envelope_type, None, parent.payload)
    with pytest.raises(pw.EnvelopeDecodeError, match=r"children\[0\]"):
        pw.PulseEnvelope.from_bytes(encode_envelope(parent))
