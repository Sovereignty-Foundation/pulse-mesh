// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `pulse-wire` Python bindings.
//!
//! Wraps `pulse_wire_udp::{Sender, Receiver}` and the core `Pulse`
//! type so Python callers can drive PMS Tier-1 + Tier-2 framed UDP
//! traffic without dropping into Rust, `PulseEnvelope`, the canonical
//! envelope codec of `pulse-canon`, and `Channel` (`channel.rs`),
//! messages between processes on one host over the shared-memory ring
//! and envelope store.
//!
//! Built with PyO3 + maturin. The native module name is `pulse_wire`
//! (matches `[lib].name` in Cargo.toml and `module-name` in
//! pyproject.toml). `pulse_wire.pyi`, beside Cargo.toml, types it.

mod channel;

use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::time::Duration;

use pyo3::buffer::PyBuffer;
use pyo3::exceptions::{PyBufferError, PyIOError, PyTimeoutError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};

use pulse_wire_core::pulse::{Instruction as RustInstruction, Pulse as RustPulse, PULSE_WIRE_SIZE};
use pulse_wire_core::{
    PayloadData, PulseEnvelope as RustEnvelope, PulseEnvelopeFlags, PulseEnvelopeId,
    ENVELOPE_ID_DOMAIN_TAG,
};
use pulse_wire_udp_transport::{
    Receiver as RustReceiver, ReceiverError, RecvMeta as RustRecvMeta, Sender as RustSender,
    SenderError, MAX_ENVELOPE,
};

// ────────────────────────────── Instruction ──────────────────────────────

/// Deterministic opcode constants. Mirrors `pulse_canon::Instruction`
/// but exposed as plain `u16` class attributes so Python callers can
/// write `pw.Instruction.DATA` without a separate enum dance.
#[pyclass(name = "Instruction", frozen)]
struct PyInstruction;

#[pymethods]
impl PyInstruction {
    #[classattr]
    const NULL: u16 = 0x0000;
    #[classattr]
    const HEARTBEAT: u16 = 0x0001;
    #[classattr]
    const DATA: u16 = 0x0010;
}

// ────────────────────────────── Pulse ──────────────────────────────

/// 128-byte cache-aligned Pulse — the wire-format atomic unit.
///
/// Mutable through Python attribute setters; passes by reference to
/// `Sender.send()` / `Sender.send_to()`.
#[pyclass(name = "Pulse")]
struct PyPulse {
    /// Boxed: PyO3 keeps a pyclass's fields inside the Python object,
    /// which CPython aligns to no more than 16 bytes, and a `Pulse` is
    /// `align(64)`, so one stored inline is misaligned. The box is
    /// allocated with `Pulse`'s own layout, aligned wherever the object is.
    inner: Box<RustPulse>,
}

impl From<RustPulse> for PyPulse {
    /// Every Python `Pulse` is made here, so every one is boxed.
    fn from(pulse: RustPulse) -> Self {
        Self {
            inner: Box::new(pulse),
        }
    }
}

// PyO3 puts a pyclass's fields in the memory CPython's object allocator
// returns for the instance. That allocator only guarantees alignment for
// fundamental scalar types (`alignof(max_align_t)`; CPython's obmalloc in
// fact aligns to 16 bytes since 3.8), never the extended alignment of a
// `#[repr(align(N))]` type — so a pyclass whose alignment exceeds the
// fundamental scalar alignment gets misaligned fields. A `Pulse` stored
// inline (`align(64)`) fails here; every field these pyclasses hold is a
// scalar, a pointer or a box, whose alignment never exceeds that of a
// `u64`.
//
// The bound is the widest fundamental alignment, not `align_of::<usize>()`
// alone: on a 32-bit host a pointer aligns to 4 but a `u64` still needs 8,
// so `PyRecvMeta`'s two `u64` fields (and the `u64` sequence counters
// inside `PySender` / `PyReceiver`) make those types `align(8)`. Bounding
// at the pointer alignment there wrongly rejected them (it failed safe:
// the crate would not compile on a 32-bit target though the layout is
// sound). `max(align_of::<usize>(), align_of::<u64>())` is 8 on every
// 32- and 64-bit target and states the requirement the allocator actually
// meets. See `tests/test_pulse_alignment.py` for the runtime side.
const _: () = {
    let ptr = std::mem::align_of::<usize>();
    let scalar = std::mem::align_of::<u64>();
    let most = if ptr > scalar { ptr } else { scalar };
    assert!(std::mem::align_of::<PyPulse>() <= most);
    assert!(std::mem::align_of::<PySender>() <= most);
    assert!(std::mem::align_of::<PyReceiver>() <= most);
    assert!(std::mem::align_of::<PyRecvMeta>() <= most);
    assert!(std::mem::align_of::<PyInstruction>() <= most);
    assert!(std::mem::align_of::<channel::PyChannel>() <= most);
    assert!(std::mem::align_of::<PyEnvelope>() <= most);
    assert!(std::mem::align_of::<PyEnvelopeFlags>() <= most);
};

#[pymethods]
impl PyPulse {
    /// Construct a zeroed Pulse (instruction = NULL).
    #[new]
    fn new() -> Self {
        RustPulse::zeroed().into()
    }

    /// Reinterpret a 128-byte buffer as a Pulse. Raises `ValueError`
    /// if the input is not exactly 128 bytes.
    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        RustPulse::from_bytes(bytes).map(Self::from).ok_or_else(|| {
            PyValueError::new_err(format!(
                "Pulse.from_bytes expects {} bytes, got {}",
                PULSE_WIRE_SIZE,
                bytes.len()
            ))
        })
    }

    /// Return a fresh `bytes` object containing the 128-byte wire
    /// representation. Copies; the underlying Pulse is unchanged.
    fn as_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.as_bytes())
    }

    /// Wire size in bytes. Always 128.
    #[classattr]
    const WIRE_SIZE: usize = PULSE_WIRE_SIZE;

    // ─── hex-encoded convenience getters (callers who want raw bytes
    //     use origin_id / envelope_ref directly) ────────────────────

    /// Hex-encoded 32-char string view of the 16-byte `origin_id`.
    #[getter]
    fn origin_id_hex(&self) -> String {
        self.inner
            .origin_id
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    /// Hex-encoded 32-char string view of the 16-byte `envelope_ref`.
    #[getter]
    fn envelope_ref_hex(&self) -> String {
        self.inner
            .envelope_ref
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    // ─── scalar fields exposed as get/set ───────────────────────────

    #[getter]
    fn instruction(&self) -> u16 {
        self.inner.instruction
    }
    #[setter]
    fn set_instruction(&mut self, v: u16) {
        self.inner.instruction = v;
    }

    #[getter]
    fn monotonic_nanos(&self) -> u64 {
        self.inner.monotonic_nanos
    }
    #[setter]
    fn set_monotonic_nanos(&mut self, v: u64) {
        self.inner.monotonic_nanos = v;
    }

    #[getter]
    fn chain_step(&self) -> u64 {
        self.inner.chain_step
    }
    #[setter]
    fn set_chain_step(&mut self, v: u64) {
        self.inner.chain_step = v;
    }

    #[getter]
    fn scope(&self) -> u32 {
        self.inner.scope
    }
    #[setter]
    fn set_scope(&mut self, v: u32) {
        self.inner.scope = v;
    }

    // ─── 16-byte byte-string fields ─────────────────────────────────

    #[getter]
    fn origin_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.origin_id)
    }
    #[setter]
    fn set_origin_id(&mut self, v: &[u8]) -> PyResult<()> {
        if v.len() != 16 {
            return Err(PyValueError::new_err(format!(
                "origin_id must be exactly 16 bytes (got {})",
                v.len()
            )));
        }
        self.inner.origin_id.copy_from_slice(v);
        Ok(())
    }

    #[getter]
    fn envelope_ref<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.envelope_ref)
    }
    #[setter]
    fn set_envelope_ref(&mut self, v: &[u8]) -> PyResult<()> {
        if v.len() != 16 {
            return Err(PyValueError::new_err(format!(
                "envelope_ref must be exactly 16 bytes (got {})",
                v.len()
            )));
        }
        self.inner.envelope_ref.copy_from_slice(v);
        Ok(())
    }

    /// The envelope store cursor a Data pulse names (where the envelope its
    /// `envelope_ref` names was stored), or `None` when it names none.
    #[getter]
    fn store_cursor(&self) -> Option<u64> {
        self.inner.store_cursor()
    }

    /// True when `envelope_ref` is non-zero (an envelope is attached).
    fn has_envelope(&self) -> bool {
        self.inner.has_envelope()
    }

    /// The 16-byte id of the envelope `envelope_ref` names, or `None` when
    /// it is all zeros (it names none).
    fn envelope_id<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner.envelope_id().map(|id| PyBytes::new(py, &id.0))
    }

    /// Name an envelope: write its 16-byte id (`PulseEnvelope.id`) into
    /// `envelope_ref`. The instruction is left as it is; by convention a
    /// pulse naming an envelope is `Instruction.DATA`. Raises `ValueError`
    /// unless `id` is 16 bytes.
    fn set_envelope_id(&mut self, id: &Bound<'_, PyAny>) -> PyResult<()> {
        let id = id16(id, "envelope id")?;
        self.inner.set_envelope_id(&PulseEnvelopeId(id));
        Ok(())
    }

    fn __repr__(&self) -> String {
        let i = self.inner.instruction;
        let name = match RustInstruction::from_u16(i) {
            RustInstruction::Null => "NULL",
            RustInstruction::Heartbeat => "HEARTBEAT",
            RustInstruction::Data => "DATA",
        };
        let origin: String = self
            .inner
            .origin_id
            .iter()
            .take(4)
            .map(|b| format!("{:02x}", b))
            .collect();
        format!(
            "Pulse(instruction={}=0x{:04x}, scope={}, monotonic_nanos={}, origin={}…)",
            name, i, self.inner.scope, self.inner.monotonic_nanos, origin
        )
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}

// ────────────────────────────── PulseEnvelope ──────────────────────────────

pyo3::create_exception!(
    pulse_wire,
    EnvelopeDecodeError,
    PyValueError,
    "Bytes that are not exactly one envelope's canonical encoding, or whose id, or a nested child's, is not the id of its content."
);

/// The envelope flag bits. Mirrors `pulse_canon::PulseEnvelopeFlags` as
/// plain `u16` class attributes, as `Instruction` mirrors the opcodes;
/// combine them with `|`. Bits 4 to 15 are reserved, and an envelope that
/// sets one is refused.
#[pyclass(name = "EnvelopeFlags", frozen)]
struct PyEnvelopeFlags;

#[pymethods]
impl PyEnvelopeFlags {
    /// Fan out to all listeners rather than deliver point to point.
    #[classattr]
    const BROADCAST: u16 = PulseEnvelopeFlags::BROADCAST.bits();
    /// The sender expects an ack from the receiver.
    #[classattr]
    const ACK_REQUIRED: u16 = PulseEnvelopeFlags::ACK_REQUIRED.bits();
    /// Schedule with elevated priority.
    #[classattr]
    const PRIORITY: u16 = PulseEnvelopeFlags::PRIORITY.bits();
    /// The payload is compressed (the codec is not the wire layer's).
    #[classattr]
    const COMPRESSED: u16 = PulseEnvelopeFlags::COMPRESSED.bits();
}

/// A content-addressed envelope and its canonical codec (chapter 3 of the
/// specification), as `pulse_canon::PulseEnvelope`.
///
/// The id is computed from the type, the type name and the payload when the
/// envelope is made, so every envelope carries its content's id;
/// `PulseEnvelope.from_bytes` refuses bytes whose stated id, or a nested
/// child's, is not its content's. The origin, the time and the flags are not
/// hashed. Envelopes are immutable. Two compare equal, and hash alike, when
/// their ids are equal, as in Rust.
#[pyclass(name = "PulseEnvelope", module = "pulse_wire", frozen, eq, hash)]
struct PyEnvelope {
    inner: RustEnvelope,
}

impl PartialEq for PyEnvelope {
    /// Equal ids, as `PulseEnvelope`'s own equality.
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Hash for PyEnvelope {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.id().hash(state);
    }
}

#[pymethods]
impl PyEnvelope {
    /// Make an envelope of raw `payload` bytes (any bytes-like object), of
    /// numeric type `envelope_type` (0 to 65535) and optional `type_name`
    /// routing key, with the 16-byte `origin` (zeros when `None`), the
    /// producer's `monotonic_nanos` and `flags` (`EnvelopeFlags` bits).
    /// Raises `ValueError` for an origin not of 16 bytes or flags that set a
    /// reserved bit.
    #[new]
    #[pyo3(signature = (envelope_type, type_name, payload, origin = None, monotonic_nanos = 0, flags = 0))]
    fn new(
        envelope_type: u16,
        type_name: Option<String>,
        payload: &Bound<'_, PyAny>,
        origin: Option<&Bound<'_, PyAny>>,
        monotonic_nanos: u64,
        flags: u16,
    ) -> PyResult<Self> {
        let payload = PayloadData::Raw(bytes_like(payload, "payload")?);
        make_envelope(
            envelope_type,
            type_name,
            payload,
            origin,
            monotonic_nanos,
            flags,
        )
    }

    /// Make an envelope whose payload is `children`, a sequence of
    /// envelopes, in order; the other arguments are the constructor's.
    #[staticmethod]
    #[pyo3(signature = (envelope_type, type_name, children, origin = None, monotonic_nanos = 0, flags = 0))]
    fn nested(
        envelope_type: u16,
        type_name: Option<String>,
        children: Vec<PyRef<'_, PyEnvelope>>,
        origin: Option<&Bound<'_, PyAny>>,
        monotonic_nanos: u64,
        flags: u16,
    ) -> PyResult<Self> {
        let children = children.iter().map(|c| c.inner.clone()).collect();
        make_envelope(
            envelope_type,
            type_name,
            PayloadData::Nested(children),
            origin,
            monotonic_nanos,
            flags,
        )
    }

    /// Decode exactly one envelope's canonical bytes (any bytes-like
    /// object) and check its id, and every nested child's, against its
    /// content. Raises `EnvelopeDecodeError` (a `ValueError`) for bytes that
    /// are truncated or malformed, set a reserved flag bit, nest deeper than
    /// 32 levels or run past the envelope, or whose id is not their
    /// content's.
    #[staticmethod]
    fn from_bytes(data: &Bound<'_, PyAny>) -> PyResult<Self> {
        let bytes = bytes_like(data, "data")?;
        let inner = RustEnvelope::from_canonical_bytes(&bytes)
            .map_err(|e| EnvelopeDecodeError::new_err(e.to_string()))?;
        if let Some(why) = misaddressed(&inner, "envelope") {
            return Err(EnvelopeDecodeError::new_err(why));
        }
        Ok(Self { inner })
    }

    /// The canonical bytes, the cross-language wire format: what
    /// `PulseEnvelope.from_bytes` decodes, byte for byte.
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.to_canonical_bytes())
    }

    /// The 16-byte content id.
    #[getter]
    fn id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.id().0)
    }

    /// The numeric envelope type.
    #[getter]
    fn envelope_type(&self) -> u16 {
        self.inner.envelope_type()
    }

    /// The string routing key (such as `"trace/event"`), or `None`.
    #[getter]
    fn type_name(&self) -> Option<&str> {
        self.inner.type_name()
    }

    /// The routing key: `type_name` when set, else the type as `"0xNNNN"`.
    #[getter]
    fn effective_type_name(&self) -> String {
        self.inner.effective_type_name()
    }

    /// The payload's bytes, as the id hashes them: a raw payload verbatim,
    /// a nested one as its child count (4 bytes, little-endian) followed by
    /// each child's canonical bytes.
    #[getter]
    fn payload<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        match self.inner.payload() {
            PayloadData::Raw(bytes) => PyBytes::new(py, bytes),
            nested => PyBytes::new(py, &nested.to_bytes()),
        }
    }

    /// The nested envelopes, in order, or `None` for a raw payload.
    #[getter]
    fn children<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyList>>> {
        let Some(children) = self.inner.payload().as_nested() else {
            return Ok(None);
        };
        let children = children
            .iter()
            .map(|child| {
                Py::new(
                    py,
                    PyEnvelope {
                        inner: child.clone(),
                    },
                )
            })
            .collect::<PyResult<Vec<_>>>()?;
        Ok(Some(PyList::new(py, children)?))
    }

    /// The 16-byte origin node identifier; not hashed into the id.
    #[getter]
    fn origin<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.origin)
    }

    /// The producer's monotonic clock in nanoseconds; not hashed into the id.
    #[getter]
    fn monotonic_nanos(&self) -> u64 {
        self.inner.monotonic_nanos
    }

    /// The `EnvelopeFlags` bits; not hashed into the id.
    #[getter]
    fn flags(&self) -> u16 {
        self.inner.flags.bits()
    }

    /// The length of `to_bytes()`.
    #[getter]
    fn canonical_size(&self) -> usize {
        self.inner.canonical_size()
    }

    fn __repr__(&self) -> String {
        let content = match self.inner.payload() {
            PayloadData::Raw(bytes) => format!("payload={} bytes", bytes.len()),
            PayloadData::Nested(children) => format!("children={}", children.len()),
        };
        let type_name = match self.inner.type_name() {
            Some(name) => format!("'{name}'"),
            None => "None".into(),
        };
        format!(
            "PulseEnvelope(id={}, envelope_type=0x{:04x}, type_name={type_name}, {content})",
            self.inner.id(),
            self.inner.envelope_type()
        )
    }
}

/// An envelope of this content and these unhashed fields, refusing an origin
/// not of 16 bytes and flags that set a reserved bit, as the decoder would.
fn make_envelope(
    envelope_type: u16,
    type_name: Option<String>,
    payload: PayloadData,
    origin: Option<&Bound<'_, PyAny>>,
    monotonic_nanos: u64,
    flags: u16,
) -> PyResult<PyEnvelope> {
    let defined = PulseEnvelopeFlags::from_bits(flags).ok_or_else(|| {
        PyValueError::new_err(format!(
            "flags {flags:#06x} set reserved bits {:#06x}; only bits 0 to 3 (EnvelopeFlags) are defined",
            flags & !PulseEnvelopeFlags::all().bits()
        ))
    })?;
    let mut inner = RustEnvelope::with_content(envelope_type, type_name, payload);
    if let Some(origin) = origin {
        inner.origin = id16(origin, "origin")?;
    }
    inner.monotonic_nanos = monotonic_nanos;
    inner.flags = defined;
    Ok(PyEnvelope { inner })
}

/// Why `envelope`, or an envelope nested in it, does not carry its content's
/// id, naming it by its `path`; `None` when every id is its content's.
fn misaddressed(envelope: &RustEnvelope, path: &str) -> Option<String> {
    if !envelope.verify() {
        let content = PulseEnvelopeId::compute_from_payload(
            envelope.envelope_type(),
            envelope.type_name(),
            envelope.payload(),
        );
        return Some(format!(
            "{path} states id {}, but its content's id is {content}",
            envelope.id()
        ));
    }
    let children = envelope.payload().as_nested().unwrap_or_default();
    children
        .iter()
        .enumerate()
        .find_map(|(i, child)| misaddressed(child, &format!("{path}.children[{i}]")))
}

/// The 16-byte content id of an envelope of type `envelope_type`, type name
/// `type_name` and raw `payload` (any bytes-like object), without making the
/// envelope: `PulseEnvelope(envelope_type, type_name, payload).id`.
#[pyfunction]
fn compute_envelope_id<'py>(
    py: Python<'py>,
    envelope_type: u16,
    type_name: Option<&str>,
    payload: &Bound<'_, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    let payload = PayloadData::Raw(bytes_like(payload, "payload")?);
    let id = PulseEnvelopeId::compute_from_payload(envelope_type, type_name, &payload);
    Ok(PyBytes::new(py, &id.0))
}

// ────────────────────────────── RecvMeta ──────────────────────────────

/// Per-frame measurement metadata recovered from the wire.
#[pyclass(name = "RecvMeta", frozen)]
struct PyRecvMeta {
    /// Monotonic per-run sequence stamped by the sender.
    #[pyo3(get)]
    seq: u64,
    /// Sender-stamped `quanta` timestamp in nanoseconds.
    #[pyo3(get)]
    send_ns: u64,
    /// Peer address that sent the datagram (`"ip:port"`).
    #[pyo3(get)]
    peer: String,
}

#[pymethods]
impl PyRecvMeta {
    fn __repr__(&self) -> String {
        format!(
            "RecvMeta(seq={}, send_ns={}, peer='{}')",
            self.seq, self.send_ns, self.peer
        )
    }
}

// ────────────────────────────── Sender ──────────────────────────────

/// UDP sender for `pulse-wire-udp` frames.
///
/// `unsendable`: backed by a `UdpSocket` that's not safe to move
/// across Python threads without GIL-mediated serialization.
#[pyclass(name = "Sender")]
struct PySender {
    inner: RustSender,
}

#[pymethods]
impl PySender {
    /// Bind a sender to `local_addr` (e.g. `"127.0.0.1:0"` to let
    /// the OS pick a port).
    #[staticmethod]
    fn bind(local_addr: &str) -> PyResult<Self> {
        RustSender::bind(local_addr)
            .map(|s| Self { inner: s })
            .map_err(map_sender_err)
    }

    /// Set the default destination for `send()`.
    fn connect(&mut self, dest: &str) -> PyResult<()> {
        self.inner.connect(dest).map_err(map_sender_err)
    }

    /// Send one frame to the connected destination. Returns the
    /// monotonic per-instance `seq` stamped on the wire.
    fn send(&mut self, send_ns: u64, pulse: &PyPulse, envelope: &[u8]) -> PyResult<u64> {
        self.inner
            .send(send_ns, &pulse.inner, envelope)
            .map_err(map_sender_err)
    }

    /// Send one frame to `dest`, overriding any default destination.
    fn send_to(
        &mut self,
        send_ns: u64,
        pulse: &PyPulse,
        envelope: &[u8],
        dest: &str,
    ) -> PyResult<u64> {
        let addr: SocketAddr = dest
            .parse()
            .map_err(|e: std::net::AddrParseError| PyValueError::new_err(e.to_string()))?;
        self.inner
            .send_to(send_ns, &pulse.inner, envelope, addr)
            .map_err(map_sender_err)
    }

    /// Send the envelope from any byte-sized buffer-protocol object
    /// without going through a Python `bytes`. Accepts `bytes`,
    /// `bytearray`, `memoryview`, NumPy `uint8` ndarrays, etc.
    ///
    /// Same semantics as [`Self::send`] otherwise: stamps `(seq, send_ns)`
    /// on the wire, returns the `seq` used.
    ///
    /// `&[u8]` extraction in `send()` already accepts most buffer-protocol
    /// objects via PyO3's `FromPyObject`, but the failure modes are
    /// inconsistent across Python types. `send_buffer` exposes the
    /// path explicitly: read-only is fine (we only read), but the
    /// buffer must be C-contiguous and byte-sized; otherwise
    /// `BufferError` is raised with a clear message.
    ///
    /// The envelope is copied out of `buf` while the GIL is held and the
    /// copy is sent with the GIL released, so no other thread can write
    /// the bytes being sent.
    fn send_buffer(
        &mut self,
        py: Python<'_>,
        send_ns: u64,
        pulse: &PyPulse,
        buf: &Bound<'_, PyAny>,
    ) -> PyResult<u64> {
        let pybuf: PyBuffer<u8> = PyBuffer::get(buf)
            .map_err(|e| PyBufferError::new_err(format!("not a u8 buffer: {e}")))?;
        if !pybuf.is_c_contiguous() {
            return Err(PyBufferError::new_err("buffer is not C-contiguous"));
        }
        let mut local = [0u8; MAX_ENVELOPE];
        let envelope = copy_envelope_out(py, &pybuf, &mut local)?;
        let result = py.detach(|| self.inner.send(send_ns, &pulse.inner, envelope));
        result.map_err(map_sender_err)
    }

    /// Like [`Self::send_to`] but accepts any byte-sized buffer-protocol
    /// object as the envelope (see [`Self::send_buffer`]).
    fn send_buffer_to(
        &mut self,
        py: Python<'_>,
        send_ns: u64,
        pulse: &PyPulse,
        buf: &Bound<'_, PyAny>,
        dest: &str,
    ) -> PyResult<u64> {
        let addr: SocketAddr = dest
            .parse()
            .map_err(|e: std::net::AddrParseError| PyValueError::new_err(e.to_string()))?;
        let pybuf: PyBuffer<u8> = PyBuffer::get(buf)
            .map_err(|e| PyBufferError::new_err(format!("not a u8 buffer: {e}")))?;
        if !pybuf.is_c_contiguous() {
            return Err(PyBufferError::new_err("buffer is not C-contiguous"));
        }
        let mut local = [0u8; MAX_ENVELOPE];
        let envelope = copy_envelope_out(py, &pybuf, &mut local)?;
        let result = py.detach(|| self.inner.send_to(send_ns, &pulse.inner, envelope, addr));
        result.map_err(map_sender_err)
    }

    /// Local socket address (`"ip:port"`) the sender is bound to.
    fn local_addr(&self) -> PyResult<String> {
        self.inner
            .local_addr()
            .map(|a| a.to_string())
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    /// Maximum envelope payload size in bytes.
    #[staticmethod]
    fn max_envelope() -> usize {
        MAX_ENVELOPE
    }

    /// Next-to-be-sent `seq` counter (diagnostic).
    fn next_seq(&self) -> u64 {
        self.inner.next_seq()
    }
}

// ────────────────────────────── Receiver ──────────────────────────────

/// UDP receiver for `pulse-wire-udp` frames.
#[pyclass(name = "Receiver")]
struct PyReceiver {
    inner: RustReceiver,
}

#[pymethods]
impl PyReceiver {
    /// Bind a receiver to `local_addr`.
    #[staticmethod]
    fn bind(local_addr: &str) -> PyResult<Self> {
        RustReceiver::bind(local_addr)
            .map(|r| Self { inner: r })
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    /// Set the underlying socket's read timeout in milliseconds.
    /// `None` (or omitted) means block forever.
    #[pyo3(signature = (millis=None))]
    fn set_read_timeout_ms(&self, millis: Option<u64>) -> PyResult<()> {
        let dur = millis.map(Duration::from_millis);
        self.inner
            .set_read_timeout(dur)
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    /// Block on the socket, decode one datagram, return
    /// `(Pulse, envelope: bytes, RecvMeta)`.
    ///
    /// Releases the GIL while blocked on `recvfrom`. Raises
    /// `TimeoutError` if a read timeout is set and elapses,
    /// `IOError` for socket errors, `ValueError` for wire-format
    /// decode failures (bad magic, CRC, etc.).
    fn recv<'py>(
        &mut self,
        py: Python<'py>,
    ) -> PyResult<(PyPulse, Bound<'py, PyBytes>, PyRecvMeta)> {
        let result = py.detach(|| self.inner.recv());
        match result {
            Ok((pulse, env, meta)) => {
                let env_py = PyBytes::new(py, &env);
                Ok((PyPulse::from(pulse), env_py, meta_to_py(meta)))
            }
            Err(e) => Err(map_receiver_err(e)),
        }
    }

    /// Receive one frame, writing the envelope payload into `buf`
    /// in place. Returns `(Pulse, env_len, RecvMeta)` where
    /// `buf[:env_len]` carries the envelope bytes.
    ///
    /// `buf` may be any Python object exposing a writable, byte-sized,
    /// 1-D contiguous buffer — e.g. `bytearray`, a `numpy.ndarray` of
    /// `dtype=uint8`, or a writable `memoryview`. The buffer must be
    /// at least as large as the incoming envelope; otherwise this
    /// raises `ValueError` and the frame is consumed.
    ///
    /// This avoids allocating a new `bytes` per packet on the Python
    /// side. Combined with NumPy: pre-allocate a buffer once, pass it
    /// to every `recv_into`, then use `buf[:n]` as a zero-copy view
    /// into the freshly written bytes.
    ///
    /// Releases the GIL while blocked on `recvfrom`. Raises
    /// `TimeoutError` on read timeout, `IOError` on socket errors,
    /// `ValueError` on wire-format / buffer-size errors,
    /// `BufferError` if `buf` is not a writable contiguous u8 buffer.
    ///
    /// The frame is received into the binding's own memory while the GIL is
    /// released, and the envelope is copied into `buf` once the GIL is held
    /// again, so no other thread writes `buf` while Rust accesses it.
    fn recv_into(
        &mut self,
        py: Python<'_>,
        buf: &Bound<'_, PyAny>,
    ) -> PyResult<(PyPulse, usize, PyRecvMeta)> {
        // Resolve `buf` to a writable, contiguous u8 buffer.
        let pybuf: PyBuffer<u8> = PyBuffer::get(buf)
            .map_err(|e| PyBufferError::new_err(format!("not a u8 buffer: {e}")))?;
        if pybuf.readonly() {
            return Err(PyBufferError::new_err("buffer is read-only"));
        }
        if !pybuf.is_c_contiguous() {
            return Err(PyBufferError::new_err("buffer is not C-contiguous"));
        }
        // An envelope larger than `buf` fails as it would into `buf`.
        let mut local = [0u8; MAX_ENVELOPE];
        let room = pybuf.item_count().min(MAX_ENVELOPE);
        let result = py.detach(|| self.inner.recv_into(&mut local[..room]));
        match result {
            Ok((pulse, env_len, meta)) => {
                let cells = pybuf.as_mut_slice(py).ok_or_else(|| {
                    PyBufferError::new_err("buffer is not a writable C-contiguous u8 buffer")
                })?;
                for (cell, &byte) in cells.iter().zip(&local[..env_len]) {
                    cell.set(byte);
                }
                Ok((PyPulse::from(pulse), env_len, meta_to_py(meta)))
            }
            Err(e) => Err(map_receiver_err(e)),
        }
    }

    /// Local socket address (`"ip:port"`) the receiver is bound to.
    fn local_addr(&self) -> PyResult<String> {
        self.inner
            .local_addr()
            .map(|a| a.to_string())
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    /// Maximum envelope payload size in bytes.
    #[staticmethod]
    fn max_envelope() -> usize {
        MAX_ENVELOPE
    }
}

// ────────────────────────────── helpers ──────────────────────────────

/// The bytes of a bytes-like object: `bytes`, `bytearray`, a `memoryview`
/// or any other C-contiguous buffer of bytes, copied.
fn bytes_like(obj: &Bound<'_, PyAny>, what: &str) -> PyResult<Vec<u8>> {
    if let Ok(bytes) = obj.cast::<PyBytes>() {
        return Ok(bytes.as_bytes().to_vec());
    }
    let buffer: PyBuffer<u8> = PyBuffer::get(obj)
        .map_err(|_| PyTypeError::new_err(format!("{what} must be a bytes-like object")))?;
    if !buffer.is_c_contiguous() {
        return Err(PyBufferError::new_err(format!(
            "{what} buffer is not C-contiguous"
        )));
    }
    buffer.to_vec(obj.py())
}

/// Exactly 16 bytes from a bytes-like object, else `ValueError`.
fn id16(obj: &Bound<'_, PyAny>, what: &str) -> PyResult<[u8; 16]> {
    let bytes = bytes_like(obj, what)?;
    <[u8; 16]>::try_from(bytes.as_slice()).map_err(|_| {
        PyValueError::new_err(format!(
            "{what} must be exactly 16 bytes (got {})",
            bytes.len()
        ))
    })
}

/// Copy the envelope in `pybuf` into `local`, holding the GIL, and return
/// the copy, so the send that follows with the GIL released reads memory
/// no other thread can write.
fn copy_envelope_out<'a>(
    py: Python<'_>,
    pybuf: &PyBuffer<u8>,
    local: &'a mut [u8; MAX_ENVELOPE],
) -> PyResult<&'a [u8]> {
    let len = pybuf.item_count();
    if len > MAX_ENVELOPE {
        return Err(PyValueError::new_err(format!(
            "envelope of {len} bytes exceeds MAX_ENVELOPE ({MAX_ENVELOPE})"
        )));
    }
    pybuf.copy_to_slice(py, &mut local[..len])?;
    Ok(&local[..len])
}

fn meta_to_py(m: RustRecvMeta) -> PyRecvMeta {
    PyRecvMeta {
        seq: m.seq,
        send_ns: m.send_ns,
        peer: m.peer.to_string(),
    }
}

fn map_sender_err(e: SenderError) -> PyErr {
    match &e {
        SenderError::Io(io) => PyIOError::new_err(io.to_string()),
        _ => PyValueError::new_err(e.to_string()),
    }
}

fn map_receiver_err(e: ReceiverError) -> PyErr {
    if e.is_timeout() {
        return PyTimeoutError::new_err(e.to_string());
    }
    match &e {
        ReceiverError::Io(io) => PyIOError::new_err(io.to_string()),
        _ => PyValueError::new_err(e.to_string()),
    }
}

/// Bind one UDP socket at `local_addr` and return a `Sender` and a
/// `Receiver` that share it, so datagrams go out from the port replies
/// come back to. A peer behind a home router (NAT) needs this: the router
/// opens a path back only to the port a datagram left from, and often only
/// for replies from the address it went to, so a program that sends and
/// receives on two sockets never hears its replies.
#[pyfunction]
fn bind_pair(local_addr: &str) -> PyResult<(PySender, PyReceiver)> {
    let socket =
        std::net::UdpSocket::bind(local_addr).map_err(|e| PyIOError::new_err(e.to_string()))?;
    let clone = socket
        .try_clone()
        .map_err(|e| PyIOError::new_err(e.to_string()))?;
    Ok((
        PySender {
            inner: RustSender::from_socket(clone),
        },
        PyReceiver {
            inner: RustReceiver::from_socket(socket),
        },
    ))
}

// ────────────────────────────── module ──────────────────────────────

// The binding copies buffer contents only while it holds the GIL, so on a
// free-threaded interpreter it keeps the GIL enabled.
#[pymodule(gil_used = true)]
fn pulse_wire(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPulse>()?;
    m.add_class::<PyInstruction>()?;
    m.add_class::<PySender>()?;
    m.add_class::<PyReceiver>()?;
    m.add_class::<PyRecvMeta>()?;
    m.add_class::<channel::PyChannel>()?;
    m.add_class::<PyEnvelope>()?;
    m.add_class::<PyEnvelopeFlags>()?;
    m.add_function(wrap_pyfunction!(bind_pair, m)?)?;
    m.add_function(wrap_pyfunction!(compute_envelope_id, m)?)?;
    m.add(
        "EnvelopeTooLarge",
        m.py().get_type::<channel::EnvelopeTooLarge>(),
    )?;
    m.add("ChannelClosed", m.py().get_type::<channel::ChannelClosed>())?;
    m.add(
        "EnvelopeDecodeError",
        m.py().get_type::<EnvelopeDecodeError>(),
    )?;
    m.add("PULSE_WIRE_SIZE", PULSE_WIRE_SIZE)?;
    m.add("MAX_ENVELOPE", MAX_ENVELOPE)?;
    m.add(
        "ENVELOPE_ID_DOMAIN_TAG",
        PyBytes::new(m.py(), ENVELOPE_ID_DOMAIN_TAG),
    )?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
