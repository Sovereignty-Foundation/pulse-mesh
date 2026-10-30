// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `Pulse`, the 128-byte control signal that rings and datagrams carry
//! verbatim, and the payloads that overlay its `_pad2`.
//!
//! Only the three wire-transport opcodes (`Null` / `Heartbeat` / `Data`) are
//! defined here; the governance, oracle and execution opcodes belong to the
//! layers above Pulse Mesh in the Sovereignty stack.

use crate::envelope::PulseEnvelopeId;

/// Bytes of a `Pulse`, in memory and on every transport.
pub const PULSE_WIRE_SIZE: usize = 128;

/// Deterministic opcode carried in `Pulse.instruction`.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Instruction {
    /// 0x0000: Blank slate. Zeroed memory or empty buffer slot.
    Null = 0x0000,
    /// 0x0001: Liveness signal. `_pad2` is reinterpreted as `HeartbeatPayload`.
    Heartbeat = 0x0001,
    /// 0x0010: Generic data signal. `envelope_ref` points to a `PulseEnvelope`;
    /// `_pad2` is reinterpreted as `DataPayload`, which names its stored copy.
    Data = 0x0010,
}

impl Instruction {
    /// Convert from raw u16. Returns `Null` for any unknown opcode.
    pub fn from_u16(value: u16) -> Self {
        match value {
            0x0001 => Self::Heartbeat,
            0x0010 => Self::Data,
            _ => Self::Null,
        }
    }
}

impl std::fmt::Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Null => "NULL",
            Self::Heartbeat => "HEARTBEAT",
            Self::Data => "DATA",
        };
        f.write_str(s)
    }
}

/// The overlay of `Pulse._pad2` when `instruction == Heartbeat`: 32 bytes,
/// `#[repr(C)]`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatPayload {
    /// Opaque schema/configuration version. Compared bytewise; this layer does
    /// not interpret it.
    pub schema_version: u64,
    /// Milliseconds since node start.
    pub uptime_ms: u64,
    /// Total error count since node start.
    pub error_count: u32,
    /// Number of registered processing stages.
    pub stage_count: u16,
    /// Number of registered processing paths.
    pub path_count: u16,
    /// Errors observed in the most recent window.
    pub consecutive_errors: u16,
    /// Wake-cycle position (0-15).
    pub wake_state: u8,
    /// Health state code (0=Healthy, 1=Warning, 2=Restarting, 3=Isolated).
    pub health_state: u8,
    /// Reserved padding to bring the struct to exactly 32 bytes.
    pub _reserved: [u8; 4],
}

const _: () = {
    assert!(std::mem::size_of::<HeartbeatPayload>() == 32);
};

impl HeartbeatPayload {
    /// All-zero payload (matches the `_pad2` of a zeroed `Pulse`).
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            schema_version: 0,
            uptime_ms: 0,
            error_count: 0,
            stage_count: 0,
            path_count: 0,
            consecutive_errors: 0,
            wake_state: 0,
            health_state: 0,
            _reserved: [0; 4],
        }
    }

    /// Reinterpret as a 32-byte slice (zero-copy).
    pub fn as_bytes(&self) -> &[u8; 32] {
        // SAFETY: `#[repr(C)]` of size 32; layout-compatible with `[u8; 32]`.
        unsafe { &*(self as *const Self as *const [u8; 32]) }
    }

    /// Reinterpret 32 bytes as a payload (any 32-byte pattern is valid).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut payload = Self::zeroed();
        // SAFETY: both ends are exactly 32 bytes; only 1-byte alignment
        // is required for the raw copy.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), &mut payload as *mut Self as *mut u8, 32);
        }
        payload
    }
}

/// Where a Data pulse's envelope is stored: the overlay of `Pulse._pad2`
/// when `instruction == Data`, 32 bytes, `#[repr(C)]`. `envelope_ref` says
/// what the envelope is; the store cursor says which stored copy, since
/// envelopes with the same content share an id.
///
/// Layout, little-endian like every Pulse field: bytes 0..8 hold the cursor
/// at which the envelope store holds the copy; byte 8 is 1 when bytes 0..8
/// hold a cursor and 0 when the pulse names no stored copy; bytes 9..32
/// are reserved, zero. All zeros, the `_pad2` of a zeroed Pulse, names
/// none, and so does any value of byte 8 other than 1.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DataPayload {
    store_cursor: [u8; 8],
    has_store_cursor: u8,
    reserved: [u8; 23],
}

const _: () = {
    assert!(std::mem::size_of::<DataPayload>() == 32);
};

impl DataPayload {
    /// All zeros: names no stored copy (the `_pad2` of a zeroed `Pulse`).
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            store_cursor: [0; 8],
            has_store_cursor: 0,
            reserved: [0; 23],
        }
    }

    /// A payload naming the copy the envelope store holds at `cursor`.
    #[must_use]
    pub const fn with_store_cursor(cursor: u64) -> Self {
        Self {
            store_cursor: cursor.to_le_bytes(),
            has_store_cursor: 1,
            reserved: [0; 23],
        }
    }

    /// The store cursor this payload names, or `None` when it names none.
    #[must_use]
    pub fn store_cursor(&self) -> Option<u64> {
        (self.has_store_cursor == 1).then(|| u64::from_le_bytes(self.store_cursor))
    }

    /// The 32 bytes `_pad2` carries for this payload.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&self.store_cursor);
        bytes[8] = self.has_store_cursor;
        bytes[9..].copy_from_slice(&self.reserved);
        bytes
    }

    /// Read a payload from 32 bytes; any pattern is valid.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut store_cursor = [0u8; 8];
        store_cursor.copy_from_slice(&bytes[..8]);
        let mut reserved = [0u8; 23];
        reserved.copy_from_slice(&bytes[9..]);
        Self {
            store_cursor,
            has_store_cursor: bytes[8],
            reserved,
        }
    }
}

/// The 128-byte control signal. Its `#[repr(C, align(64))]` bytes are its
/// wire format, and the alignment keeps it off its neighbours' cache lines.
///
/// A `Pulse` is plain data: every field is an integer or a byte array, any
/// 128 bytes are a valid `Pulse`, and it is `Copy`.
#[repr(C, align(64))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Pulse {
    // --- Cache Line 1 (64 bytes) ---
    /// The first eight bytes: in a ring slot, the slot's SeqLock counter,
    /// which the ring reads and writes atomically in the slot itself; in a
    /// `Pulse` value, the counter as it was when the slot was copied, or
    /// whatever a sender's slot held. A `Pulse` value is never a live lock.
    /// [`Pulse::seq_lock`] reads it.
    seq_lock: u64,
    /// 16-byte node identifier (truncated cryptographic hash of node name/key).
    pub origin_id: [u8; 16],
    /// CLOCK_MONOTONIC nanoseconds at pulse creation.
    pub monotonic_nanos: u64,
    /// Reserved for the hash chain of a replay-defence layer that is not
    /// implemented in this release: nothing here decrements or checks it,
    /// and some carriers reuse the field (core-ring marks overruns in it).
    pub chain_step: u64,
    /// Deterministic opcode. See `Instruction`.
    pub instruction: u16,
    /// Reserved. Maintains 4-byte alignment for `scope`.
    pub _pad0: u16,
    /// Execution scope bound (path index or memory region).
    pub scope: u32,
    /// The attached envelope's content id, byte for byte, or all zeros for
    /// none ([`Pulse::envelope_id`]).
    pub envelope_ref: [u8; 16],

    // --- Cache Line 2 (64 bytes) ---
    /// 32-byte hash-chain preimage, reserved for a replay-defence layer that
    /// is not implemented in this release: nothing here reads or checks it,
    /// so a Pulse carries no replay protection yet.
    pub preimage: [u8; 32],
    /// Padding to the end of cache line 2, read as a `HeartbeatPayload`
    /// when `instruction == Heartbeat` and a `DataPayload` when
    /// `instruction == Data`.
    pub _pad2: [u8; 32],
}

const _: () = {
    assert!(std::mem::size_of::<Pulse>() == PULSE_WIRE_SIZE);
    assert!(std::mem::align_of::<Pulse>() == 64);
    assert!(std::mem::offset_of!(Pulse, seq_lock) == Pulse::SEQ_LOCK_OFFSET);
};

impl Pulse {
    /// Byte offset of the SeqLock word, [`Pulse::seq_lock`], in a Pulse's
    /// 128 bytes: it is the first 8.
    pub const SEQ_LOCK_OFFSET: usize = 0;

    /// All-zero pulse; `instruction = Null`.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            seq_lock: 0,
            origin_id: [0; 16],
            monotonic_nanos: 0,
            chain_step: 0,
            instruction: 0,
            _pad0: 0,
            scope: 0,
            envelope_ref: [0; 16],
            preimage: [0; 32],
            _pad2: [0; 32],
        }
    }

    /// A Pulse from exactly 128 bytes, `None` for any other length;
    /// [`Pulse::from_array`] takes a `[u8; 128]` and cannot fail.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; 128] = bytes.try_into().ok()?;
        Some(Self::from_array(bytes))
    }

    /// A Pulse from a 128-byte array: [`Pulse::from_bytes`] without the
    /// length check.
    #[inline]
    #[must_use]
    pub fn from_array(bytes: &[u8; 128]) -> Self {
        // SAFETY: `Pulse` is 128 bytes of integer and byte-array fields,
        // so any 128 bytes are a valid `Pulse`; `transmute` moves the value
        // into an aligned `Pulse`, whatever the alignment of `bytes`.
        unsafe { std::mem::transmute::<[u8; 128], Self>(*bytes) }
    }

    /// The Pulse's 128 bytes, without a copy.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 128] {
        // SAFETY: `Pulse` is `#[repr(C, align(64))]`, 128 bytes of integer
        // and byte-array fields with no padding between them (the size is
        // asserted above), so every byte of the view is initialised, and
        // `&self` keeps them unchanged for the borrow.
        unsafe { &*(self as *const Self as *const [u8; 128]) }
    }

    /// The SeqLock word, at byte [`Pulse::SEQ_LOCK_OFFSET`]: in a copy of a
    /// ring slot, the slot's counter when copied; in a Pulse off the wire,
    /// whatever the sender's slot held.
    #[must_use]
    pub fn seq_lock(&self) -> u64 {
        self.seq_lock
    }

    /// Typed view of the opcode.
    pub fn instruction_code(&self) -> Instruction {
        Instruction::from_u16(self.instruction)
    }

    /// True when `envelope_ref` is non-zero.
    pub fn has_envelope(&self) -> bool {
        self.envelope_ref != [0u8; 16]
    }

    /// The [`PulseEnvelopeId`] in `envelope_ref`, or `None` when it is all
    /// zeros, so an all-zero id cannot be attached.
    pub fn envelope_id(&self) -> Option<PulseEnvelopeId> {
        self.has_envelope()
            .then_some(PulseEnvelopeId(self.envelope_ref))
    }

    /// Name an envelope: write its id into `envelope_ref`. The opcode is
    /// left as it is; by convention it is [`Instruction::Data`].
    pub fn set_envelope_id(&mut self, id: &PulseEnvelopeId) {
        self.envelope_ref = id.0;
    }

    /// `Some(payload)` only when `instruction == Heartbeat`; the opcode
    /// determines the interpretation of `_pad2`.
    pub fn heartbeat_payload(&self) -> Option<HeartbeatPayload> {
        if self.instruction_code() != Instruction::Heartbeat {
            return None;
        }
        Some(HeartbeatPayload::from_bytes(&self._pad2))
    }

    /// Write a heartbeat payload into `_pad2` and set `instruction = Heartbeat`.
    pub fn set_heartbeat_payload(&mut self, payload: &HeartbeatPayload) {
        self.instruction = Instruction::Heartbeat as u16;
        self._pad2 = *payload.as_bytes();
    }

    /// `Some(payload)` only when `instruction == Data`; the opcode
    /// determines the interpretation of `_pad2`.
    pub fn data_payload(&self) -> Option<DataPayload> {
        (self.instruction_code() == Instruction::Data).then(|| DataPayload::from_bytes(&self._pad2))
    }

    /// Write a Data payload into `_pad2` and set `instruction = Data`.
    pub fn set_data_payload(&mut self, payload: &DataPayload) {
        self.instruction = Instruction::Data as u16;
        self._pad2 = payload.to_bytes();
    }

    /// The envelope-store cursor of the copy a Data pulse signals: `None`
    /// for any other instruction, and for a Data pulse that names none.
    /// See [`DataPayload`].
    pub fn store_cursor(&self) -> Option<u64> {
        self.data_payload()?.store_cursor()
    }

    /// Name the stored copy this pulse signals: write a [`DataPayload`]
    /// naming store cursor `cursor` into `_pad2` and set
    /// `instruction = Data`.
    pub fn set_store_cursor(&mut self, cursor: u64) {
        self.set_data_payload(&DataPayload::with_store_cursor(cursor));
    }
}

impl std::fmt::Debug for Pulse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pulse")
            .field("seq_lock", &self.seq_lock)
            .field("monotonic_nanos", &self.monotonic_nanos)
            .field("chain_step", &self.chain_step)
            .field("instruction", &self.instruction_code())
            .field("scope", &self.scope)
            .field("has_envelope", &self.has_envelope())
            .finish()
    }
}
