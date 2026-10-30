// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `PulseEnvelope`, the variable-size payload a Pulse names, addressed by
//! its content id ([`PulseEnvelopeId`]), and its canonical codec.

/// The `len` bytes of `buf` at `offset`, or
/// [`EnvelopeCodecError::Truncated`] if the slice runs short. Checked: on a
/// 32-bit target a declared length near `u32::MAX` would wrap the end.
#[inline]
fn read_slice<'a>(
    buf: &'a [u8],
    offset: usize,
    len: usize,
    field: &'static str,
) -> Result<&'a [u8], EnvelopeCodecError> {
    offset
        .checked_add(len)
        .and_then(|end| buf.get(offset..end))
        .ok_or(EnvelopeCodecError::Truncated { field, offset })
}

/// Read N bytes at `offset` as a fixed-size array, or
/// [`EnvelopeCodecError::Truncated`] if the slice runs short.
#[inline]
fn read_array<const N: usize>(
    buf: &[u8],
    offset: usize,
    field: &'static str,
) -> Result<[u8; N], EnvelopeCodecError> {
    read_slice(buf, offset, N, field).and_then(|s| {
        <[u8; N]>::try_from(s).map_err(|_| EnvelopeCodecError::Truncated { field, offset })
    })
}

/// Domain-separation tag that starts every envelope-id preimage, so an
/// envelope id never coincides with another truncated BLAKE3 identifier
/// (such as [`crate::NodeId`]); its revision suffix changes with the
/// preimage framing.
pub const ENVELOPE_ID_DOMAIN_TAG: &[u8] = b"pulse-envelope-id/v2";

/// An envelope's 16-byte content id: the first 16 bytes of the BLAKE3 hash
/// of its type, type name and payload ([`Self::compute_from_payload`] gives
/// the preimage). Envelopes with the same content share an id; the origin,
/// time and flags are not hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PulseEnvelopeId(pub [u8; 16]);

impl PulseEnvelopeId {
    /// All zeros: no envelope.
    pub const ZERO: Self = Self([0u8; 16]);

    /// The id of an envelope with no type name and a raw payload:
    /// `compute_from_payload(envelope_type, None,
    /// &PayloadData::Raw(payload.to_vec()))` without the copy.
    pub fn compute(envelope_type: u16, payload: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        Self::write_preimage(
            &mut hasher,
            envelope_type,
            None,
            PAYLOAD_VARIANT_RAW,
            payload,
        );
        Self::from_hash(hasher.finalize())
    }

    /// The id of an envelope with this type, type name and payload, as the
    /// constructors compute it. The preimage, integers little-endian:
    ///
    /// ```text
    /// | domain tag | et:u16 | tn?:u8 | tn_len:u32 | tn_bytes |
    ///                       | pv:u8 | pl_len:u32 | pl_bytes |
    /// ```
    ///
    /// The lengths, and the presence and variant tags of the canonical
    /// encoding, keep distinct envelopes' preimages apart: without them a
    /// type name's end could slide into the payload, and `Raw([0; 4])`
    /// would hash as `Nested([])`.
    pub fn compute_from_payload(
        envelope_type: u16,
        type_name: Option<&str>,
        payload: &PayloadData,
    ) -> Self {
        let variant = match payload {
            PayloadData::Raw(_) => PAYLOAD_VARIANT_RAW,
            PayloadData::Nested(_) => PAYLOAD_VARIANT_NESTED,
        };
        let mut hasher = blake3::Hasher::new();
        Self::write_preimage(
            &mut hasher,
            envelope_type,
            type_name,
            variant,
            &payload.to_bytes(),
        );
        Self::from_hash(hasher.finalize())
    }

    /// The preimage encoder behind both `compute*` functions.
    fn write_preimage(
        hasher: &mut blake3::Hasher,
        envelope_type: u16,
        type_name: Option<&str>,
        payload_variant: u8,
        payload_bytes: &[u8],
    ) {
        hasher.update(ENVELOPE_ID_DOMAIN_TAG);
        hasher.update(&envelope_type.to_le_bytes());
        match type_name {
            None => {
                hasher.update(&[0u8]);
            }
            Some(name) => {
                hasher.update(&[1u8]);
                hasher.update(&(name.len() as u32).to_le_bytes());
                hasher.update(name.as_bytes());
            }
        }
        hasher.update(&[payload_variant]);
        hasher.update(&(payload_bytes.len() as u32).to_le_bytes());
        hasher.update(payload_bytes);
    }

    fn from_hash(hash: blake3::Hash) -> Self {
        let mut id = [0u8; 16];
        id.copy_from_slice(&hash.as_bytes()[..16]);
        Self(id)
    }

    /// True when every byte of the ID is zero.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 16]
    }

    /// Lowercase hexadecimal rendering (32 chars).
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl std::fmt::Display for PulseEnvelopeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

bitflags::bitflags! {
    /// Routing and behaviour flags for `PulseEnvelope`: bits 0 to 3 of the
    /// canonical flags word. Bits 4 to 15 are reserved: encoders must not
    /// set them, and the decoder refuses them
    /// ([`EnvelopeCodecError::UnknownFlags`]).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct PulseEnvelopeFlags: u16 {
        /// Fan out to all listeners (vs. point-to-point delivery).
        const BROADCAST    = 0b0000_0001;
        /// Sender expects an ack from the receiver.
        const ACK_REQUIRED = 0b0000_0010;
        /// Schedule with elevated priority.
        const PRIORITY     = 0b0000_0100;
        /// Payload is compressed (codec out of scope for the wire layer).
        const COMPRESSED   = 0b0000_1000;
    }
}

impl Default for PulseEnvelopeFlags {
    fn default() -> Self {
        Self::empty()
    }
}

/// An envelope's payload: opaque bytes, or a sequence of envelopes (for
/// batches, bundles and audit chains).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PayloadData {
    /// Opaque byte payload; `to_bytes()` returns it verbatim.
    Raw(Vec<u8>),
    /// Recursive payload — zero or more nested [`PulseEnvelope`]s.
    Nested(Vec<PulseEnvelope>),
}

impl PayloadData {
    /// The payload's bytes, as the id and the canonical encoding take them:
    ///
    /// - `Raw(b)` → `b` verbatim.
    /// - `Nested(envs)` → `count:u32_le ‖ env₀.canonical_bytes ‖ env₁.canonical_bytes ‖ …`.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Raw(bytes) => bytes.clone(),
            Self::Nested(envelopes) => {
                let mut out = Vec::new();
                out.extend_from_slice(&(envelopes.len() as u32).to_le_bytes());
                for env in envelopes {
                    env.write_canonical_into(&mut out);
                }
                out
            }
        }
    }

    /// Byte length of the serialized payload as returned by [`Self::to_bytes`].
    pub fn byte_len(&self) -> usize {
        match self {
            Self::Raw(bytes) => bytes.len(),
            Self::Nested(envelopes) => {
                4 + envelopes.iter().map(|e| e.canonical_size()).sum::<usize>()
            }
        }
    }

    /// Borrow the raw bytes, or `None` if this is `Nested`.
    pub fn as_raw(&self) -> Option<&[u8]> {
        match self {
            Self::Raw(bytes) => Some(bytes),
            Self::Nested(_) => None,
        }
    }

    /// Borrow the nested envelopes, or `None` if this is `Raw`.
    pub fn as_nested(&self) -> Option<&[PulseEnvelope]> {
        match self {
            Self::Raw(_) => None,
            Self::Nested(envelopes) => Some(envelopes),
        }
    }

    /// True for `Raw`.
    pub fn is_raw(&self) -> bool {
        matches!(self, Self::Raw(_))
    }

    /// True for `Nested`.
    pub fn is_nested(&self) -> bool {
        matches!(self, Self::Nested(_))
    }
}

/// Canonical wire-format variant tag byte for [`PayloadData::Raw`].
pub const PAYLOAD_VARIANT_RAW: u8 = 0;

/// Canonical wire-format variant tag byte for [`PayloadData::Nested`].
pub const PAYLOAD_VARIANT_NESTED: u8 = 1;

impl Default for PayloadData {
    fn default() -> Self {
        Self::Raw(Vec::new())
    }
}

impl From<Vec<u8>> for PayloadData {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Raw(bytes)
    }
}

impl From<&[u8]> for PayloadData {
    fn from(bytes: &[u8]) -> Self {
        Self::Raw(bytes.to_vec())
    }
}

/// A variable-size, content-addressed payload. The content (the type, the
/// type name and the payload) and its id are private and set together, so
/// an envelope built in Rust carries its content's id. One decoded from
/// canonical bytes carries the id the bytes stated, which [`Self::verify`]
/// checks (chapter 3.5 of the specification); with the `serde` feature, a
/// deserialized envelope is refused unless its id is its content's.
/// Equality compares ids alone.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "EnvelopeFields"))]
pub struct PulseEnvelope {
    id: PulseEnvelopeId,
    /// Origin node identifier; not hashed into the id.
    pub origin: [u8; 16],
    /// `CLOCK_MONOTONIC` nanoseconds at creation, set by the producer; not
    /// hashed into the id.
    pub monotonic_nanos: u64,
    envelope_type: u16,
    type_name: Option<String>,
    /// Routing and behaviour flags; not hashed into the id.
    pub flags: PulseEnvelopeFlags,
    payload: PayloadData,
}

/// A serialized [`PulseEnvelope`]'s fields, which become one only when the
/// id they carry is their content's.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct EnvelopeFields {
    id: PulseEnvelopeId,
    origin: [u8; 16],
    monotonic_nanos: u64,
    envelope_type: u16,
    type_name: Option<String>,
    flags: PulseEnvelopeFlags,
    payload: PayloadData,
}

#[cfg(feature = "serde")]
impl TryFrom<EnvelopeFields> for PulseEnvelope {
    type Error = String;

    fn try_from(fields: EnvelopeFields) -> Result<Self, String> {
        let mut envelope =
            Self::with_content(fields.envelope_type, fields.type_name, fields.payload);
        if envelope.id != fields.id {
            return Err(format!(
                "envelope id {} is not the id of its content, {}",
                fields.id, envelope.id
            ));
        }
        envelope.origin = fields.origin;
        envelope.monotonic_nanos = fields.monotonic_nanos;
        envelope.flags = fields.flags;
        Ok(envelope)
    }
}

impl PartialEq for PulseEnvelope {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for PulseEnvelope {}

impl PulseEnvelope {
    /// Build an envelope from its content, a numeric type, an optional type
    /// name and a payload, with the id computed from the three. The origin,
    /// the time and the flags start empty.
    pub fn with_content(
        envelope_type: u16,
        type_name: Option<String>,
        payload: impl Into<PayloadData>,
    ) -> Self {
        let payload = payload.into();
        let id =
            PulseEnvelopeId::compute_from_payload(envelope_type, type_name.as_deref(), &payload);
        Self {
            id,
            origin: [0u8; 16],
            monotonic_nanos: 0,
            envelope_type,
            type_name,
            flags: PulseEnvelopeFlags::empty(),
            payload,
        }
    }

    /// Build an envelope with a numeric type and no type name.
    pub fn new(envelope_type: u16, payload: impl Into<PayloadData>) -> Self {
        Self::with_content(envelope_type, None, payload)
    }

    /// Build an envelope routed by string `type_name`; `envelope_type = 0`.
    pub fn typed(type_name: impl Into<String>, payload: impl Into<PayloadData>) -> Self {
        Self::with_content(0, Some(type_name.into()), payload)
    }

    /// Build an envelope with an explicit origin node identifier.
    pub fn with_origin(
        envelope_type: u16,
        payload: impl Into<PayloadData>,
        origin: [u8; 16],
    ) -> Self {
        let mut env = Self::new(envelope_type, payload);
        env.origin = origin;
        env
    }

    /// Build a broadcast envelope (`BROADCAST` flag set).
    pub fn broadcast(envelope_type: u16, payload: impl Into<PayloadData>) -> Self {
        let mut env = Self::new(envelope_type, payload);
        env.flags |= PulseEnvelopeFlags::BROADCAST;
        env
    }

    /// Build a typed broadcast envelope (`BROADCAST` flag set).
    pub fn typed_broadcast(type_name: impl Into<String>, payload: impl Into<PayloadData>) -> Self {
        let mut env = Self::typed(type_name, payload);
        env.flags |= PulseEnvelopeFlags::BROADCAST;
        env
    }

    /// The content id: computed from the type, the type name and the
    /// payload, except in an envelope decoded from canonical bytes, which
    /// carries the id the bytes stated until [`Self::verify`] checks it.
    pub fn id(&self) -> PulseEnvelopeId {
        self.id
    }

    /// The numeric envelope type.
    pub fn envelope_type(&self) -> u16 {
        self.envelope_type
    }

    /// The string routing key (e.g. `"trace/event"`), if the envelope has one.
    pub fn type_name(&self) -> Option<&str> {
        self.type_name.as_deref()
    }

    /// The payload.
    pub fn payload(&self) -> &PayloadData {
        &self.payload
    }

    /// The payload, taken out of the envelope.
    pub fn into_payload(self) -> PayloadData {
        self.payload
    }

    /// True when the stored id matches one freshly computed over the type,
    /// the type name and the payload.
    pub fn verify(&self) -> bool {
        let expected = PulseEnvelopeId::compute_from_payload(
            self.envelope_type,
            self.type_name.as_deref(),
            &self.payload,
        );
        self.id == expected
    }

    /// Effective routing key: `type_name` if set, else `0xNNNN`.
    pub fn effective_type_name(&self) -> String {
        self.type_name
            .clone()
            .unwrap_or_else(|| format!("0x{:04x}", self.envelope_type))
    }

    /// Payload length in bytes.
    pub fn payload_len(&self) -> usize {
        self.payload.byte_len()
    }

    /// The length of [`Self::to_canonical_bytes`].
    pub fn canonical_size(&self) -> usize {
        let type_name_section = match &self.type_name {
            None => 1,
            Some(s) => 1 + 4 + s.len(),
        };
        let payload_section = match &self.payload {
            PayloadData::Raw(bytes) => 1 + 4 + bytes.len(),
            PayloadData::Nested(envelopes) => {
                1 + 4 + envelopes.iter().map(|e| e.canonical_size()).sum::<usize>()
            }
        };
        CANONICAL_FIXED_HEADER + type_name_section + payload_section
    }

    /// The envelope's canonical bytes, all little-endian, no padding:
    ///
    /// ```text
    /// | id:16 | origin:16 | mono_ns:u64 | et:u16 | flg:u16 |       (44 B fixed)
    /// | tn?:u8 | tn_len:u32 | tn_bytes:tn_len |                    (1 + 4 + L if Some)
    /// | variant:u8 | <variant data> |                              (variant-specific)
    ///
    /// variant=0 (Raw):    | payload_len:u32 | payload_bytes:n |
    /// variant=1 (Nested): | count:u32 | child_canonical_bytes... |
    /// ```
    ///
    /// This is the cross-language wire format (chapter 3 of the
    /// specification); a change to it needs a new wire-format version.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.canonical_size());
        self.write_canonical_into(&mut out);
        out
    }

    /// Append the canonical encoding to `out`.
    pub fn write_canonical_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.id.0);
        out.extend_from_slice(&self.origin);
        out.extend_from_slice(&self.monotonic_nanos.to_le_bytes());
        out.extend_from_slice(&self.envelope_type.to_le_bytes());
        out.extend_from_slice(&self.flags.bits().to_le_bytes());

        match &self.type_name {
            None => {
                out.push(0u8);
            }
            Some(s) => {
                out.push(1u8);
                out.extend_from_slice(&(s.len() as u32).to_le_bytes());
                out.extend_from_slice(s.as_bytes());
            }
        }

        match &self.payload {
            PayloadData::Raw(bytes) => {
                out.push(PAYLOAD_VARIANT_RAW);
                out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                out.extend_from_slice(bytes);
            }
            PayloadData::Nested(envelopes) => {
                out.push(PAYLOAD_VARIANT_NESTED);
                out.extend_from_slice(&(envelopes.len() as u32).to_le_bytes());
                for env in envelopes {
                    env.write_canonical_into(out);
                }
            }
        }
    }

    /// Decode exactly one envelope's canonical bytes, the inverse of
    /// [`Self::to_canonical_bytes`]: an envelope this returns re-encodes to
    /// `buf` byte for byte, since anything the encoder would not have
    /// written is refused, not normalised. Checks structure only; call
    /// [`Self::verify`] to check the id. [`Self::decode_canonical_at`]
    /// reads an envelope from the front of a longer buffer.
    ///
    /// # Errors
    /// [`EnvelopeCodecError`] when the buffer is too short or malformed,
    /// sets a reserved flag bit ([`EnvelopeCodecError::UnknownFlags`]), or
    /// has bytes after the envelope ([`EnvelopeCodecError::TrailingBytes`]).
    pub fn from_canonical_bytes(buf: &[u8]) -> Result<Self, EnvelopeCodecError> {
        let (env, used) = Self::decode_canonical_at(buf, 0)?;
        if used != buf.len() {
            return Err(EnvelopeCodecError::TrailingBytes {
                used,
                len: buf.len(),
            });
        }
        Ok(env)
    }

    /// Decode the envelope that starts at `buf[start]`, returning it with the
    /// offset just past it. The bytes between are exactly its canonical
    /// bytes, as in [`Self::from_canonical_bytes`]; bytes after it are left
    /// alone.
    ///
    /// # Errors
    /// [`EnvelopeCodecError`] on any structural fault, and
    /// [`EnvelopeCodecError::UnknownFlags`] when the envelope's flags word,
    /// or a nested child's, sets a reserved bit.
    pub fn decode_canonical_at(
        buf: &[u8],
        start: usize,
    ) -> Result<(Self, usize), EnvelopeCodecError> {
        Self::decode_canonical_at_depth(buf, start, 0)
    }

    /// [`Self::decode_canonical_at`] with the current nesting depth, so a
    /// crafted buffer cannot recurse past [`MAX_NESTING_DEPTH`].
    fn decode_canonical_at_depth(
        buf: &[u8],
        start: usize,
        depth: usize,
    ) -> Result<(Self, usize), EnvelopeCodecError> {
        // The smallest envelope, MIN_CANONICAL_ENVELOPE.
        let min = CANONICAL_FIXED_HEADER + 1 + 1 + 4;
        if start.checked_add(min).is_none_or(|need| buf.len() < need) {
            return Err(EnvelopeCodecError::BufferTooSmall {
                got: buf.len().saturating_sub(start),
                min,
            });
        }

        let id = read_array::<16>(buf, start, "id")?;
        let origin = read_array::<16>(buf, start + 16, "origin")?;
        let monotonic_nanos =
            u64::from_le_bytes(read_array::<8>(buf, start + 32, "monotonic_nanos")?);
        let envelope_type = u16::from_le_bytes(read_array::<2>(buf, start + 40, "envelope_type")?);
        let flags_bits = u16::from_le_bytes(read_array::<2>(buf, start + 42, "flags")?);
        // Refused, not dropped: dropping would decode two byte strings to
        // one envelope.
        let flags = PulseEnvelopeFlags::from_bits(flags_bits)
            .ok_or(EnvelopeCodecError::UnknownFlags { flags: flags_bits })?;

        let mut cursor = start + CANONICAL_FIXED_HEADER;
        let presence = *buf.get(cursor).ok_or(EnvelopeCodecError::Truncated {
            field: "type_name_presence",
            offset: cursor,
        })?;
        cursor += 1;
        let type_name = match presence {
            0 => None,
            1 => {
                let len =
                    u32::from_le_bytes(read_array::<4>(buf, cursor, "type_name_len")?) as usize;
                cursor += 4;
                let name_bytes = read_slice(buf, cursor, len, "type_name")?;
                let s = std::str::from_utf8(name_bytes)
                    .map_err(|_| EnvelopeCodecError::InvalidTypeName)?;
                cursor += len;
                Some(s.to_string())
            }
            tag => {
                return Err(EnvelopeCodecError::InvalidTypeNameTag { tag });
            }
        };

        let variant = *buf.get(cursor).ok_or(EnvelopeCodecError::Truncated {
            field: "payload_variant_tag",
            offset: cursor,
        })?;
        cursor += 1;

        let payload = match variant {
            PAYLOAD_VARIANT_RAW => {
                let payload_len =
                    u32::from_le_bytes(read_array::<4>(buf, cursor, "payload_len")?) as usize;
                cursor += 4;
                let payload_bytes = read_slice(buf, cursor, payload_len, "payload")?;
                let bytes = payload_bytes.to_vec();
                cursor += payload_len;
                PayloadData::Raw(bytes)
            }
            PAYLOAD_VARIANT_NESTED => {
                let count =
                    u32::from_le_bytes(read_array::<4>(buf, cursor, "nested_count")?) as usize;
                cursor += 4;
                // Bounded before anything is allocated: a count from the
                // wire must never size an allocation on its own.
                let available = buf.len().saturating_sub(cursor);
                let max = available / MIN_CANONICAL_ENVELOPE;
                if count > max {
                    return Err(EnvelopeCodecError::NestedCountExceedsBuffer {
                        count,
                        available,
                        max,
                    });
                }
                if depth >= MAX_NESTING_DEPTH {
                    return Err(EnvelopeCodecError::NestingTooDeep {
                        max: MAX_NESTING_DEPTH,
                    });
                }
                // Collected as they decode, not reserved for `count`: every
                // level of a nest bounds its count by the same remaining
                // bytes, so reserving at each level multiplies the memory
                // by the depth (`tests/decode_memory.rs`).
                let mut envelopes = Vec::new();
                for child_index in 0..count {
                    match Self::decode_canonical_at_depth(buf, cursor, depth + 1) {
                        Ok((env, next_cursor)) => {
                            cursor = next_cursor;
                            envelopes.push(env);
                        }
                        Err(cause) => {
                            return Err(EnvelopeCodecError::NestedDecode {
                                child_index,
                                cause: Box::new(cause),
                            });
                        }
                    }
                }
                PayloadData::Nested(envelopes)
            }
            tag => {
                return Err(EnvelopeCodecError::InvalidPayloadVariantTag { tag });
            }
        };

        let env = Self {
            id: PulseEnvelopeId(id),
            origin,
            monotonic_nanos,
            envelope_type,
            type_name,
            flags,
            payload,
        };
        Ok((env, cursor))
    }
}

/// Smallest canonical envelope: the fixed prefix, an absent-name tag, a
/// variant tag and a 4-byte length or count with nothing after it.
pub const MIN_CANONICAL_ENVELOPE: usize = CANONICAL_FIXED_HEADER + 1 + 1 + 4;

/// Deepest nesting the decoder accepts
/// ([`EnvelopeCodecError::NestingTooDeep`]), to keep decoding untrusted
/// bytes stack-safe.
pub const MAX_NESTING_DEPTH: usize = 32;

/// Bytes in the fixed canonical prefix
/// (`id` + `origin` + `monotonic_nanos` + `envelope_type` + `flags`).
pub const CANONICAL_FIXED_HEADER: usize = 16 + 16 + 8 + 2 + 2;

/// Decode errors for the canonical wire codec.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeCodecError {
    /// Buffer shorter than the fixed-header + minimum tail.
    BufferTooSmall {
        /// Bytes provided.
        got: usize,
        /// Minimum required.
        min: usize,
    },
    /// A length-prefixed field declared more bytes than `buf` contained.
    Truncated {
        /// Field that ran out of bytes.
        field: &'static str,
        /// Offset where decoding stopped.
        offset: usize,
    },
    /// `type_name` presence tag was neither 0 (None) nor 1 (Some).
    InvalidTypeNameTag {
        /// The bad tag byte.
        tag: u8,
    },
    /// `type_name` bytes were present but not valid UTF-8.
    InvalidTypeName,
    /// A nested payload declares more children than the remaining bytes can
    /// hold, at [`MIN_CANONICAL_ENVELOPE`] bytes each.
    NestedCountExceedsBuffer {
        /// Declared child count.
        count: usize,
        /// Bytes remaining after the count field.
        available: usize,
        /// Largest count those bytes could hold.
        max: usize,
    },
    /// Nesting deeper than [`MAX_NESTING_DEPTH`], which the format itself
    /// does not limit.
    NestingTooDeep {
        /// [`MAX_NESTING_DEPTH`].
        max: usize,
    },
    /// Payload variant tag was neither [`PAYLOAD_VARIANT_RAW`] nor
    /// [`PAYLOAD_VARIANT_NESTED`].
    InvalidPayloadVariantTag {
        /// The bad tag byte.
        tag: u8,
    },
    /// A nested child failed to decode.
    NestedDecode {
        /// Index of the failing child within the parent's sequence.
        child_index: usize,
        /// Recursive cause from the child's decode.
        cause: Box<EnvelopeCodecError>,
    },
    /// The flags word sets a bit no [`PulseEnvelopeFlags`] flag defines.
    UnknownFlags {
        /// The flags word as read.
        flags: u16,
    },
    /// [`PulseEnvelope::from_canonical_bytes`] was given bytes after the
    /// envelope.
    TrailingBytes {
        /// Bytes the envelope spans.
        used: usize,
        /// Bytes given.
        len: usize,
    },
}

impl std::fmt::Display for EnvelopeCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferTooSmall { got, min } => {
                write!(f, "buffer too small: {got} bytes, need at least {min}")
            }
            Self::Truncated { field, offset } => {
                write!(f, "truncated at field '{field}', offset {offset}")
            }
            Self::InvalidTypeNameTag { tag } => {
                write!(f, "invalid type_name presence tag: {tag} (expected 0 or 1)")
            }
            Self::InvalidTypeName => write!(f, "type_name bytes are not valid UTF-8"),
            Self::InvalidPayloadVariantTag { tag } => write!(
                f,
                "invalid payload variant tag: {tag} (expected 0=Raw or 1=Nested)"
            ),
            Self::NestedCountExceedsBuffer {
                count,
                available,
                max,
            } => write!(
                f,
                "nested count {count} exceeds what {available} remaining bytes can hold ({max} max)"
            ),
            Self::NestingTooDeep { max } => {
                write!(f, "nested envelopes exceed the maximum depth of {max}")
            }
            Self::NestedDecode { child_index, cause } => write!(
                f,
                "nested envelope at index {child_index} failed to decode: {cause}"
            ),
            Self::UnknownFlags { flags } => write!(
                f,
                "flags word {flags:#06x} sets reserved bits {:#06x}",
                flags & !PulseEnvelopeFlags::all().bits()
            ),
            Self::TrailingBytes { used, len } => write!(
                f,
                "{len} bytes given, but the envelope ends after {used}; canonical bytes carry nothing after the envelope"
            ),
        }
    }
}

impl std::error::Error for EnvelopeCodecError {}

#[cfg(test)]
mod canonical_codec_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn round_trip_minimum_envelope() {
        let env = PulseEnvelope::new(0x0001, b"hello".to_vec());
        let bytes = env.to_canonical_bytes();
        let decoded = PulseEnvelope::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(decoded, env);
        assert_eq!(decoded.payload.as_raw(), Some(&b"hello"[..]));
        assert!(decoded.verify());
    }

    #[test]
    fn round_trip_with_type_name() {
        let env = PulseEnvelope::typed("trace/event", b"payload".to_vec());
        let bytes = env.to_canonical_bytes();
        let decoded = PulseEnvelope::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(decoded, env);
        assert_eq!(decoded.type_name.as_deref(), Some("trace/event"));
        assert!(decoded.verify());
    }

    #[test]
    fn round_trip_with_origin_and_flags() {
        let mut env = PulseEnvelope::with_origin(0x0042, b"".to_vec(), [0xAB; 16]);
        env.flags = PulseEnvelopeFlags::BROADCAST | PulseEnvelopeFlags::PRIORITY;
        env.monotonic_nanos = 1_234_567_890;
        let bytes = env.to_canonical_bytes();
        let decoded = PulseEnvelope::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(decoded.origin, [0xAB; 16]);
        assert!(decoded.flags.contains(PulseEnvelopeFlags::BROADCAST));
        assert!(decoded.flags.contains(PulseEnvelopeFlags::PRIORITY));
        assert_eq!(decoded.monotonic_nanos, 1_234_567_890);
    }

    #[test]
    fn canonical_size_matches_encoded_length() {
        let env = PulseEnvelope::typed("api/inference", b"x".repeat(900));
        assert_eq!(env.canonical_size(), env.to_canonical_bytes().len());
    }

    #[test]
    fn empty_payload_round_trip() {
        let env = PulseEnvelope::new(0x0010, Vec::<u8>::new());
        let bytes = env.to_canonical_bytes();
        let decoded = PulseEnvelope::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(decoded.payload.byte_len(), 0);
        assert_eq!(decoded, env);
    }

    #[test]
    fn buffer_too_small_rejected() {
        let too_small = vec![0u8; CANONICAL_FIXED_HEADER]; // 44 — missing tags + lengths
        let err = PulseEnvelope::from_canonical_bytes(&too_small).unwrap_err();
        match err {
            EnvelopeCodecError::BufferTooSmall { .. } => {}
            other => panic!("expected BufferTooSmall, got {:?}", other),
        }
    }

    #[test]
    fn truncated_payload_rejected() {
        let env = PulseEnvelope::new(0x0001, b"hello".to_vec());
        let mut bytes = env.to_canonical_bytes();
        bytes.truncate(bytes.len() - 2); // chop the last two bytes of payload
        let err = PulseEnvelope::from_canonical_bytes(&bytes).unwrap_err();
        match err {
            EnvelopeCodecError::Truncated {
                field: "payload", ..
            } => {}
            other => panic!("expected Truncated{{field=\"payload\"}}, got {:?}", other),
        }
    }

    #[test]
    fn invalid_type_name_tag_rejected() {
        let env = PulseEnvelope::new(0x0001, b"x".to_vec());
        let mut bytes = env.to_canonical_bytes();
        // Corrupt the presence tag at offset 44 (CANONICAL_FIXED_HEADER).
        bytes[CANONICAL_FIXED_HEADER] = 99;
        let err = PulseEnvelope::from_canonical_bytes(&bytes).unwrap_err();
        match err {
            EnvelopeCodecError::InvalidTypeNameTag { tag: 99 } => {}
            other => panic!("expected InvalidTypeNameTag, got {:?}", other),
        }
    }

    #[test]
    fn invalid_payload_variant_tag_rejected() {
        let env = PulseEnvelope::new(0x0001, b"hi".to_vec());
        let mut bytes = env.to_canonical_bytes();
        // type_name presence at offset 44 = None (0); payload variant at offset 45.
        bytes[45] = 99;
        let err = PulseEnvelope::from_canonical_bytes(&bytes).unwrap_err();
        match err {
            EnvelopeCodecError::InvalidPayloadVariantTag { tag: 99 } => {}
            other => panic!("expected InvalidPayloadVariantTag, got {:?}", other),
        }
    }

    /// Each of the sixteen flag bits alone: a defined flag decodes and
    /// re-encodes to the same bytes; a reserved bit is refused.
    #[test]
    fn reserved_flag_bits_are_refused_not_dropped() {
        let env = PulseEnvelope::new(0x0001, b"x".to_vec());
        let defined = PulseEnvelopeFlags::all().bits();
        for bit in 0..16 {
            let flags = 1u16 << bit;
            let mut bytes = env.to_canonical_bytes();
            bytes[42..44].copy_from_slice(&flags.to_le_bytes());
            let got = PulseEnvelope::from_canonical_bytes(&bytes);
            if flags & defined != 0 {
                let decoded = got.expect("a defined flag decodes");
                assert_eq!(decoded.flags.bits(), flags);
                assert_eq!(decoded.to_canonical_bytes(), bytes);
            } else {
                assert_eq!(got.unwrap_err(), EnvelopeCodecError::UnknownFlags { flags });
            }
        }
        // Defined flags alongside a reserved one are refused as well.
        let mut bytes = env.to_canonical_bytes();
        bytes[42..44].copy_from_slice(&0x0105u16.to_le_bytes());
        assert_eq!(
            PulseEnvelope::from_canonical_bytes(&bytes).unwrap_err(),
            EnvelopeCodecError::UnknownFlags { flags: 0x0105 }
        );
    }

    #[test]
    fn a_reserved_flag_bit_in_a_nested_child_is_refused() {
        let child = PulseEnvelope::new(0x0001, b"leaf".to_vec());
        let parent = PulseEnvelope::new(0x0050, PayloadData::Nested(vec![child]));
        let mut bytes = parent.to_canonical_bytes();
        // The child follows the parent's fixed header, its absent-name tag,
        // its variant tag and its count: MIN_CANONICAL_ENVELOPE bytes.
        let child_flags = MIN_CANONICAL_ENVELOPE + 42;
        bytes[child_flags..child_flags + 2].copy_from_slice(&0x8000u16.to_le_bytes());
        match PulseEnvelope::from_canonical_bytes(&bytes) {
            Err(EnvelopeCodecError::NestedDecode {
                child_index: 0,
                cause,
            }) => assert_eq!(*cause, EnvelopeCodecError::UnknownFlags { flags: 0x8000 }),
            other => panic!("expected the child's reserved bit refused, got {other:?}"),
        }
    }

    #[test]
    fn bytes_after_the_envelope_are_refused_by_from_canonical_bytes() {
        let env = PulseEnvelope::typed("trace/event", b"payload".to_vec());
        let bytes = env.to_canonical_bytes();
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(
            PulseEnvelope::from_canonical_bytes(&longer).unwrap_err(),
            EnvelopeCodecError::TrailingBytes {
                used: bytes.len(),
                len: longer.len(),
            }
        );
        // `decode_canonical_at` reads the envelope at the front and says
        // where it ends; the bytes it spans re-encode to themselves.
        let (decoded, used) = PulseEnvelope::decode_canonical_at(&longer, 0).expect("the prefix");
        assert_eq!(used, bytes.len());
        assert_eq!(decoded.to_canonical_bytes(), bytes);
    }

    #[test]
    fn a_start_at_or_past_the_end_is_refused_without_overflow() {
        let bytes = PulseEnvelope::new(1, b"x".to_vec()).to_canonical_bytes();
        for start in [bytes.len(), bytes.len() + 1, usize::MAX - 10, usize::MAX] {
            match PulseEnvelope::decode_canonical_at(&bytes, start) {
                Err(EnvelopeCodecError::BufferTooSmall { got: 0, min }) => {
                    assert_eq!(min, MIN_CANONICAL_ENVELOPE);
                }
                other => panic!("start {start}: expected BufferTooSmall, got {other:?}"),
            }
        }
    }

    /// Hard-coded canonical bytes for a known envelope. If this test starts
    /// failing, the codec layout changed — that is a wire-incompatible
    /// change and requires a version bump.
    #[test]
    fn canonical_layout_is_stable_for_a_known_envelope() {
        // Construct a deterministic envelope: zero origin, zero monotonic,
        // numeric type 0x0001, no type_name, payload = [0x42, 0x42, 0x42, 0x42].
        let env = PulseEnvelope::new(0x0001, vec![0x42, 0x42, 0x42, 0x42]);
        let bytes = env.to_canonical_bytes();

        // Expected layout (54 bytes):
        //   [0..16]  id (BLAKE3 of the length-prefixed preimage, truncated)
        //   [16..32] origin = all zeros
        //   [32..40] monotonic_nanos = 0
        //   [40..42] envelope_type = 0x0001
        //   [42..44] flags = 0
        //   [44]     type_name presence = 0
        //   [45]     payload variant tag = 0 (Raw)
        //   [46..50] payload_len = 4
        //   [50..54] payload = [0x42 0x42 0x42 0x42]
        assert_eq!(bytes.len(), 54);
        assert_eq!(&bytes[16..32], &[0u8; 16][..]); // origin
        assert_eq!(&bytes[32..40], &[0u8; 8][..]); // monotonic_nanos
        assert_eq!(&bytes[40..42], &[0x01, 0x00][..]); // envelope_type LE
        assert_eq!(&bytes[42..44], &[0x00, 0x00][..]); // flags
        assert_eq!(bytes[44], 0); // type_name presence = None
        assert_eq!(bytes[45], PAYLOAD_VARIANT_RAW); // payload variant = Raw
        assert_eq!(&bytes[46..50], &[0x04, 0x00, 0x00, 0x00][..]); // payload_len = 4 LE
        assert_eq!(&bytes[50..54], &[0x42, 0x42, 0x42, 0x42][..]); // payload

        // Round-trip and verify integrity.
        let decoded = PulseEnvelope::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(decoded, env);
        assert!(decoded.verify());
    }

    // ─────────────────────────────────────────────────────────────────
    //  Nested(Vec<PulseEnvelope>) — recursive composition tests
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn nested_empty_round_trips() {
        let mut env = PulseEnvelope::new(0x0050, b"unused".to_vec());
        env.payload = PayloadData::Nested(Vec::new());
        env.id = PulseEnvelopeId::compute_from_payload(
            env.envelope_type,
            env.type_name.as_deref(),
            &env.payload,
        );

        let bytes = env.to_canonical_bytes();
        let decoded = PulseEnvelope::from_canonical_bytes(&bytes).expect("decode");
        assert!(decoded.payload.is_nested());
        assert_eq!(decoded.payload.as_nested().unwrap().len(), 0);
        assert_eq!(decoded, env);
    }

    #[test]
    fn nested_single_child_round_trips() {
        let child = PulseEnvelope::new(0x0001, b"child payload".to_vec());
        let mut parent = PulseEnvelope::new(0x0050, b"unused".to_vec());
        parent.payload = PayloadData::Nested(vec![child.clone()]);
        parent.id = PulseEnvelopeId::compute_from_payload(
            parent.envelope_type,
            parent.type_name.as_deref(),
            &parent.payload,
        );

        let bytes = parent.to_canonical_bytes();
        let decoded = PulseEnvelope::from_canonical_bytes(&bytes).expect("decode");
        assert!(decoded.payload.is_nested());
        let children = decoded.payload.as_nested().unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0], child);
        assert!(decoded.verify());
    }

    #[test]
    fn nested_multiple_children_preserve_order() {
        let children: Vec<PulseEnvelope> = (0..5)
            .map(|i| PulseEnvelope::new(0x0010 + i as u16, vec![i as u8; (i + 1) as usize * 4]))
            .collect();
        let mut parent = PulseEnvelope::typed("batch/audit-chain", b"unused".to_vec());
        parent.payload = PayloadData::Nested(children.clone());
        parent.id = PulseEnvelopeId::compute_from_payload(
            parent.envelope_type,
            parent.type_name.as_deref(),
            &parent.payload,
        );

        let bytes = parent.to_canonical_bytes();
        let decoded = PulseEnvelope::from_canonical_bytes(&bytes).expect("decode");
        let decoded_children = decoded.payload.as_nested().unwrap();
        assert_eq!(decoded_children.len(), 5);
        for (i, child) in decoded_children.iter().enumerate() {
            assert_eq!(child, &children[i]);
        }
        assert!(decoded.verify());
    }

    #[test]
    fn nested_supports_recursion() {
        // Three-level nesting: outer contains inner_a contains leaf, plus
        // inner_b is a Raw sibling.
        let leaf = PulseEnvelope::new(0x0001, b"leaf".to_vec());
        let mut inner_a = PulseEnvelope::new(0x0050, b"unused".to_vec());
        inner_a.payload = PayloadData::Nested(vec![leaf.clone()]);
        inner_a.id =
            PulseEnvelopeId::compute_from_payload(inner_a.envelope_type, None, &inner_a.payload);

        let inner_b = PulseEnvelope::new(0x0002, b"sibling".to_vec());

        let mut outer = PulseEnvelope::new(0x0050, b"unused".to_vec());
        outer.payload = PayloadData::Nested(vec![inner_a.clone(), inner_b.clone()]);
        outer.id = PulseEnvelopeId::compute_from_payload(outer.envelope_type, None, &outer.payload);

        let bytes = outer.to_canonical_bytes();
        let decoded = PulseEnvelope::from_canonical_bytes(&bytes).expect("decode");
        let level1 = decoded.payload.as_nested().unwrap();
        assert_eq!(level1.len(), 2);
        assert_eq!(level1[0], inner_a);
        assert_eq!(level1[1], inner_b);

        // Drill into the recursive child.
        let level2 = level1[0].payload.as_nested().unwrap();
        assert_eq!(level2.len(), 1);
        assert_eq!(level2[0], leaf);

        assert!(decoded.verify());
    }

    #[test]
    fn nested_canonical_size_matches_encoded_length() {
        let children = vec![
            PulseEnvelope::new(1, b"a".to_vec()),
            PulseEnvelope::typed("trace/event", b"event payload".to_vec()),
            PulseEnvelope::new(2, vec![0u8; 100]),
        ];
        let mut parent = PulseEnvelope::new(0x0050, Vec::new());
        parent.payload = PayloadData::Nested(children);
        parent.id =
            PulseEnvelopeId::compute_from_payload(parent.envelope_type, None, &parent.payload);

        assert_eq!(parent.canonical_size(), parent.to_canonical_bytes().len());
    }

    #[test]
    fn nested_decode_error_surfaces_child_index() {
        let leaf = PulseEnvelope::new(0x0001, b"leaf".to_vec());
        let mut parent = PulseEnvelope::new(0x0050, Vec::new());
        parent.payload = PayloadData::Nested(vec![leaf.clone(), leaf.clone()]);
        parent.id =
            PulseEnvelopeId::compute_from_payload(parent.envelope_type, None, &parent.payload);

        let mut bytes = parent.to_canonical_bytes();
        // Corrupt deep inside the second nested child by truncating the
        // buffer so the second child can't fully decode.
        bytes.truncate(bytes.len() - 5);

        let err = PulseEnvelope::from_canonical_bytes(&bytes).unwrap_err();
        match err {
            EnvelopeCodecError::NestedDecode { child_index: 1, .. } => {}
            other => panic!("expected NestedDecode at child_index=1, got {:?}", other),
        }
    }
}

#[cfg(test)]
mod envelope_id_preimage_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    /// The `type_name`/`payload` boundary must not slide: without lengths
    /// in the preimage both of these would hash the same bytes, and, since
    /// equality compares ids, the two envelopes would compare equal.
    #[test]
    fn type_name_payload_boundary_is_unambiguous() {
        let a = PulseEnvelopeId::compute_from_payload(
            0,
            Some("trace/event"),
            &PayloadData::Raw(b"X".to_vec()),
        );
        let b = PulseEnvelopeId::compute_from_payload(
            0,
            Some("trace/eventX"),
            &PayloadData::Raw(Vec::new()),
        );
        assert_ne!(a, b, "type_name/payload boundary slid: shared preimage");

        // The same defect stated as its user-visible consequence.
        let env_a = PulseEnvelope::typed("trace/event", b"X".to_vec());
        let env_b = PulseEnvelope::typed("trace/eventX", Vec::new());
        assert_ne!(env_a, env_b, "distinct envelopes compared equal");
    }

    /// Lengths alone are not enough: `Raw([0; 4])` and `Nested([])` both
    /// serialize to four zero bytes, so only the payload variant tag keeps
    /// their preimages apart.
    #[test]
    fn raw_and_nested_payload_variants_do_not_collide() {
        let raw = PayloadData::Raw(vec![0, 0, 0, 0]);
        let nested = PayloadData::Nested(Vec::new());
        assert_eq!(
            raw.to_bytes(),
            nested.to_bytes(),
            "precondition: the two payloads serialize identically"
        );

        let a = PulseEnvelopeId::compute_from_payload(1, None, &raw);
        let b = PulseEnvelopeId::compute_from_payload(1, None, &nested);
        assert_ne!(a, b, "Raw and Nested payloads shared a preimage");
    }

    /// An absent `type_name` must not hash like an empty one.
    #[test]
    fn absent_type_name_differs_from_empty_type_name() {
        let payload = PayloadData::Raw(b"body".to_vec());
        let absent = PulseEnvelopeId::compute_from_payload(7, None, &payload);
        let empty = PulseEnvelopeId::compute_from_payload(7, Some(""), &payload);
        assert_ne!(absent, empty);
    }

    /// The two public entry points share one preimage encoder, so a raw
    /// byte payload computes the same ID through either. `math_anchor`'s
    /// SIG-C13 anchor depends on this; keeping the assertion here means a
    /// future edit to one function fails fast in the crate's own suite.
    #[test]
    fn compute_agrees_with_compute_from_payload_for_raw() {
        let payload = vec![0x42, 0x42, 0x42, 0x42];
        assert_eq!(
            PulseEnvelopeId::compute(0x0001, &payload),
            PulseEnvelopeId::compute_from_payload(0x0001, None, &PayloadData::Raw(payload.clone())),
        );
        assert_eq!(
            PulseEnvelopeId::compute(0x0001, &payload),
            PulseEnvelope::new(0x0001, payload).id,
        );
    }

    #[test]
    fn nested_count_is_bounded_by_the_buffer() {
        // Fixed prefix + type_name absent + Nested variant + count = u32::MAX,
        // followed by nothing: the count can never be satisfied and must be
        // rejected before any allocation happens.
        let mut buf = vec![0u8; CANONICAL_FIXED_HEADER];
        buf.push(0); // type_name absent
        buf.push(PAYLOAD_VARIANT_NESTED);
        buf.extend_from_slice(&u32::MAX.to_le_bytes());
        match PulseEnvelope::from_canonical_bytes(&buf) {
            Err(EnvelopeCodecError::NestedCountExceedsBuffer { count, max, .. }) => {
                assert_eq!(count, u32::MAX as usize);
                assert_eq!(max, 0);
            }
            other => panic!("expected NestedCountExceedsBuffer, got {other:?}"),
        }
    }

    fn nested_chain(levels: usize) -> PulseEnvelope {
        let mut env = PulseEnvelope::new(0x0010, PayloadData::Raw(vec![0xaa]));
        for _ in 0..levels {
            env = PulseEnvelope::new(0x0020, PayloadData::Nested(vec![env]));
        }
        env
    }

    #[test]
    fn nesting_depth_is_bounded() {
        // MAX_NESTING_DEPTH nested payloads (leaf below them) decode; one more does not.
        let ok = nested_chain(MAX_NESTING_DEPTH).to_canonical_bytes();
        assert!(PulseEnvelope::from_canonical_bytes(&ok).is_ok());
        let too_deep = nested_chain(MAX_NESTING_DEPTH + 1).to_canonical_bytes();
        let err = PulseEnvelope::from_canonical_bytes(&too_deep).unwrap_err();
        fn innermost(e: &EnvelopeCodecError) -> &EnvelopeCodecError {
            match e {
                EnvelopeCodecError::NestedDecode { cause, .. } => innermost(cause),
                other => other,
            }
        }
        assert!(
            matches!(innermost(&err), EnvelopeCodecError::NestingTooDeep { max } if *max == MAX_NESTING_DEPTH),
            "got {err:?}"
        );
    }
}

/// With the `serde` feature an envelope round-trips through serde, and one
/// whose id is not its content's does not deserialize.
#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn sample() -> PulseEnvelope {
        let child = PulseEnvelope::typed("trace/event", b"child".to_vec());
        let mut env = PulseEnvelope::with_content(
            0x0007,
            Some("a/b".into()),
            PayloadData::Nested(vec![child]),
        );
        env.origin = [9; 16];
        env.monotonic_nanos = 42;
        env.flags = PulseEnvelopeFlags::BROADCAST;
        env
    }

    #[test]
    fn an_envelope_round_trips() {
        let env = sample();
        let back: PulseEnvelope =
            serde_json::from_str(&serde_json::to_string(&env).unwrap()).unwrap();
        assert_eq!(back.to_canonical_bytes(), env.to_canonical_bytes());
    }

    #[test]
    fn changed_content_under_the_old_id_is_refused() {
        let mut json = serde_json::to_value(sample()).unwrap();
        json["envelope_type"] = serde_json::json!(8);
        let err = serde_json::from_value::<PulseEnvelope>(json).unwrap_err();
        assert!(
            err.to_string().contains("is not the id of its content"),
            "{err}"
        );
    }

    #[test]
    fn a_nested_child_with_a_false_id_is_refused() {
        let mut json = serde_json::to_value(sample()).unwrap();
        json["payload"]["Nested"][0]["payload"] = serde_json::json!({ "Raw": [1, 2, 3] });
        let err = serde_json::from_value::<PulseEnvelope>(json).unwrap_err();
        assert!(
            err.to_string().contains("is not the id of its content"),
            "{err}"
        );
    }
}
