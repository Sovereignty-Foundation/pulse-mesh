// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Wire format for `pulse-wire-udp`. One UDP datagram = one [`Frame`].
//!
//! ## Layout (little-endian, no padding)
//!
//! ```text
//! +--------+----+--------+----------+----------+----+----------------+--------+
//! | magic | v | seq | send_ns | pulse | n | envelope[0..n] | crc32c |
//! | 4 B | 1B | 8 B | 8 B | 128 B | 4B | up to ~1315 B | 4 B |
//! +--------+----+--------+----------+----------+----+----------------+--------+
//! ```
//!
//! - **`magic`** = [`MAGIC`]; **`v`** = [`VERSION`].
//! - **`seq`** = the sender's sequence number.
//! - **`send_ns`** = the sender's clock in nanoseconds, as its caller gave
//!   it, for one-way latency.
//! - **`pulse`** = the 128 bytes of `Pulse::as_bytes()`.
//! - **`n`** = the envelope's length, at most [`MAX_ENVELOPE`]; then `n`
//!   opaque envelope bytes.
//! - **`crc32c`** = Castagnoli CRC over every byte before it; a frame that
//!   fails it is not delivered.
//!
//! An envelope longer than [`MAX_ENVELOPE`] does not fit a frame: a sender
//! with fragmentation on sends it as a run of fragments
//! ([`crate::fragment`]), and refuses it otherwise.

use pulse_canon::Pulse;
use pulse_canon::PULSE_WIRE_SIZE;
use pulse_canon::{EnvelopeCodecError, PulseEnvelope, PulseEnvelopeId};

/// Read N bytes at `offset` as a fixed-size array. Returns
/// [`WireError::BufferTooSmall`] if the buffer is too short.
#[inline]
fn read_array<const N: usize>(buf: &[u8], offset: usize) -> Result<[u8; N], WireError> {
    buf.get(offset..offset + N)
        .and_then(|s| <[u8; N]>::try_from(s).ok())
        .ok_or(WireError::BufferTooSmall {
            got: buf.len(),
            min: offset + N,
        })
}

/// 4-byte magic identifying a pulse-wire-udp datagram. Little-endian on
/// the wire: bytes `0x50 0x4D 0x53 0x57` = ASCII `"PMSW"`.
pub const MAGIC: u32 = 0x57534D50;

/// Wire format version. Bump on any layout-incompatible change.
pub const VERSION: u8 = 1;

/// The UDP payload this crate assumes a path carries: 1500 (Ethernet) − 20
/// (IPv4) − 8 (UDP).
pub const MTU_BYTES: usize = 1472;

/// Pre-payload header size in bytes:
/// `magic(4) + v(1) + seq(8) + send_ns(8) + pulse(128) + n(4) = 153`.
pub const HEADER_BYTES: usize = 4 + 1 + 8 + 8 + PULSE_WIRE_SIZE + 4;

/// Trailer size in bytes (CRC32C).
pub const TRAILER_BYTES: usize = 4;

/// Maximum envelope payload size in bytes that fits in one MTU-sized
/// datagram. `MTU_BYTES − HEADER_BYTES − TRAILER_BYTES = 1315`.
pub const MAX_ENVELOPE: usize = MTU_BYTES - HEADER_BYTES - TRAILER_BYTES;

#[non_exhaustive]
/// Errors returned by the encode / decode helpers.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// The buffer is shorter than a frame with no envelope,
    /// [`HEADER_BYTES`] + [`TRAILER_BYTES`].
    #[error("buffer too small: {got} bytes, need at least {min}")]
    BufferTooSmall {
        /// Bytes provided.
        got: usize,
        /// Minimum required (`HEADER_BYTES + TRAILER_BYTES`).
        min: usize,
    },
    /// The frame declares an envelope longer than [`MAX_ENVELOPE`] or than
    /// the buffer holds.
    #[error("invalid envelope length: declared {declared}, max {max}, buffer {buf}")]
    InvalidEnvelopeLength {
        /// `n` field as read from the wire.
        declared: usize,
        /// [`MAX_ENVELOPE`].
        max: usize,
        /// Bytes available in the decode buffer.
        buf: usize,
    },
    /// Magic mismatch — datagram is not a pulse-wire-udp frame.
    #[error("bad magic: got {got:#010x}, expected {expected:#010x}")]
    BadMagic {
        /// Magic bytes as read.
        got: u32,
        /// Expected [`MAGIC`].
        expected: u32,
    },
    /// Version mismatch.
    #[error("unsupported version: got {got}, expected {expected}")]
    UnsupportedVersion {
        /// Version byte as read.
        got: u8,
        /// Expected [`VERSION`].
        expected: u8,
    },
    /// CRC32C mismatch — wire-level bit-flip or mid-stream truncation;
    /// receivers count this toward loss metrics.
    #[error("crc mismatch: got {got:#010x}, computed {computed:#010x}")]
    CrcMismatch {
        /// CRC field as read from the wire.
        got: u32,
        /// CRC recomputed over the body.
        computed: u32,
    },
    /// The envelope is too large for one datagram, or, from a sender with
    /// FEC on, for its window's parity to fit one; with fragmentation on,
    /// too large for a run of fragments. Refused before anything is sent,
    /// so the caller can chunk.
    #[error("envelope too large: {got} bytes, max {max}")]
    EnvelopeTooLarge {
        /// Bytes the caller tried to encode.
        got: usize,
        /// The limit that applied: [`MAX_ENVELOPE`], or
        /// [`FEC_MAX_ENVELOPE`](crate::FEC_MAX_ENVELOPE) from a sender with
        /// FEC on.
        max: usize,
    },
    /// A fragment that disagrees with itself: an index or count out of
    /// range, a total length over [`crate::fragment::MAX_MESSAGE`], or a
    /// sequence number that is not its run's first plus its index
    /// ([`crate::fragment::decode_fragment`]).
    #[error("invalid fragment: {0}")]
    InvalidFragment(&'static str),
    /// A decoded [`Frame`]'s envelope bytes are not a canonical
    /// [`PulseEnvelope`]. Returned only by [`decode_with_envelope`].
    #[error("envelope codec error: {0}")]
    EnvelopeCodec(#[from] EnvelopeCodecError),
    /// The envelope decoded, but its content id is not the id of its type,
    /// name and payload: the frame passed its CRC, so the id is stale or
    /// forged. Returned only by [`decode_with_envelope`].
    #[error("envelope id mismatch: stored {}, computed {}", stored.to_hex(), computed.to_hex())]
    EnvelopeIdMismatch {
        /// The id carried in the envelope header.
        stored: PulseEnvelopeId,
        /// The id recomputed from the envelope's type, name and payload.
        computed: PulseEnvelopeId,
    },
}

/// A decoded datagram, borrowing its envelope from the buffer it was
/// decoded from.
#[derive(Debug, Clone, Copy)]
pub struct Frame<'a> {
    /// The sender's sequence number.
    pub seq: u64,
    /// The sender's clock in nanoseconds, as its caller gave it.
    pub send_ns: u64,
    /// 128-byte raw `Pulse` bytes; pass to [`Pulse::from_bytes`].
    pub pulse: [u8; PULSE_WIRE_SIZE],
    /// Borrowed envelope payload (length = on-wire `n`).
    pub envelope: &'a [u8],
}

/// The size of a datagram whose envelope is `envelope_len` bytes.
#[inline]
pub fn datagram_size(envelope_len: usize) -> usize {
    HEADER_BYTES + envelope_len + TRAILER_BYTES
}

/// Encode `(seq, send_ns, pulse, envelope)` into a fresh `Vec<u8>` of
/// exactly `datagram_size(envelope.len())` bytes.
///
/// # Errors
/// Returns [`WireError::EnvelopeTooLarge`] if `envelope.len() > MAX_ENVELOPE`.
pub fn encode(
    seq: u64,
    send_ns: u64,
    pulse: &Pulse,
    envelope: &[u8],
) -> Result<Vec<u8>, WireError> {
    if envelope.len() > MAX_ENVELOPE {
        return Err(WireError::EnvelopeTooLarge {
            got: envelope.len(),
            max: MAX_ENVELOPE,
        });
    }
    let mut buf = Vec::with_capacity(datagram_size(envelope.len()));
    encode_into(seq, send_ns, pulse, envelope, &mut buf)?;
    Ok(buf)
}

/// The CRC32C trailer, `crc32c(header || envelope)`, computed without
/// joining the two, so the scatter-gather send paths never copy the
/// envelope. Every path that writes or checks a trailer computes it here.
#[must_use]
pub fn frame_crc(header: &[u8], envelope: &[u8]) -> u32 {
    crc32c::crc32c_append(crc32c::crc32c(header), envelope)
}

/// Append to `out` the [`HEADER_BYTES`]-byte header of a frame with an
/// `envelope_len`-byte envelope, without the envelope or the trailer, for
/// a scatter-gather send of header, envelope and [`frame_crc`] trailer.
///
/// # Errors
/// Returns [`WireError::EnvelopeTooLarge`] if `envelope_len > MAX_ENVELOPE`.
pub fn encode_header_into(
    seq: u64,
    send_ns: u64,
    pulse: &Pulse,
    envelope_len: usize,
    out: &mut Vec<u8>,
) -> Result<(), WireError> {
    if envelope_len > MAX_ENVELOPE {
        return Err(WireError::EnvelopeTooLarge {
            got: envelope_len,
            max: MAX_ENVELOPE,
        });
    }
    out.extend_from_slice(&MAGIC.to_le_bytes());
    out.push(VERSION);
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&send_ns.to_le_bytes());
    out.extend_from_slice(pulse.as_bytes());
    out.extend_from_slice(&(envelope_len as u32).to_le_bytes());
    Ok(())
}

/// [`encode`], appending to `out`, which is not cleared, so a send loop can
/// reuse one buffer.
///
/// # Errors
/// Returns [`WireError::EnvelopeTooLarge`] if `envelope.len() > MAX_ENVELOPE`.
pub fn encode_into(
    seq: u64,
    send_ns: u64,
    pulse: &Pulse,
    envelope: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), WireError> {
    if envelope.len() > MAX_ENVELOPE {
        return Err(WireError::EnvelopeTooLarge {
            got: envelope.len(),
            max: MAX_ENVELOPE,
        });
    }
    let body_start = out.len();
    out.extend_from_slice(&MAGIC.to_le_bytes());
    out.push(VERSION);
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&send_ns.to_le_bytes());
    out.extend_from_slice(pulse.as_bytes());
    out.extend_from_slice(&(envelope.len() as u32).to_le_bytes());
    out.extend_from_slice(envelope);
    let crc = frame_crc(&out[body_start..], &[]);
    out.extend_from_slice(&crc.to_le_bytes());
    Ok(())
}

/// Decode a datagram into a [`Frame`] borrowing its envelope from `buf`,
/// checking the length, magic, version, declared envelope length and
/// CRC32C, in that order.
///
/// # Errors
/// The [`WireError`] of the first check that fails.
pub fn decode(buf: &[u8]) -> Result<Frame<'_>, WireError> {
    let min = HEADER_BYTES + TRAILER_BYTES;
    if buf.len() < min {
        return Err(WireError::BufferTooSmall {
            got: buf.len(),
            min,
        });
    }

    let magic = u32::from_le_bytes(read_array::<4>(buf, 0)?);
    if magic != MAGIC {
        return Err(WireError::BadMagic {
            got: magic,
            expected: MAGIC,
        });
    }
    let version = buf[4];
    if version != VERSION {
        return Err(WireError::UnsupportedVersion {
            got: version,
            expected: VERSION,
        });
    }

    let seq = u64::from_le_bytes(read_array::<8>(buf, 5)?);
    let send_ns = u64::from_le_bytes(read_array::<8>(buf, 13)?);

    let pulse_bytes = read_array::<PULSE_WIRE_SIZE>(buf, 21)?;
    let n_off = 21 + PULSE_WIRE_SIZE;
    let n = u32::from_le_bytes(read_array::<4>(buf, n_off)?) as usize;
    let env_off = n_off + 4;
    let env_end = env_off + n;
    let crc_off = env_end;
    let total = crc_off + TRAILER_BYTES;
    if n > MAX_ENVELOPE || total > buf.len() {
        return Err(WireError::InvalidEnvelopeLength {
            declared: n,
            max: MAX_ENVELOPE,
            buf: buf.len(),
        });
    }

    let crc_got = u32::from_le_bytes(read_array::<4>(buf, crc_off)?);
    let crc_computed = frame_crc(&buf[..crc_off], &[]);
    if crc_got != crc_computed {
        return Err(WireError::CrcMismatch {
            got: crc_got,
            computed: crc_computed,
        });
    }

    Ok(Frame {
        seq,
        send_ns,
        pulse: pulse_bytes,
        envelope: &buf[env_off..env_end],
    })
}

/// Append a frame whose envelope is `envelope`'s canonical encoding, written
/// in place: the same bytes as encoding the envelope first and passing it to
/// [`encode_into`], without the intermediate `Vec`.
///
/// ```
/// use pulse_canon::{Pulse, PulseEnvelope};
/// use pulse_wire_udp::wire::{encode_envelope_into, encode_into};
///
/// let pulse = Pulse::zeroed();
/// let envelope = PulseEnvelope::typed("jobs/new", b"first job".to_vec());
/// let (mut in_place, mut via_bytes) = (Vec::new(), Vec::new());
/// encode_envelope_into(7, 1_000, &pulse, &envelope, &mut in_place)?;
/// encode_into(7, 1_000, &pulse, &envelope.to_canonical_bytes(), &mut via_bytes)?;
/// assert_eq!(in_place, via_bytes);
/// # Ok::<(), pulse_wire_udp::wire::WireError>(())
/// ```
///
/// # Errors
///
/// [`WireError::EnvelopeTooLarge`] when `envelope.canonical_size()` exceeds
/// [`MAX_ENVELOPE`]; nothing else can fail.
pub fn encode_envelope_into(
    seq: u64,
    send_ns: u64,
    pulse: &Pulse,
    envelope: &PulseEnvelope,
    out: &mut Vec<u8>,
) -> Result<(), WireError> {
    let env_size = envelope.canonical_size();
    if env_size > MAX_ENVELOPE {
        return Err(WireError::EnvelopeTooLarge {
            got: env_size,
            max: MAX_ENVELOPE,
        });
    }
    let body_start = out.len();
    out.extend_from_slice(&MAGIC.to_le_bytes());
    out.push(VERSION);
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&send_ns.to_le_bytes());
    out.extend_from_slice(pulse.as_bytes());
    out.extend_from_slice(&(env_size as u32).to_le_bytes());
    envelope.write_canonical_into(out);
    let crc = frame_crc(&out[body_start..], &[]);
    out.extend_from_slice(&crc.to_le_bytes());
    Ok(())
}

/// [`decode`], then decode the frame's envelope as a canonical
/// [`PulseEnvelope`] and check its content id: an envelope returned always
/// passes [`PulseEnvelope::verify`].
///
/// # Errors
///
/// - Any error of [`decode`], before the envelope is looked at.
/// - [`WireError::EnvelopeCodec`] when the envelope bytes are not canonical
///   (an unknown payload tag, a malformed type-name length).
/// - [`WireError::EnvelopeIdMismatch`] when the envelope's stored id is not
///   the one its type, name and payload give.
pub fn decode_with_envelope(buf: &[u8]) -> Result<(Frame<'_>, PulseEnvelope), WireError> {
    let frame = decode(buf)?;
    let envelope = PulseEnvelope::from_canonical_bytes(frame.envelope)?;
    if !envelope.verify() {
        let computed = PulseEnvelopeId::compute_from_payload(
            envelope.envelope_type(),
            envelope.type_name(),
            envelope.payload(),
        );
        return Err(WireError::EnvelopeIdMismatch {
            stored: envelope.id(),
            computed,
        });
    }
    Ok((frame, envelope))
}

#[cfg(test)]
mod typed_envelope_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use pulse_canon::Pulse;

    #[test]
    fn typed_envelope_round_trip_through_wire() {
        let envelope = PulseEnvelope::typed("api/inference", b"hello world".to_vec());
        let pulse = Pulse::zeroed();
        let mut buf = Vec::new();
        encode_envelope_into(42, 1_000_000, &pulse, &envelope, &mut buf).expect("encode");

        let (frame, decoded_env) = decode_with_envelope(&buf).expect("decode");
        assert_eq!(frame.seq, 42);
        assert_eq!(frame.send_ns, 1_000_000);
        assert_eq!(decoded_env, envelope);
        assert!(decoded_env.verify());
    }

    /// A CRC-valid frame whose envelope's id is not its content's does not
    /// decode.
    #[test]
    fn envelope_with_forged_id_is_rejected() {
        // Forged as a sender would: canonical bytes with the id zeroed. The
        // envelope decoder checks structure only, so they decode.
        let mut forged =
            PulseEnvelope::typed("api/inference", b"hello world".to_vec()).to_canonical_bytes();
        forged[..16].fill(0);
        let envelope = PulseEnvelope::from_canonical_bytes(&forged).expect("structure intact");
        let pulse = Pulse::zeroed();
        let mut buf = Vec::new();
        encode_envelope_into(7, 1, &pulse, &envelope, &mut buf).expect("encode");
        // The frame itself is intact: the byte-level decoder accepts it.
        decode(&buf).expect("frame decodes");
        match decode_with_envelope(&buf) {
            Err(WireError::EnvelopeIdMismatch { stored, computed }) => {
                assert_eq!(stored, PulseEnvelopeId::ZERO);
                assert_ne!(computed, PulseEnvelopeId::ZERO);
            }
            other => panic!("expected EnvelopeIdMismatch, got {other:?}"),
        }
    }

    #[test]
    fn byte_identical_to_manual_canonical_encoding() {
        // One step or two, the same bytes: a sender without
        // `encode_envelope_into` produces the same frames.
        let envelope = PulseEnvelope::new(0x0010, b"PMS".repeat(20));
        let pulse = Pulse::zeroed();

        let env_bytes = envelope.to_canonical_bytes();
        let mut manual_buf = Vec::new();
        encode_into(7, 999, &pulse, &env_bytes, &mut manual_buf).expect("manual");

        let mut integrated_buf = Vec::new();
        encode_envelope_into(7, 999, &pulse, &envelope, &mut integrated_buf).expect("integrated");

        assert_eq!(manual_buf, integrated_buf);
    }

    #[test]
    fn envelope_too_large_rejected() {
        let too_big_payload = vec![0u8; MAX_ENVELOPE]; // Will exceed once envelope header is added.
        let envelope = PulseEnvelope::new(0x0001, too_big_payload);
        let pulse = Pulse::zeroed();
        let mut buf = Vec::new();
        let err = encode_envelope_into(0, 0, &pulse, &envelope, &mut buf).unwrap_err();
        match err {
            WireError::EnvelopeTooLarge { .. } => {}
            other => panic!("expected EnvelopeTooLarge, got {:?}", other),
        }
    }
}
