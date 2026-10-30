// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Wire-format round-trip and edge-case tests for [`pulse_wire_udp::wire`].

use pulse_canon::{Instruction, Pulse};
use pulse_wire_udp::wire::{
    datagram_size, decode, encode, encode_into, WireError, HEADER_BYTES, MAGIC, MAX_ENVELOPE,
    MTU_BYTES, TRAILER_BYTES, VERSION,
};

fn sample_pulse() -> Pulse {
    let mut p = Pulse::zeroed();
    p.instruction = Instruction::Data as u16;
    p.chain_step = 7;
    p.scope = 42;
    p.monotonic_nanos = 1_234_567_890;
    p
}

#[test]
fn constants_match_design_spec() {
    // 4 (magic) + 1 (v) + 8 (seq) + 8 (send_ns) + 128 (pulse) + 4 (n) = 153
    assert_eq!(HEADER_BYTES, 153);
    assert_eq!(TRAILER_BYTES, 4);
    assert_eq!(MTU_BYTES, 1472);
    assert_eq!(MAX_ENVELOPE, 1472 - 153 - 4);
    assert_eq!(MAX_ENVELOPE, 1315);
    assert_eq!(VERSION, 1);
}

#[test]
fn magic_is_little_endian_pmsw() {
    let bytes = MAGIC.to_le_bytes();
    assert_eq!(&bytes, b"PMSW", "MAGIC should spell PMSW on the wire");
}

#[test]
fn datagram_size_grows_linearly_with_envelope() {
    assert_eq!(datagram_size(0), HEADER_BYTES + TRAILER_BYTES);
    assert_eq!(datagram_size(100), HEADER_BYTES + 100 + TRAILER_BYTES);
    assert_eq!(datagram_size(MAX_ENVELOPE), MTU_BYTES);
}

#[test]
fn round_trip_zero_envelope() {
    let p = sample_pulse();
    let buf = encode(42, 1_234_567, &p, &[]).unwrap();
    assert_eq!(buf.len(), HEADER_BYTES + TRAILER_BYTES);
    let frame = decode(&buf).unwrap();
    assert_eq!(frame.seq, 42);
    assert_eq!(frame.send_ns, 1_234_567);
    assert_eq!(frame.envelope, b"");
    let recovered = Pulse::from_bytes(&frame.pulse).unwrap();
    assert_eq!(recovered.instruction, p.instruction);
    assert_eq!(recovered.chain_step, p.chain_step);
}

#[test]
fn round_trip_small_envelope() {
    let p = sample_pulse();
    let env = b"hello world";
    let buf = encode(1, 100, &p, env).unwrap();
    let frame = decode(&buf).unwrap();
    assert_eq!(frame.envelope, env);
}

#[test]
fn round_trip_max_size_envelope() {
    let p = sample_pulse();
    let env: Vec<u8> = (0..MAX_ENVELOPE).map(|i| (i & 0xFF) as u8).collect();
    let buf = encode(0xDEAD_BEEF, 0xCAFE_BABE, &p, &env).unwrap();
    assert_eq!(buf.len(), MTU_BYTES);
    let frame = decode(&buf).unwrap();
    assert_eq!(frame.seq, 0xDEAD_BEEF);
    assert_eq!(frame.send_ns, 0xCAFE_BABE);
    assert_eq!(frame.envelope.len(), MAX_ENVELOPE);
    assert_eq!(frame.envelope, env.as_slice());
}

#[test]
fn over_max_envelope_rejected_at_encode() {
    let p = sample_pulse();
    let env = vec![0u8; MAX_ENVELOPE + 1];
    let err = encode(0, 0, &p, &env).unwrap_err();
    match err {
        WireError::EnvelopeTooLarge { got, max } => {
            assert_eq!(got, MAX_ENVELOPE + 1);
            assert_eq!(max, MAX_ENVELOPE);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn truncated_buffer_rejected_at_decode() {
    let p = sample_pulse();
    let buf = encode(1, 1, &p, b"abc").unwrap();
    let truncated = &buf[..buf.len() - 5];
    let err = decode(truncated).unwrap_err();
    // The body shrinks but `n=3` is still declared, so the decoder
    // should report InvalidEnvelopeLength (since CRC offset would
    // exceed the buffer length).
    assert!(
        matches!(
            err,
            WireError::InvalidEnvelopeLength { .. } | WireError::BufferTooSmall { .. }
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn buffer_too_small_to_hold_header_rejected() {
    let buf = vec![0u8; 10];
    let err = decode(&buf).unwrap_err();
    match err {
        WireError::BufferTooSmall { got, min } => {
            assert_eq!(got, 10);
            assert_eq!(min, HEADER_BYTES + TRAILER_BYTES);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn bad_magic_rejected() {
    let p = sample_pulse();
    let mut buf = encode(1, 1, &p, b"x").unwrap();
    buf[0] ^= 0xFF;
    let err = decode(&buf).unwrap_err();
    assert!(matches!(err, WireError::BadMagic { .. }), "got: {err:?}");
}

#[test]
fn bad_version_rejected() {
    let p = sample_pulse();
    let mut buf = encode(1, 1, &p, b"x").unwrap();
    buf[4] = 0xFE;
    let err = decode(&buf).unwrap_err();
    assert!(
        matches!(err, WireError::UnsupportedVersion { .. }),
        "got: {err:?}"
    );
}

#[test]
fn flipped_payload_byte_caught_by_crc() {
    let p = sample_pulse();
    let mut buf = encode(99, 99, &p, b"important data").unwrap();
    let env_off = HEADER_BYTES;
    buf[env_off + 3] ^= 0x01;
    let err = decode(&buf).unwrap_err();
    assert!(matches!(err, WireError::CrcMismatch { .. }), "got: {err:?}");
}

#[test]
fn flipped_seq_byte_caught_by_crc() {
    let p = sample_pulse();
    let mut buf = encode(0xAA_BB_CC_DD, 0, &p, b"x").unwrap();
    buf[5] ^= 0x80;
    let err = decode(&buf).unwrap_err();
    assert!(matches!(err, WireError::CrcMismatch { .. }), "got: {err:?}");
}

#[test]
fn declared_length_overflowing_buffer_rejected() {
    let p = sample_pulse();
    let mut buf = encode(1, 1, &p, b"abc").unwrap();
    let n_off = 4 + 1 + 8 + 8 + 128;
    buf[n_off..n_off + 4].copy_from_slice(&(MAX_ENVELOPE as u32 + 1).to_le_bytes());
    let err = decode(&buf).unwrap_err();
    assert!(
        matches!(err, WireError::InvalidEnvelopeLength { .. }),
        "got: {err:?}"
    );
}

#[test]
fn encode_into_appends_without_clearing() {
    let p = sample_pulse();
    let mut buf = vec![0xFFu8; 10];
    encode_into(7, 8, &p, b"hi", &mut buf).unwrap();
    assert_eq!(&buf[..10], &[0xFF; 10]);
    let frame = decode(&buf[10..]).unwrap();
    assert_eq!(frame.seq, 7);
    assert_eq!(frame.send_ns, 8);
    assert_eq!(frame.envelope, b"hi");
}

#[test]
fn encode_is_deterministic() {
    let p = sample_pulse();
    let a = encode(1, 2, &p, b"deterministic").unwrap();
    let b = encode(1, 2, &p, b"deterministic").unwrap();
    assert_eq!(
        a, b,
        "encode of identical inputs must produce identical bytes"
    );
}

#[test]
fn distinct_seqs_produce_distinct_crcs() {
    let p = sample_pulse();
    let a = encode(1, 0, &p, b"x").unwrap();
    let b = encode(2, 0, &p, b"x").unwrap();
    let crc_a = &a[a.len() - 4..];
    let crc_b = &b[b.len() - 4..];
    assert_ne!(crc_a, crc_b);
}
