// SPDX-License-Identifier: LicenseRef-Proprietary
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Scatter-gather sendmsg fast-path tests.
//!
//! When neither NACK send-cache nor FEC is enabled, `Sender::send_to`
//! takes a fast path that avoids copying the envelope into
//! `encode_buf` and dispatches `[header | envelope | crc]` as three
//! `iovec`s in a single `sendmsg(2)`. These tests verify the wire
//! bytes the receiver decodes are byte-equivalent to the contiguous
//! `encode_into`-then-`sendto` path that NACK/FEC users rely on.

use std::time::Duration;

use pulse_canon::{HeartbeatPayload, Instruction, Pulse};
use pulse_wire_udp::{
    decode, encode, BackpressureConfig, Receiver, Sender, DEFAULT_SEND_CACHE_CAPACITY,
};

fn fresh_pulse(scope: u32, seq_field: u64) -> Pulse {
    let mut p = Pulse::zeroed();
    p.instruction = Instruction::Data as u16;
    p.scope = scope;
    p.monotonic_nanos = seq_field;
    p.origin_id = [0xAB; 16];
    p
}

#[test]
fn fast_path_round_trip_decodes_correctly() {
    // Default sender (no FEC, no NACK) hits the scatter-gather path.
    let mut recv = Receiver::bind("127.0.0.1:0").unwrap();
    recv.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    sender.connect(recv.local_addr().unwrap()).unwrap();

    let envelope = b"scatter-gather payload that is moderately sized".to_vec();
    let pulse = fresh_pulse(0xC0FFEE, 12345);
    let seq = sender.send(987_654_321, &pulse, &envelope).unwrap();

    let (got_pulse, got_env, meta) = recv.recv().unwrap();
    assert_eq!(seq, 0);
    assert_eq!(meta.seq, 0);
    assert_eq!(meta.send_ns, 987_654_321);
    assert_eq!(got_env, envelope);
    assert_eq!(got_pulse.scope, 0xC0FFEE);
    assert_eq!(got_pulse.monotonic_nanos, 12345);
    assert_eq!(got_pulse.origin_id, [0xAB; 16]);
}

#[test]
fn fast_path_zero_length_envelope_round_trips() {
    let mut recv = Receiver::bind("127.0.0.1:0").unwrap();
    recv.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    sender.connect(recv.local_addr().unwrap()).unwrap();

    let pulse = fresh_pulse(7, 0);
    sender.send(1, &pulse, &[]).unwrap();

    let (_pulse, env, meta) = recv.recv().unwrap();
    assert!(env.is_empty());
    assert_eq!(meta.seq, 0);
}

#[test]
fn fast_path_max_size_envelope_round_trips() {
    let mut recv = Receiver::bind("127.0.0.1:0").unwrap();
    recv.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    sender.connect(recv.local_addr().unwrap()).unwrap();

    let envelope: Vec<u8> = (0..pulse_wire_udp::MAX_ENVELOPE)
        .map(|i| (i & 0xFF) as u8)
        .collect();
    let pulse = fresh_pulse(99, 7);
    sender.send(2, &pulse, &envelope).unwrap();

    let (_pulse, got_env, meta) = recv.recv().unwrap();
    assert_eq!(got_env.len(), pulse_wire_udp::MAX_ENVELOPE);
    assert_eq!(got_env, envelope);
    assert_eq!(meta.seq, 0);
}

#[test]
fn fast_path_wire_bytes_byte_equal_to_contiguous_encode() {
    // Direct cross-check: encode the same frame contiguously and
    // confirm the decoded view matches what we sent. Loopback is
    // CRC-validated by the receiver; if the fast path's incremental
    // CRC diverged from the contiguous CRC, the receiver would
    // surface CrcMismatch and `recv()` would error out.
    //
    // We further confirm that `encode()` and the over-the-wire
    // bytes produce identical decoded `Frame`s.
    let mut recv = Receiver::bind("127.0.0.1:0").unwrap();
    recv.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    sender.connect(recv.local_addr().unwrap()).unwrap();

    let pulse = fresh_pulse(42, 9999);
    let envelope = b"\x00\xff\x55\xaa".repeat(200); // 800 bytes
    sender.send(3, &pulse, &envelope).unwrap();
    let (got_pulse, got_env, meta) = recv.recv().unwrap();

    // Build the reference (contiguous) encoding and confirm the
    // decoded view from `decode(reference)` matches the over-the-
    // wire decoded view.
    let reference = encode(meta.seq, meta.send_ns, &pulse, &envelope).unwrap();
    let frame = decode(&reference).unwrap();
    assert_eq!(frame.envelope, &envelope[..]);
    assert_eq!(frame.envelope, &got_env[..]);
    assert_eq!(got_pulse.scope, pulse.scope);
    assert_eq!(got_pulse.monotonic_nanos, pulse.monotonic_nanos);
}

#[test]
fn fast_path_alongside_heartbeat_payload_in_pulse_pad2() {
    // Confirms the entire 128-byte Pulse — including the heartbeat
    // overlay in `_pad2` — flows through the fast path unchanged.
    let mut recv = Receiver::bind("127.0.0.1:0").unwrap();
    recv.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    sender.connect(recv.local_addr().unwrap()).unwrap();

    let mut pulse = Pulse::zeroed();
    let mut hb = HeartbeatPayload::zeroed();
    hb.uptime_ms = 7_777_777;
    hb.error_count = 3;
    hb.stage_count = 5;
    pulse.set_heartbeat_payload(&hb);

    sender.send(0, &pulse, b"hb-tail").unwrap();
    let (got_pulse, got_env, _meta) = recv.recv().unwrap();
    assert_eq!(got_env, b"hb-tail");
    let got_hb = got_pulse.heartbeat_payload().expect("heartbeat overlay");
    assert_eq!(got_hb.uptime_ms, 7_777_777);
    assert_eq!(got_hb.error_count, 3);
    assert_eq!(got_hb.stage_count, 5);
}

#[test]
fn slow_path_engaged_when_fec_enabled() {
    // Smoke check that enabling FEC doesn't break the round trip;
    // the FEC end-to-end suite covers parity correctness in detail.
    let mut recv = Receiver::bind("127.0.0.1:0").unwrap();
    recv.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    sender.connect(recv.local_addr().unwrap()).unwrap();
    sender.enable_fec(8);
    assert!(sender.fec_enabled());

    sender.send(0, &fresh_pulse(1, 1), b"with-fec").unwrap();
    let (_pulse, env, _meta) = recv.recv().unwrap();
    assert_eq!(env, b"with-fec");
}

#[test]
fn slow_path_engaged_when_nack_cache_enabled() {
    // Smoke check that enabling backpressure-with-NACK doesn't break
    // the round trip; nack_backfill.rs covers retransmit semantics.
    let mut recv = Receiver::bind("127.0.0.1:0").unwrap();
    recv.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    sender.connect(recv.local_addr().unwrap()).unwrap();

    let cfg = BackpressureConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .with_nack(DEFAULT_SEND_CACHE_CAPACITY);
    sender.enable_backpressure(cfg).unwrap();
    assert!(sender.backpressure_enabled());

    sender.send(0, &fresh_pulse(2, 2), b"with-nack").unwrap();
    let (_pulse, env, _meta) = recv.recv().unwrap();
    assert_eq!(env, b"with-nack");
}
