// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! End-to-end round-trip tests over a real UDP loopback socket pair.
//! Validates that a [`Sender`] / [`Receiver`] pair can transport
//! `Pulse + envelope` end-to-end with byte-exact recovery.

use std::time::Duration;

use pulse_canon::{Instruction, Pulse};
use pulse_wire_udp::{Receiver, Sender};

fn sample_pulse(scope: u32) -> Pulse {
    let mut p = Pulse::zeroed();
    p.instruction = Instruction::Data as u16;
    p.scope = scope;
    p.chain_step = 100;
    p.monotonic_nanos = 999_999;
    p
}

fn pair() -> (Sender, Receiver) {
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    let receiver = Receiver::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let recv_addr = receiver.local_addr().unwrap();
    sender.connect(recv_addr).unwrap();
    (sender, receiver)
}

#[test]
fn round_trip_one_frame_zero_envelope() {
    let (mut sender, mut receiver) = pair();
    let pulse = sample_pulse(7);
    let seq = sender.send(0xCAFE, &pulse, &[]).unwrap();
    assert_eq!(seq, 0);
    let (recv_pulse, env, meta) = receiver.recv().unwrap();
    assert_eq!(env, b"");
    assert_eq!(meta.seq, 0);
    assert_eq!(meta.send_ns, 0xCAFE);
    assert_eq!(
        meta.sealed_by, None,
        "a plaintext datagram is sealed by nobody"
    );
    assert_eq!(recv_pulse.scope, 7);
    assert_eq!(recv_pulse.chain_step, 100);
}

#[test]
fn round_trip_small_envelope() {
    let (mut sender, mut receiver) = pair();
    let pulse = sample_pulse(8);
    let env = b"hello pulse mesh";
    let _ = sender.send(1, &pulse, env).unwrap();
    let (_, recv_env, _) = receiver.recv().unwrap();
    assert_eq!(recv_env, env);
}

#[test]
fn round_trip_max_envelope() {
    let (mut sender, mut receiver) = pair();
    let pulse = sample_pulse(9);
    let env: Vec<u8> = (0..pulse_wire_udp::MAX_ENVELOPE)
        .map(|i| ((i ^ 0xA5) & 0xFF) as u8)
        .collect();
    let _ = sender.send(2, &pulse, &env).unwrap();
    let (_, recv_env, _) = receiver.recv().unwrap();
    assert_eq!(recv_env.len(), env.len());
    assert_eq!(recv_env, env);
}

#[test]
fn over_max_envelope_returns_error_without_sending() {
    let (mut sender, _receiver) = pair();
    let pulse = sample_pulse(10);
    let env = vec![0u8; pulse_wire_udp::MAX_ENVELOPE + 1];
    let err = sender.send(0, &pulse, &env).unwrap_err();
    assert!(matches!(
        err,
        pulse_wire_udp::SenderError::Encode(pulse_wire_udp::WireError::EnvelopeTooLarge { .. })
    ));
}

#[test]
fn seq_increments_per_send() {
    let (mut sender, mut receiver) = pair();
    let pulse = sample_pulse(11);
    for i in 0..5 {
        let seq = sender.send(i, &pulse, &[]).unwrap();
        assert_eq!(seq, i);
    }
    for i in 0..5 {
        let (_, _, meta) = receiver.recv().unwrap();
        assert_eq!(meta.seq, i);
        assert_eq!(meta.send_ns, i);
    }
}

#[test]
fn many_frames_back_to_back() {
    const TOTAL: u64 = 1000;
    // Drain each burst before the next so we never rely on the kernel
    // holding hundreds of datagrams while recv is idle (Linux CI
    // default SO_RCVBUF is small; blind flood-then-drain flakes there).
    const CHUNK: u64 = 50;

    let (mut sender, mut receiver) = pair();
    let pulse = sample_pulse(12);
    let env = vec![0xDEu8; 256];
    for base in (0..TOTAL).step_by(CHUNK as usize) {
        let end = (base + CHUNK).min(TOTAL);
        for i in base..end {
            let seq = sender.send(i, &pulse, &env).unwrap();
            assert_eq!(seq, i);
        }
        for i in base..end {
            let (_, recv_env, meta) = receiver.recv().unwrap();
            assert_eq!(meta.seq, i);
            assert_eq!(meta.send_ns, i);
            assert_eq!(recv_env, env);
        }
    }
}

#[test]
fn no_destination_send_errors() {
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    let pulse = sample_pulse(13);
    let err = sender.send(0, &pulse, &[]).unwrap_err();
    assert!(matches!(err, pulse_wire_udp::SenderError::NoDestination));
}

#[test]
fn read_timeout_returns_would_block() {
    let receiver = Receiver::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let mut receiver = receiver;
    let err = receiver.recv().unwrap_err();
    assert!(err.is_timeout(), "expected timeout, got: {err:?}");
}
