// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A gap wider than the sender's retransmit cache must not make the
//! receiver stage or scan an unbounded range, even for a sequence number
//! near `u64::MAX`. A lone frame that far ahead, beyond the horizon, moves
//! nothing at all; a jump the next frame confirms resynchronises the head
//! to the recoverable window; and either way the call returns promptly.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use pulse_canon::Pulse;
use pulse_wire_udp::{wire, BackpressureConfig, Receiver, Sender};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

#[test]
fn huge_gap_resyncs_instead_of_staging_every_seq() {
    const CACHE: usize = 64;
    let mut receiver = Receiver::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let recv_addr = receiver.local_addr().unwrap();
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    sender.connect(recv_addr).unwrap();
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut cfg = BackpressureConfig::new(any, any).with_nack(CACHE);
    cfg.ack_period = Duration::from_millis(20);
    cfg.target_queue_depth = 4096;
    sender.enable_backpressure(cfg.clone()).unwrap();
    cfg.ack_target_addr = sender.ack_local_addr().unwrap();
    receiver.enable_backpressure(cfg).unwrap();

    sender.send(0, &Pulse::zeroed(), &[]).unwrap();
    sender.send(1, &Pulse::zeroed(), &[]).unwrap();
    receiver.recv().unwrap();
    receiver.recv().unwrap();
    assert_eq!(receiver.contiguous_head(), 2);

    let injector = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = Vec::with_capacity(wire::MTU_BYTES);
    for first in [1_000_000u64, u64::MAX - 9] {
        let head = receiver.contiguous_head();
        for seq in [first, first + 1] {
            buf.clear();
            wire::encode_into(seq, 7, &Pulse::zeroed(), &[], &mut buf).unwrap();
            injector.send_to(&buf, recv_addr).unwrap();
            let started = Instant::now();
            receiver.recv().unwrap();
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "receiving seq {seq} took {:?}: gap staging is not bounded",
                started.elapsed()
            );
            if seq == first {
                assert_eq!(
                    receiver.contiguous_head(),
                    head,
                    "a lone frame moved the head"
                );
            }
        }
        assert_eq!(
            receiver.contiguous_head(),
            first + 1 - CACHE as u64,
            "head resynced to the window"
        );
    }
    assert_eq!(receiver.gap_resyncs(), 2);
    assert_eq!(
        receiver.beyond_horizon_count(),
        2,
        "the first frame of each jump moved nothing"
    );
    std::thread::sleep(Duration::from_millis(80));
    assert!(
        receiver.nacks_sent() <= 2 * CACHE as u64,
        "NACKs bounded by the window: {}",
        receiver.nacks_sent()
    );
}
