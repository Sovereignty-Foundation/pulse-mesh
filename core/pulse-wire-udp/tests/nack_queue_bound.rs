// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A NACK flood must not grow the pending queue without bound or turn a
//! single send into thousands of retransmits.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use pulse_canon::Pulse;
use pulse_wire_udp::{encode_nack, BackpressureConfig, Receiver, Sender, MAX_NACKS_PER_CYCLE};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

#[test]
fn nack_flood_is_bounded_by_the_cache_window_and_the_per_send_cap() {
    const CACHE: usize = 64;
    let receiver = Receiver::bind("127.0.0.1:0").unwrap();
    let recv_addr = receiver.local_addr().unwrap();
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    sender.connect(recv_addr).unwrap();
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut cfg = BackpressureConfig::new(any, any).with_nack(CACHE);
    cfg.target_queue_depth = 4096;
    sender.enable_backpressure(cfg).unwrap();
    let ack = sender.ack_local_addr().unwrap();

    for _ in 0..10 {
        sender.send(0, &Pulse::zeroed(), &[]).unwrap(); // seqs 0..10 cached
    }

    let inj = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = Vec::new();
    encode_nack(3, &mut buf);
    for _ in 0..10_000 {
        inj.send_to(&buf, ack).unwrap();
    }
    // Wait until the feedback thread has consumed the whole flood: the
    // drop counter must be non-zero and must stop moving.
    let start = Instant::now();
    let mut last = 0;
    let mut stable_since = Instant::now();
    loop {
        let now = sender.nack_drop_count();
        if now != last {
            last = now;
            stable_since = Instant::now();
        } else if now > 0 && stable_since.elapsed() > Duration::from_millis(300) {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "flood never settled"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        sender.nack_drop_count() > 0,
        "queue must drop beyond {CACHE} pending NACKs"
    );

    sender.send(0, &Pulse::zeroed(), &[]).unwrap();
    assert!(
        sender.retransmit_count() <= MAX_NACKS_PER_CYCLE as u64,
        "one send retransmitted {} frames",
        sender.retransmit_count()
    );
    for _ in 0..10 {
        sender.send(0, &Pulse::zeroed(), &[]).unwrap();
    }
    assert!(
        sender.retransmit_count() <= CACHE as u64,
        "retransmits exceeded the queue bound: {}",
        sender.retransmit_count()
    );
    assert_eq!(sender.cache_miss_count(), 0, "seq 3 is in the cache");
}
