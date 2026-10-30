// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Setting backpressure up: enabling it again, and feedback over IPv6.
//!
//! A second `Sender::enable_backpressure` reconfigures the running
//! backpressure in place: the socket carries over when the address is the
//! one it holds, so a fixed `ack_bind_addr` can be given again, another
//! address is bound before anything changes, and the cursor and the
//! counters carry over either way. The receiver binds its feedback socket
//! in the target's family, so feedback reaches an IPv6 sender.

use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use pulse_canon::Pulse;
use pulse_wire_udp::{encode_ack, BackpressureConfig, Receiver, Sender, SenderError};

fn any_loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn wait_for(mut cond: impl FnMut() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(2) {
        if cond() {
            return true;
        }
        thread::sleep(Duration::from_millis(2));
    }
    cond()
}

/// Send an ACK carrying `cursor` to `feedback` from a socket of its own.
fn inject_ack(feedback: SocketAddr, cursor: u64) {
    let injector = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut ack = Vec::new();
    encode_ack(cursor, &mut ack);
    injector.send_to(&ack, feedback).unwrap();
}

/// A sender whose data goes to a socket that never acknowledges anything.
fn sender_to_a_sink() -> (Sender, UdpSocket) {
    let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    sender.connect(sink.local_addr().unwrap()).unwrap();
    (sender, sink)
}

#[test]
fn a_fixed_feedback_address_can_be_given_again() {
    // A fixed port: learn a free one, then ask for it by number.
    let fixed = UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let (mut sender, _sink) = sender_to_a_sink();
    let mut cfg = BackpressureConfig::new(fixed, any_loopback())
        .with_stall_timeout(Some(Duration::from_millis(300)))
        .with_feedback_peer(IpAddr::V6(Ipv6Addr::LOCALHOST));
    cfg.target_queue_depth = 2;
    sender.enable_backpressure(cfg.clone()).unwrap();
    assert_eq!(sender.ack_local_addr(), Some(fixed));
    // The filter names an address no loopback socket here has: counted.
    inject_ack(fixed, 3);
    assert!(wait_for(|| sender.feedback_rejected_count() == 1));

    // The same address again, with a deeper queue and no filter.
    let mut changed = cfg.clone();
    changed.target_queue_depth = 4;
    changed.feedback_peer = None;
    sender
        .enable_backpressure(changed)
        .unwrap_or_else(|e| panic!("enabling backpressure again on {fixed} failed: {e}"));
    assert_eq!(sender.ack_local_addr(), Some(fixed));
    assert_eq!(
        sender.feedback_rejected_count(),
        1,
        "the counters carry over"
    );

    // ACKs still reach the socket, now from anyone, and the new depth
    // applies: with the cursor at 5, frames 0 to 8 go and the tenth stalls.
    inject_ack(fixed, 5);
    assert!(wait_for(|| sender.observed_recv_cursor() == 5));
    for seq in 0..9u64 {
        assert_eq!(sender.send(0, &Pulse::zeroed(), &[]).unwrap(), seq);
    }
    match sender.send(0, &Pulse::zeroed(), &[]) {
        Err(SenderError::Stalled { in_flight: 4, .. }) => {}
        other => panic!("expected a stall at the new depth, got {other:?}"),
    }

    // And the cursor carries over too.
    sender.enable_backpressure(cfg).unwrap();
    assert_eq!(sender.observed_recv_cursor(), 5);
}

#[test]
fn another_address_moves_the_socket_and_a_failed_bind_changes_nothing() {
    let (mut sender, _sink) = sender_to_a_sink();
    let cfg = BackpressureConfig::new(any_loopback(), any_loopback());
    sender.enable_backpressure(cfg.clone()).unwrap();
    let first = sender.ack_local_addr().unwrap();
    inject_ack(first, 2);
    assert!(wait_for(|| sender.observed_recv_cursor() == 2));

    // Port 0 again is another address: a new socket, the cursor kept.
    sender.enable_backpressure(cfg.clone()).unwrap();
    let second = sender.ack_local_addr().unwrap();
    assert_ne!(second, first);
    assert_eq!(sender.observed_recv_cursor(), 2);
    inject_ack(second, 4);
    assert!(wait_for(|| sender.observed_recv_cursor() == 4));

    // An address another socket holds cannot be bound, and nothing changes.
    let squatter = UdpSocket::bind("127.0.0.1:0").unwrap();
    let taken = BackpressureConfig::new(squatter.local_addr().unwrap(), any_loopback());
    match sender.enable_backpressure(taken) {
        Err(SenderError::Io(e)) if e.kind() == std::io::ErrorKind::AddrInUse => {}
        other => panic!("expected AddrInUse, got {other:?}"),
    }
    assert_eq!(sender.ack_local_addr(), Some(second));
    inject_ack(second, 6);
    assert!(
        wait_for(|| sender.observed_recv_cursor() == 6),
        "the running feedback thread stopped listening"
    );

    // Switched off, the sender no longer stalls or listens.
    sender.disable_backpressure();
    assert!(!sender.backpressure_enabled());
    assert_eq!(sender.ack_local_addr(), None);
    for _ in 0..64 {
        sender.send(0, &Pulse::zeroed(), &[]).unwrap();
    }
}

#[test]
fn receiver_feedback_reaches_an_ipv6_sender() {
    let mut receiver = Receiver::bind("[::1]:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut sender = Sender::bind("[::1]:0").unwrap();
    sender.connect(receiver.local_addr().unwrap()).unwrap();
    let any_v6: SocketAddr = "[::1]:0".parse().unwrap();
    let mut cfg = BackpressureConfig::new(any_v6, any_v6);
    cfg.target_queue_depth = 4;
    sender.enable_backpressure(cfg.clone()).unwrap();
    cfg.ack_target_addr = sender.ack_local_addr().unwrap();
    assert!(cfg.ack_target_addr.is_ipv6());
    receiver
        .enable_backpressure(cfg)
        .unwrap_or_else(|e| panic!("feedback to an IPv6 address failed: {e}"));

    // More frames than the depth: they go only because the receiver's ACKs
    // reach the sender over IPv6.
    for seq in 0..16u64 {
        assert_eq!(sender.send(0, &Pulse::zeroed(), &[]).unwrap(), seq);
        assert_eq!(receiver.recv().unwrap().2.seq, seq);
    }
    assert!(wait_for(|| sender.observed_recv_cursor() == 16));
    assert_eq!(receiver.feedback_error_count(), 0);
}
