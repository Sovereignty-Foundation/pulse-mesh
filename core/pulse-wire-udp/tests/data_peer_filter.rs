// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! The receiver's data socket only takes datagrams from the named peer.
//!
//! Without a filter any host that can reach the data socket can inject
//! frames and parity. With `with_data_peer` set, datagrams from any other
//! source IP are dropped before they are decoded and counted. The loopback
//! senders here all bind 127.0.0.1, so the rejecting cases name the IPv6
//! loopback instead, which never matches; on Linux, where all of 127/8 is
//! loopback, a second address also sends forged frames among the peer's.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use pulse_canon::Pulse;
use pulse_wire_udp::{Receiver, Sender, MAX_ENVELOPE};

fn receiver_for(peer: IpAddr) -> Receiver {
    let receiver = Receiver::bind("127.0.0.1:0").unwrap().with_data_peer(peer);
    receiver
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    receiver
}

#[test]
fn frames_from_the_named_peer_are_taken() {
    let mut receiver = receiver_for(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    sender.connect(receiver.local_addr().unwrap()).unwrap();
    for seq in 0..3u64 {
        sender.send(0, &Pulse::zeroed(), b"peer").unwrap();
        let (_, envelope, meta) = receiver.recv().unwrap();
        assert_eq!((meta.seq, envelope.as_slice()), (seq, &b"peer"[..]));
    }
    assert_eq!(receiver.data_rejected_count(), 0);
}

#[test]
fn frames_and_parity_from_another_address_are_dropped_and_counted() {
    let mut receiver = receiver_for(IpAddr::V6(Ipv6Addr::LOCALHOST));
    receiver.enable_fec(4, 8);
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    sender.connect(receiver.local_addr().unwrap()).unwrap();
    sender.enable_fec(4);
    // Four frames and their window's parity.
    for _ in 0..4 {
        sender.send(0, &Pulse::zeroed(), b"stranger").unwrap();
    }
    match receiver.recv() {
        Err(e) if e.is_timeout() => {}
        other => panic!("a datagram from another address was taken: {other:?}"),
    }
    assert_eq!(receiver.data_rejected_count(), 5);
    assert_eq!(receiver.parity_received_count(), 0, "parity was decoded");

    // The batch receive drops them the same way: read, neither a frame nor
    // an error.
    sender.send(0, &Pulse::zeroed(), b"stranger").unwrap();
    let mut slots = vec![vec![0u8; MAX_ENVELOPE]; 4];
    let batch = {
        let mut refs: Vec<&mut [u8]> = slots.iter_mut().map(|s| s.as_mut_slice()).collect();
        receiver.recv_batch_into(4, &mut refs).unwrap()
    };
    assert_eq!(batch.received, 1);
    assert!(batch.frames.is_empty() && batch.errors.is_empty());
    assert_eq!(receiver.data_rejected_count(), 6);
}

/// Forged frames from another address, even a pair far enough ahead and
/// close enough together to pass for a stream that jumped, never reach the
/// tracking: the filter drops them before they are decoded.
#[cfg(target_os = "linux")]
#[test]
fn forged_frames_among_the_peers_are_dropped() {
    use std::net::UdpSocket;

    use pulse_wire_udp::{wire, BackpressureConfig};

    let feedback = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut receiver = receiver_for(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let any = "127.0.0.1:0".parse().unwrap();
    let cfg = BackpressureConfig::new(any, feedback.local_addr().unwrap()).with_nack(64);
    receiver.enable_backpressure(cfg).unwrap();
    let recv_addr = receiver.local_addr().unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let forger = UdpSocket::bind("127.0.0.2:0").unwrap();
    let frame = |seq: u64| wire::encode(seq, 0, &Pulse::zeroed(), &[]).unwrap();

    for (seq, forged) in [(0u64, u64::MAX - 2), (1, u64::MAX - 1)] {
        forger.send_to(&frame(forged), recv_addr).unwrap();
        peer.send_to(&frame(seq), recv_addr).unwrap();
        assert_eq!(receiver.recv().unwrap().2.seq, seq);
    }
    assert_eq!(receiver.data_rejected_count(), 2);
    assert_eq!(receiver.beyond_horizon_count(), 0);
    assert_eq!(receiver.gap_resyncs(), 0);
    assert_eq!(receiver.contiguous_head(), 2);
    assert_eq!(receiver.published_recv_cursor(), 2);
}
