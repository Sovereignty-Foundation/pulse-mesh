// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The sender's feedback socket only trusts the configured peer.
//!
//! Without a filter any host that can reach the ACK socket can forge an
//! ACK (disabling the stall) or NACKs (forcing retransmits). With
//! `feedback_peer` set, datagrams from any other source are dropped and
//! counted. Both loopback sockets here are 127.0.0.1, so the rejecting
//! case filters on the IPv6 loopback instead, which never matches.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use pulse_wire_udp::{encode_ack, encode_nack, BackpressureConfig, Sender};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

fn ephemeral() -> SocketAddr {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn wait_for(mut cond: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(2) {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    cond()
}

fn sender_with(peer: Option<IpAddr>) -> (Sender, SocketAddr) {
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut cfg = BackpressureConfig::new(any, any).with_nack(16);
    if let Some(p) = peer {
        cfg = cfg.with_feedback_peer(p);
    }
    sender.enable_backpressure(cfg).unwrap();
    let ack = sender.ack_local_addr().unwrap();
    (sender, ack)
}

#[test]
fn matching_peer_is_accepted() {
    let (sender, ack) = sender_with(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let inj = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = Vec::new();
    encode_ack(5, &mut buf);
    inj.send_to(&buf, ack).unwrap();
    assert!(
        wait_for(|| sender.observed_recv_cursor() == 5),
        "ACK not applied"
    );
    assert_eq!(sender.feedback_rejected_count(), 0);
}

#[test]
fn mismatching_peer_is_rejected() {
    let (mut sender, ack) = sender_with(Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    let dest = ephemeral();
    sender.connect(dest).unwrap();
    let inj = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = Vec::new();
    encode_ack(9, &mut buf);
    inj.send_to(&buf, ack).unwrap();
    buf.clear();
    encode_nack(0, &mut buf);
    inj.send_to(&buf, ack).unwrap();
    assert!(
        wait_for(|| sender.feedback_rejected_count() == 2),
        "both forged datagrams must be counted as rejected"
    );
    assert_eq!(
        sender.observed_recv_cursor(),
        0,
        "forged ACK must not move the cursor"
    );
    sender.send(0, &pulse_canon::Pulse::zeroed(), &[]).unwrap();
    assert_eq!(
        sender.retransmit_count(),
        0,
        "forged NACK must not retransmit"
    );
}

#[test]
fn unset_peer_accepts_any_source() {
    let (sender, ack) = sender_with(None);
    let inj = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = Vec::new();
    encode_ack(7, &mut buf);
    inj.send_to(&buf, ack).unwrap();
    assert!(
        wait_for(|| sender.observed_recv_cursor() == 7),
        "ACK not applied"
    );
    assert_eq!(sender.feedback_rejected_count(), 0);
}
