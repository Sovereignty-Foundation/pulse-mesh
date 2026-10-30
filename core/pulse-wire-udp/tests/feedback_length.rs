// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A feedback datagram longer than an ACK or a NACK is refused, even when
//! it starts with a well-formed one.
//!
//! A UDP receive copies what fits in the buffer and drops the rest without
//! saying so. With a buffer exactly as long as an ACK, a longer datagram
//! arrives cut to an ACK's length, and the decoder's exact-length check
//! cannot see that it was longer. The feedback thread lends a buffer one
//! byte longer, so such a datagram arrives one byte too long and is
//! refused. Each test ends with a well-formed ACK as a marker: loopback
//! delivers one sender's datagrams in order, so once the marker has been
//! applied, the datagram sent before it has been taken too.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use pulse_canon::Pulse;
use pulse_wire_udp::{encode_ack, encode_nack, BackpressureConfig, Receiver, Sender};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

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

/// A sender with NACK on, connected to a live receiver, that has sent (and
/// cached) the frames numbered `0..frames`; and its feedback address.
fn sender(frames: usize) -> (Sender, Receiver, SocketAddr) {
    let receiver = Receiver::bind("127.0.0.1:0").unwrap();
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    sender.connect(receiver.local_addr().unwrap()).unwrap();
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut cfg = BackpressureConfig::new(any, any).with_nack(16);
    cfg.target_queue_depth = 4096;
    sender.enable_backpressure(cfg).unwrap();
    for _ in 0..frames {
        sender.send(0, &Pulse::zeroed(), &[]).unwrap();
    }
    let ack = sender.ack_local_addr().unwrap();
    (sender, receiver, ack)
}

/// `datagram` with `extra` bytes after it.
fn longer(datagram: &[u8], extra: usize) -> Vec<u8> {
    let mut out = datagram.to_vec();
    out.resize(datagram.len() + extra, 0xA5);
    out
}

#[test]
fn an_ack_with_bytes_after_it_does_not_move_the_cursor() {
    let (sender, _receiver, ack) = sender(0);
    let inj = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = Vec::new();
    encode_ack(1_000, &mut buf);
    for extra in [1, 4, 8, 100] {
        inj.send_to(&longer(&buf, extra), ack).unwrap();
    }
    encode_ack(3, &mut buf);
    inj.send_to(&buf, ack).unwrap();
    assert!(
        wait_for(|| sender.observed_recv_cursor() != 0),
        "the well-formed ACK after them was never applied"
    );
    assert_eq!(
        sender.observed_recv_cursor(),
        3,
        "an over-length datagram that starts like an ACK moved the cursor"
    );
}

#[test]
fn a_nack_with_bytes_after_it_requests_nothing() {
    let (mut sender, _receiver, ack) = sender(4);
    let inj = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = Vec::new();
    encode_nack(1, &mut buf);
    for extra in [1, 4, 8, 100] {
        inj.send_to(&longer(&buf, extra), ack).unwrap();
    }
    encode_ack(2, &mut buf);
    inj.send_to(&buf, ack).unwrap();
    assert!(
        wait_for(|| sender.observed_recv_cursor() == 2),
        "the well-formed ACK after them was never applied"
    );
    sender.send(0, &Pulse::zeroed(), &[]).unwrap();
    assert_eq!(
        sender.retransmit_count(),
        0,
        "an over-length datagram that starts like a NACK was taken as one"
    );

    // The same NACK at its exact length is taken, so the test would see one.
    encode_nack(1, &mut buf);
    inj.send_to(&buf, ack).unwrap();
    encode_ack(3, &mut buf);
    inj.send_to(&buf, ack).unwrap();
    assert!(
        wait_for(|| sender.observed_recv_cursor() == 3),
        "the marker ACK was never applied"
    );
    sender.send(0, &Pulse::zeroed(), &[]).unwrap();
    assert_eq!(
        sender.retransmit_count(),
        1,
        "a well-formed NACK for a cached frame must be retransmitted"
    );
}
