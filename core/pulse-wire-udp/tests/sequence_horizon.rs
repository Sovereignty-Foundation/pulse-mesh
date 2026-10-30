// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! One forged frame cannot switch off backpressure or loss recovery.
//!
//! The receiver's ACK cursor only ever rises, so a CRC-valid frame numbered
//! near `u64::MAX`, from any socket that can reach the receiver, would pin
//! it there if it counted: the sender would never stall again, and gap
//! tracking would resync to the forged number and request no later loss.
//! A frame more than the horizon, twice the recovery window, beyond the
//! contiguous head is delivered but moves nothing and is counted, unless a
//! second such frame within one window of it confirms that the stream
//! really jumped.

use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use pulse_canon::Pulse;
use pulse_wire_udp::{decode_ack, wire, BackpressureConfig, Receiver, Sender, SenderError};

/// The recovery window, the sender's send-cache capacity: the horizon is
/// twice it.
const WINDOW: u64 = 64;

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

/// A sender and a receiver with backpressure and NACK over loopback, the
/// sender held to `depth` frames beyond the cursor.
fn pair(depth: u32) -> (Sender, Receiver) {
    let mut receiver = Receiver::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    sender.connect(receiver.local_addr().unwrap()).unwrap();
    let mut cfg = BackpressureConfig::new(any_loopback(), any_loopback())
        .with_nack(WINDOW as usize)
        .with_stall_timeout(Some(Duration::from_millis(300)));
    cfg.target_queue_depth = depth;
    sender.enable_backpressure(cfg.clone()).unwrap();
    cfg.ack_target_addr = sender.ack_local_addr().unwrap();
    receiver.enable_backpressure(cfg).unwrap();
    (sender, receiver)
}

/// Send a CRC-valid frame numbered `seq` to the receiver from a socket of
/// its own, as anyone who can reach the receiver can.
fn forge(receiver: &Receiver, seq: u64) {
    let forger = UdpSocket::bind("127.0.0.1:0").unwrap();
    let frame = wire::encode(seq, 0, &Pulse::zeroed(), b"forged").unwrap();
    forger
        .send_to(&frame, receiver.local_addr().unwrap())
        .unwrap();
}

/// Take the next frame and return its sequence number.
fn next_seq(receiver: &mut Receiver) -> u64 {
    receiver
        .recv()
        .unwrap_or_else(|e| panic!("recv failed: {e}"))
        .2
        .seq
}

#[test]
fn one_forged_frame_leaves_backpressure_on() {
    let (mut sender, mut receiver) = pair(4);
    for seq in 0..4u64 {
        assert_eq!(sender.send(0, &Pulse::zeroed(), &[]).unwrap(), seq);
        assert_eq!(next_seq(&mut receiver), seq);
    }
    assert!(wait_for(|| sender.observed_recv_cursor() == 4));

    // One forged frame near the top of the sequence space is delivered, and
    // counted, but moves neither the cursor nor the head.
    forge(&receiver, u64::MAX - 1);
    assert_eq!(next_seq(&mut receiver), u64::MAX - 1);
    assert_eq!(receiver.beyond_horizon_count(), 1);
    assert_eq!(receiver.published_recv_cursor(), 4);
    assert_eq!(receiver.contiguous_head(), 4);

    // Many ACK periods later the sender still sees the receiver's real
    // cursor, so backpressure still holds it: with the receiver no longer
    // draining, four more frames go and the fifth stalls.
    thread::sleep(Duration::from_millis(30));
    assert_eq!(sender.observed_recv_cursor(), 4);
    for seq in 4..8u64 {
        assert_eq!(sender.send(0, &Pulse::zeroed(), &[]).unwrap(), seq);
    }
    match sender.send(0, &Pulse::zeroed(), &[]) {
        Err(SenderError::Stalled { in_flight: 4, .. }) => {}
        other => panic!("backpressure is off after one forged frame: {other:?}"),
    }
}

#[test]
fn one_forged_frame_leaves_loss_recovery_on() {
    // A loose depth: this test is about the NACK, not the window.
    let (mut sender, mut receiver) = pair(4096);
    for seq in 0..4u64 {
        sender.send(0, &Pulse::zeroed(), &[]).unwrap();
        assert_eq!(next_seq(&mut receiver), seq);
    }
    forge(&receiver, u64::MAX - 1);
    assert_eq!(next_seq(&mut receiver), u64::MAX - 1);

    // Seq 4 is lost on the way; 5 and 6 arrive, and the gap holds the head.
    // Seq 5's arrival already stages a request for 4, and the sender answers
    // requests ahead of its next frame, so when the request reaches it
    // before 6 is sent, the resent 4 arrives just ahead of 6: loss recovery
    // at work, in the order the timing gives.
    let lost = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .send_to(0, &Pulse::zeroed(), &[], lost.local_addr().unwrap())
        .unwrap();
    sender.send(0, &Pulse::zeroed(), &[]).unwrap();
    assert_eq!(next_seq(&mut receiver), 5);
    sender.send(0, &Pulse::zeroed(), &[]).unwrap();
    let mut got = next_seq(&mut receiver);
    let resent_early = got == 4;
    if resent_early {
        got = next_seq(&mut receiver);
    }
    assert_eq!(got, 6);
    if !resent_early {
        assert_eq!(receiver.contiguous_head(), 4);
    }
    assert!(
        wait_for(|| receiver.nacks_sent() >= 1),
        "loss recovery is off after one forged frame: seq 4 was never requested"
    );

    // The sender answers the request ahead of its next frame; send until it
    // has, then take everything until the head passes all that was sent.
    let started = Instant::now();
    while sender.retransmit_count() == 0 && started.elapsed() < Duration::from_secs(2) {
        thread::sleep(Duration::from_millis(5));
        sender.send(0, &Pulse::zeroed(), &[]).unwrap();
    }
    assert!(
        sender.retransmit_count() >= 1,
        "the NACK was never answered"
    );
    let sent = sender.next_seq();
    while receiver.contiguous_head() < sent {
        next_seq(&mut receiver);
    }
    assert_eq!(receiver.contiguous_head(), sent);
    assert_eq!(receiver.beyond_horizon_count(), 1);
}

/// A receiver whose feedback goes to a plain socket, so its ACKs can be
/// read, and a socket that injects frames numbered at will.
struct Rig {
    receiver: Receiver,
    feedback: UdpSocket,
    injector: UdpSocket,
}

impl Rig {
    fn new() -> Self {
        let feedback = UdpSocket::bind("127.0.0.1:0").unwrap();
        feedback
            .set_read_timeout(Some(Duration::from_millis(5)))
            .unwrap();
        let mut receiver = Receiver::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let cfg = BackpressureConfig::new(any_loopback(), feedback.local_addr().unwrap())
            .with_nack(WINDOW as usize);
        receiver.enable_backpressure(cfg).unwrap();
        Self {
            receiver,
            feedback,
            injector: UdpSocket::bind("127.0.0.1:0").unwrap(),
        }
    }

    /// Deliver the frame numbered `seq` and have the receiver take it in.
    fn deliver(&mut self, seq: u64) {
        let frame = wire::encode(seq, 0, &Pulse::zeroed(), &[]).unwrap();
        self.injector
            .send_to(&frame, self.receiver.local_addr().unwrap())
            .unwrap();
        assert_eq!(next_seq(&mut self.receiver), seq);
    }

    /// The cursor as the receiver's ACKs carry it, once one carries `at_least`.
    fn acked(&self, at_least: u64) -> Option<u64> {
        let mut buf = [0u8; 64];
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(2) {
            if let Ok(n) = self.feedback.recv(&mut buf) {
                if let Some(cursor) = decode_ack(&buf[..n]) {
                    if cursor >= at_least {
                        return Some(cursor);
                    }
                }
            }
        }
        None
    }
}

/// A stream that really jumped, as for a receiver that joins it late or a
/// loss longer than the horizon, is followed from its second frame.
#[test]
fn a_stream_that_jumps_is_followed_from_its_second_frame() {
    let mut rig = Rig::new();
    rig.deliver(0);
    rig.deliver(1);
    const AT: u64 = 1_000_000;

    // The first frame beyond the horizon moves nothing.
    rig.deliver(AT);
    assert_eq!(rig.receiver.contiguous_head(), 2);
    assert_eq!(rig.receiver.published_recv_cursor(), 2);
    assert_eq!(rig.receiver.beyond_horizon_count(), 1);

    // The next one, within a window of it, confirms the jump: the tracking
    // resyncs to the window below it, with the first frame arrived.
    rig.deliver(AT + 1);
    assert_eq!(rig.receiver.published_recv_cursor(), AT + 2);
    assert_eq!(rig.receiver.contiguous_head(), AT + 1 - WINDOW);
    assert_eq!(rig.receiver.gap_resyncs(), 1);
    assert_eq!(rig.receiver.beyond_horizon_count(), 1);

    // The stream carries on from there, and the ACKs say so.
    rig.deliver(AT + 2);
    assert_eq!(rig.receiver.published_recv_cursor(), AT + 3);
    assert_eq!(rig.acked(AT + 3), Some(AT + 3));
}

/// Neither a replay of the frame beyond the horizon nor a frame numbered
/// `u64::MAX` confirms a jump, and the stream goes on as if they had not
/// come.
#[test]
fn a_replayed_or_top_frame_never_confirms_a_jump() {
    let mut rig = Rig::new();
    rig.deliver(0);
    for seq in [u64::MAX - 1, u64::MAX - 1, u64::MAX, u64::MAX] {
        rig.deliver(seq);
        assert_eq!(
            rig.receiver.contiguous_head(),
            1,
            "seq {seq} moved the head"
        );
        assert_eq!(rig.receiver.published_recv_cursor(), 1);
    }
    assert_eq!(rig.receiver.beyond_horizon_count(), 4);
    assert_eq!(rig.receiver.gap_resyncs(), 0);
    rig.deliver(1);
    rig.deliver(2);
    assert_eq!(rig.receiver.contiguous_head(), 3);
    assert_eq!(rig.acked(3), Some(3));
}
