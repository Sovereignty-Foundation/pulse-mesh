// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! The sender's backpressure stall cannot wedge.
//!
//! Three things can leave the sender's view of the receiver's cursor
//! stuck: a receiver that outlives a restart of its sender keeps
//! acknowledging the previous run's head, ahead of the new run; an ACK from
//! the admitted peer can carry any cursor at all; and a receiver that stops
//! acknowledging leaves the cursor where it was. The first two must not
//! stall the sender at all. The third must end in `SenderError::Stalled` at
//! the configured deadline, with the frame unsent and its sequence number
//! unused, for a single send and for a batch alike; without a deadline the
//! send waits for the cursor. A target depth of zero, which would stall
//! every send, is refused when backpressure is enabled.

use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use pulse_canon::Pulse;
use pulse_wire_udp::{encode_ack, wire, BackpressureConfig, Receiver, Sender, SenderError};

fn any_loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn wait_for(mut cond: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(2) {
        if cond() {
            return true;
        }
        thread::sleep(Duration::from_millis(2));
    }
    cond()
}

/// A data destination that is bound but never acknowledges anything.
fn silent_sink() -> UdpSocket {
    let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
    sink.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    sink
}

/// The sequence numbers of every data frame waiting on `sink`.
fn drain_seqs(sink: &UdpSocket) -> Vec<u64> {
    let mut buf = vec![0u8; wire::MTU_BYTES];
    let mut seqs = Vec::new();
    while let Ok(n) = sink.recv(&mut buf) {
        seqs.push(wire::decode(&buf[..n]).unwrap().seq);
    }
    seqs
}

/// Send an ACK carrying `cursor` to the sender's feedback socket, as the
/// receiver (or anyone the filter admits) would.
fn inject_ack(sender: &Sender, cursor: u64) {
    let injector = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut ack = Vec::new();
    encode_ack(cursor, &mut ack);
    injector
        .send_to(&ack, sender.ack_local_addr().unwrap())
        .unwrap();
}

#[test]
fn a_restarted_sender_is_not_held_back_by_the_old_runs_cursor() {
    let mut receiver = Receiver::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let recv_addr = receiver.local_addr().unwrap();

    // The first run: a hundred frames, all received, so the receiver's
    // cursor stands at 100. Its depth is loose only so that the burst can
    // go out before this thread drains it.
    let mut first = Sender::bind("127.0.0.1:0").unwrap();
    first.connect(recv_addr).unwrap();
    let mut cfg = BackpressureConfig::new(any_loopback(), any_loopback());
    cfg.target_queue_depth = 1024;
    first.enable_backpressure(cfg.clone()).unwrap();
    let feedback_addr = first.ack_local_addr().unwrap();
    cfg.ack_target_addr = feedback_addr;
    receiver.enable_backpressure(cfg).unwrap();
    for i in 0..100u64 {
        first.send(i, &Pulse::zeroed(), &[]).unwrap();
    }
    for _ in 0..100 {
        receiver.recv().unwrap();
    }
    assert_eq!(receiver.published_recv_cursor(), 100);

    // The sender restarts: the old process is gone, and the new one binds
    // the same feedback address, where the receiver still reports the old
    // run's cursor. The new run starts again at sequence 0, with the
    // default depth of 16 and a one-second deadline so that a regression
    // fails here rather than hanging.
    drop(first);
    let mut second = Sender::bind("127.0.0.1:0").unwrap();
    second.connect(recv_addr).unwrap();
    let cfg = BackpressureConfig::new(feedback_addr, any_loopback())
        .with_stall_timeout(Some(Duration::from_secs(1)));
    second.enable_backpressure(cfg).unwrap();
    assert_eq!(second.ack_local_addr(), Some(feedback_addr));
    assert!(
        wait_for(|| second.observed_recv_cursor() == 100),
        "the old run's cursor must reach the restarted sender"
    );
    assert_eq!(second.next_seq(), 0);

    let started = Instant::now();
    for i in 0..64u64 {
        let seq = second
            .send(i, &Pulse::zeroed(), &[])
            .unwrap_or_else(|e| panic!("send {i} after the restart failed: {e}"));
        assert_eq!(seq, i);
    }
    let took = started.elapsed();
    assert!(
        took < Duration::from_millis(500),
        "64 sends after the restart took {took:?}"
    );

    // The receiver still delivers the new run's frames.
    for i in 0..64u64 {
        let (_, _, meta) = receiver.recv().unwrap();
        assert_eq!(meta.seq, i);
    }
}

#[test]
fn a_silent_receiver_ends_the_stall_at_the_deadline() {
    const DEADLINE: Duration = Duration::from_millis(300);
    let sink = silent_sink();
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    sender.connect(sink.local_addr().unwrap()).unwrap();
    // The feedback socket is bound, but nobody acknowledges to it.
    let mut cfg =
        BackpressureConfig::new(any_loopback(), any_loopback()).with_stall_timeout(Some(DEADLINE));
    cfg.target_queue_depth = 4;
    sender.enable_backpressure(cfg).unwrap();

    for i in 0..4u64 {
        assert_eq!(sender.send(i, &Pulse::zeroed(), &[]).unwrap(), i);
    }
    let started = Instant::now();
    let err = sender.send(4, &Pulse::zeroed(), &[]).unwrap_err();
    let took = started.elapsed();
    match err {
        SenderError::Stalled { in_flight, waited } => {
            assert_eq!(in_flight, 4);
            assert!(waited >= DEADLINE, "gave up after {waited:?}");
        }
        other => panic!("expected Stalled, got {other:?}"),
    }
    assert!(
        took >= DEADLINE && took < 4 * DEADLINE,
        "the stall lasted {took:?} against a {DEADLINE:?} deadline"
    );
    assert_eq!(
        sender.next_seq(),
        4,
        "the stalled frame must not use a sequence number"
    );
    assert_eq!(
        drain_seqs(&sink),
        vec![0, 1, 2, 3],
        "the stalled frame was sent"
    );

    // Once the receiver acknowledges, the retried frame goes out under the
    // number the stalled attempt left unused.
    inject_ack(&sender, 4);
    assert!(wait_for(|| sender.observed_recv_cursor() == 4));
    assert_eq!(sender.send(4, &Pulse::zeroed(), &[]).unwrap(), 4);
    assert_eq!(drain_seqs(&sink), vec![4]);
}

#[test]
fn an_ack_far_ahead_of_the_sender_never_stalls_it() {
    let sink = silent_sink();
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    sender.connect(sink.local_addr().unwrap()).unwrap();
    let mut cfg = BackpressureConfig::new(any_loopback(), any_loopback())
        .with_stall_timeout(Some(Duration::from_secs(1)));
    cfg.target_queue_depth = 4;
    sender.enable_backpressure(cfg).unwrap();

    for cursor in [1u64 << 40, u64::MAX] {
        inject_ack(&sender, cursor);
        assert!(
            wait_for(|| sender.observed_recv_cursor() == cursor),
            "ACK {cursor} not applied"
        );
        let started = Instant::now();
        for _ in 0..64 {
            sender
                .send(0, &Pulse::zeroed(), &[])
                .unwrap_or_else(|e| panic!("send under a cursor of {cursor} failed: {e}"));
        }
        let took = started.elapsed();
        assert!(
            took < Duration::from_millis(500),
            "64 sends under a cursor of {cursor} took {took:?}"
        );
    }
    assert_eq!(sender.next_seq(), 128);
}

#[test]
fn without_a_deadline_the_send_waits_for_the_cursor() {
    let sink = silent_sink();
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    sender.connect(sink.local_addr().unwrap()).unwrap();
    let mut cfg = BackpressureConfig::new(any_loopback(), any_loopback()).with_stall_timeout(None);
    cfg.target_queue_depth = 2;
    sender.enable_backpressure(cfg).unwrap();
    let feedback_addr = sender.ack_local_addr().unwrap();

    sender.send(0, &Pulse::zeroed(), &[]).unwrap();
    sender.send(1, &Pulse::zeroed(), &[]).unwrap();
    let blocked = thread::spawn(move || sender.send(2, &Pulse::zeroed(), &[]));
    thread::sleep(Duration::from_millis(400));
    assert!(
        !blocked.is_finished(),
        "with no deadline the send must still be waiting for the cursor"
    );

    let injector = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut ack = Vec::new();
    encode_ack(1, &mut ack);
    injector.send_to(&ack, feedback_addr).unwrap();
    assert_eq!(blocked.join().unwrap().unwrap(), 2);
}

/// `send_batch` stalls under the same rule and deadline as `send_to` and
/// ends the batch at the frame that stalls, on every platform: off Linux
/// it sends frame by frame through `send_to`, and on Linux it waits for the
/// window between `sendmmsg(2)` calls.
#[test]
fn a_batch_stops_at_the_frame_that_stalls() {
    use pulse_wire_udp::BatchSendError;

    let sink = silent_sink();
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    let mut cfg = BackpressureConfig::new(any_loopback(), any_loopback())
        .with_stall_timeout(Some(Duration::from_millis(200)));
    cfg.target_queue_depth = 3;
    sender.enable_backpressure(cfg).unwrap();

    let pulse = Pulse::zeroed();
    let frames: Vec<(u64, &Pulse, &[u8])> = (0..8u64).map(|i| (i, &pulse, &[][..])).collect();
    match sender.send_batch(&frames, sink.local_addr().unwrap()) {
        Err(BatchSendError::FrameError {
            index: 3,
            error: SenderError::Stalled { in_flight: 3, .. },
        }) => {}
        other => panic!("expected the fourth frame to stall, got {other:?}"),
    }
    assert_eq!(sender.next_seq(), 3);
    assert_eq!(drain_seqs(&sink), vec![0, 1, 2]);
}

/// A depth of zero admits no frame, so every send would stall until its
/// deadline. The sender refuses such a config before binding anything, and
/// the backpressure it already runs, if any, stays as it was.
#[test]
fn a_zero_queue_depth_is_refused() {
    let sink = silent_sink();
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    sender.connect(sink.local_addr().unwrap()).unwrap();
    let mut cfg = BackpressureConfig::new(any_loopback(), any_loopback());
    cfg.target_queue_depth = 0;
    match sender.enable_backpressure(cfg.clone()) {
        Err(SenderError::InvalidQueueDepth) => {}
        other => panic!("expected InvalidQueueDepth, got {other:?}"),
    }
    assert!(!sender.backpressure_enabled());
    assert_eq!(
        sender.ack_local_addr(),
        None,
        "the refused config bound a socket"
    );

    // A depth of one is the smallest that works; refusing a zero depth
    // afterwards leaves it running, feedback socket and all.
    cfg.target_queue_depth = 1;
    sender.enable_backpressure(cfg.clone()).unwrap();
    let feedback_addr = sender.ack_local_addr().unwrap();
    cfg.target_queue_depth = 0;
    match sender.enable_backpressure(cfg) {
        Err(SenderError::InvalidQueueDepth) => {}
        other => panic!("expected InvalidQueueDepth, got {other:?}"),
    }
    assert_eq!(sender.ack_local_addr(), Some(feedback_addr));
    assert_eq!(sender.send(0, &Pulse::zeroed(), &[]).unwrap(), 0);
    assert_eq!(drain_seqs(&sink), vec![0]);
}
