// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! NACK staging is bounded and staged once.
//!
//! The receiver stages a missing sequence once, when the arrival that
//! reveals the gap is processed; later arrivals do not stage it again. A
//! sequence still missing after the retry interval is requested again, at
//! most `MAX_NACK_ATTEMPTS` times in all, and a sequence that arrives or
//! that the head jumps past is not requested again. The staged set is
//! capped at the recovery window, and the missing sequences a wider gap
//! leaves outside it are counted. Every jump here stays within the
//! horizon, twice the window beyond the head, as far as one frame may move
//! the tracking; `sequence_horizon.rs` covers frames beyond it. The
//! sender's feedback socket is stood in
//! for by a plain UDP socket bound to port 0, so every request the
//! receiver emits can be seen and counted, and data frames are injected
//! with chosen sequence numbers so that a loss is exactly the one intended.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use pulse_canon::Pulse;
use pulse_wire_udp::{
    decode_nack, wire, BackpressureConfig, Receiver, MAX_NACK_ATTEMPTS, NACK_RETRY_PERIODS,
};

const ATTEMPTS: usize = MAX_NACK_ATTEMPTS as usize;

/// A receiver with NACK on, the socket its feedback goes to, and a socket
/// that injects data frames.
struct Rig {
    receiver: Receiver,
    recv_addr: SocketAddr,
    feedback: UdpSocket,
    injector: UdpSocket,
    frame: Vec<u8>,
}

impl Rig {
    fn new(window: usize, ack_period: Duration) -> Self {
        let feedback = UdpSocket::bind("127.0.0.1:0").unwrap();
        feedback
            .set_read_timeout(Some(Duration::from_millis(5)))
            .unwrap();
        let mut receiver = Receiver::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let recv_addr = receiver.local_addr().unwrap();
        let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut cfg =
            BackpressureConfig::new(any, feedback.local_addr().unwrap()).with_nack(window);
        cfg.ack_period = ack_period;
        receiver.enable_backpressure(cfg).unwrap();
        Self {
            receiver,
            recv_addr,
            feedback,
            injector: UdpSocket::bind("127.0.0.1:0").unwrap(),
            frame: Vec::with_capacity(wire::MTU_BYTES),
        }
    }

    /// Deliver the frame numbered `seq` and have the receiver take it in.
    fn deliver(&mut self, seq: u64) {
        self.frame.clear();
        wire::encode_into(seq, 0, &Pulse::zeroed(), &[], &mut self.frame).unwrap();
        self.injector.send_to(&self.frame, self.recv_addr).unwrap();
        let (_, _, meta) = self.receiver.recv().unwrap();
        assert_eq!(meta.seq, seq);
    }

    /// Read the receiver's NACKs into `seen`, with the time each was read,
    /// until `done(seen)` holds or `limit` passes. ACKs are skipped.
    fn read_nacks(
        &self,
        seen: &mut Vec<(Instant, u64)>,
        limit: Duration,
        done: impl Fn(&[(Instant, u64)]) -> bool,
    ) {
        let mut buf = [0u8; 64];
        let start = Instant::now();
        while !done(seen) && start.elapsed() < limit {
            if let Ok(n) = self.feedback.recv(&mut buf) {
                if let Some(seq) = decode_nack(&buf[..n]) {
                    seen.push((Instant::now(), seq));
                }
            }
        }
    }
}

fn seqs(seen: &[(Instant, u64)]) -> Vec<u64> {
    seen.iter().map(|&(_, seq)| seq).collect()
}

#[test]
fn one_loss_then_a_thousand_arrivals_is_requested_once_per_attempt() {
    let ack_period = Duration::from_millis(5);
    let retry = ack_period * NACK_RETRY_PERIODS;
    let mut rig = Rig::new(4096, ack_period);
    rig.deliver(0);
    // Seq 1 is lost, then a thousand later frames arrive, each one a new
    // out-of-order arrival above the gap.
    for seq in 2..=1001 {
        rig.deliver(seq);
    }
    assert_eq!(rig.receiver.contiguous_head(), 1);

    let mut seen = Vec::new();
    rig.read_nacks(&mut seen, Duration::from_secs(3), |s| s.len() >= ATTEMPTS);
    // Nothing more comes, however long the gap stays open.
    rig.read_nacks(&mut seen, 5 * retry, |_| false);
    assert_eq!(
        seqs(&seen),
        vec![1; ATTEMPTS],
        "one request per attempt for the lost seq and none for any other"
    );
    assert_eq!(rig.receiver.nacks_sent(), u64::from(MAX_NACK_ATTEMPTS));
    assert_eq!(rig.receiver.nack_drop_count(), 0);
}

#[test]
fn a_gap_wider_than_the_cap_is_capped_and_counted() {
    const WINDOW: u64 = 64;
    let ack_period = Duration::from_millis(5);
    let retry = ack_period * NACK_RETRY_PERIODS;
    let mut rig = Rig::new(WINDOW as usize, ack_period);
    rig.deliver(0);
    // 1..TOP are lost: 128 missing seqs against a cap of 64. TOP is the
    // horizon beyond the head at 1, the widest jump one frame may make.
    const TOP: u64 = 1 + 2 * WINDOW;
    rig.deliver(TOP);
    let floor = TOP - WINDOW;
    assert_eq!(rig.receiver.contiguous_head(), floor);
    assert_eq!(rig.receiver.gap_resyncs(), 1);
    assert_eq!(
        rig.receiver.nack_drop_count(),
        floor - 1,
        "the missing seqs below the window are counted instead of staged"
    );

    let mut seen = Vec::new();
    rig.read_nacks(&mut seen, Duration::from_secs(5), |s| {
        s.len() >= WINDOW as usize * ATTEMPTS
    });
    rig.read_nacks(&mut seen, 5 * retry, |_| false);
    let mut per_seq: BTreeMap<u64, usize> = BTreeMap::new();
    for seq in seqs(&seen) {
        *per_seq.entry(seq).or_default() += 1;
    }
    assert_eq!(
        per_seq.keys().copied().collect::<Vec<_>>(),
        (floor..TOP).collect::<Vec<_>>(),
        "exactly the newest window of the gap is requested"
    );
    assert!(
        per_seq.values().all(|&n| n == ATTEMPTS),
        "each staged seq is requested once per attempt: {per_seq:?}"
    );
    assert_eq!(rig.receiver.nack_drop_count(), floor - 1);
}

#[test]
fn a_seq_still_missing_is_requested_again_after_the_interval_up_to_the_limit() {
    let ack_period = Duration::from_millis(10);
    let retry = ack_period * NACK_RETRY_PERIODS;
    let mut rig = Rig::new(64, ack_period);
    rig.deliver(0);
    rig.deliver(2);

    let mut seen = Vec::new();
    rig.read_nacks(&mut seen, Duration::from_secs(3), |s| s.len() >= ATTEMPTS);
    rig.read_nacks(&mut seen, 4 * retry, |_| false);
    assert_eq!(
        seqs(&seen),
        vec![1; ATTEMPTS],
        "requested again while missing, and never past the limit"
    );
    // Each repeat waits for the retry interval. The times are read times,
    // so allow for the reader being late with the earlier one.
    for pair in seen.windows(2) {
        let gap = pair[1].0 - pair[0].0;
        assert!(
            gap >= retry / 2,
            "a repeat {gap:?} after the last request; the interval is {retry:?}"
        );
    }
}

#[test]
fn a_seq_that_arrives_after_its_first_request_is_not_requested_again() {
    // A long period, so that the retransmission below lands well before
    // the repeat would fall due.
    let ack_period = Duration::from_millis(20);
    let retry = ack_period * NACK_RETRY_PERIODS;
    let mut rig = Rig::new(64, ack_period);
    rig.deliver(0);
    rig.deliver(2);

    let mut seen = Vec::new();
    rig.read_nacks(&mut seen, Duration::from_secs(3), |s| !s.is_empty());
    assert_eq!(seqs(&seen), vec![1]);
    rig.deliver(1);
    assert_eq!(rig.receiver.contiguous_head(), 3);
    rig.read_nacks(&mut seen, 3 * retry, |_| false);
    assert_eq!(
        seqs(&seen),
        vec![1],
        "an arrived seq is not requested again"
    );
}

#[test]
fn staged_seqs_the_head_jumps_past_are_not_requested_again() {
    const WINDOW: u64 = 64;
    // A long period, so that the jump below comes before any repeat.
    let ack_period = Duration::from_millis(20);
    let retry = ack_period * NACK_RETRY_PERIODS;
    let mut rig = Rig::new(WINDOW as usize, ack_period);
    rig.deliver(0);
    rig.deliver(10);

    let mut seen = Vec::new();
    rig.read_nacks(&mut seen, Duration::from_secs(3), |s| s.len() >= 9);
    assert_eq!(
        seqs(&seen).into_iter().collect::<BTreeSet<_>>(),
        (1..10).collect::<BTreeSet<_>>()
    );

    // A frame more than a window ahead, at the horizon beyond the head at
    // 1, moves the head past 1..10 before their repeats fall due.
    let jump = 1 + 2 * WINDOW;
    rig.deliver(jump);
    let floor = jump - WINDOW;
    assert_eq!(rig.receiver.contiguous_head(), floor);
    let before = seen.len();
    rig.read_nacks(&mut seen, 3 * retry, |_| false);
    let later = seqs(&seen[before..]);
    assert!(!later.is_empty(), "the new window is requested");
    assert!(
        later.iter().all(|&seq| seq >= floor),
        "requests below the head after the jump: {later:?}"
    );
    // 1..10 had been requested, so they are not counted; 11..floor were
    // never staged, and are.
    assert_eq!(rig.receiver.nack_drop_count(), floor - 11);
}

#[test]
fn a_permanent_loss_moves_the_head_once_the_window_passes_it() {
    const WINDOW: u64 = 64;
    let mut rig = Rig::new(WINDOW as usize, Duration::from_millis(5));
    rig.deliver(0);
    // Seq 1 never arrives; the stream carries on in order past the window.
    for seq in 2..=200 {
        rig.deliver(seq);
    }
    assert_eq!(
        rig.receiver.gap_resyncs(),
        1,
        "the head jumps once, not once per later frame"
    );
    assert_eq!(rig.receiver.contiguous_head(), 201);
}
