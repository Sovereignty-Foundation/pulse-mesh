// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Congestion control end to end: a sender and a receiver on loopback with
//! NACK on, the data passing through a proxy that drops chosen frames the
//! first time they pass. The window grows on the clean stretch, halves for
//! the loss, and every frame arrives.
//!
//! A receiver learns of a lost frame only from a later one, so each test
//! sends [`TAIL`] frames after the [`FRAMES`] it counts: a frame the
//! kernel drops at the end, where a socket buffer overflows first, is then
//! requested and resent like any other.

use std::collections::BTreeSet;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use pulse_canon::{Instruction, Pulse};
use pulse_wire_udp::{BackpressureConfig, CongestionConfig, Receiver, Sender, MAGIC};

/// Frames each test counts.
const FRAMES: u64 = 3_000;
/// Frames sent after them, uncounted, so a loss among them is revealed.
const TAIL: u64 = 256;
/// The cap on frames in flight, and the congestion window's.
const DEPTH: u32 = 256;
/// The depth without congestion control: small enough that a fixed window
/// never overflows a Linux socket buffer of the default size, which a
/// 256-frame burst through the proxy can.
const FIXED_DEPTH: u32 = 32;

fn pulse(step: u64) -> Pulse {
    let mut p = Pulse::zeroed();
    p.instruction = Instruction::Data as u16;
    p.chain_step = step;
    p.monotonic_nanos = 1;
    p
}

/// A proxy on loopback that forwards every datagram to `to`, except that
/// it drops each data frame whose sequence number is in `drop` the first
/// time it passes, so its retransmission gets through. Ends when `stop` is
/// set.
fn lossy_proxy(to: SocketAddr, drop: BTreeSet<u64>, stop: Arc<AtomicBool>) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let addr = socket.local_addr().unwrap();
    thread::spawn(move || {
        let mut dropped = BTreeSet::new();
        let mut buf = [0u8; 2048];
        while !stop.load(Ordering::Relaxed) {
            let Ok(n) = socket.recv(&mut buf) else {
                continue;
            };
            let datagram = &buf[..n];
            let is_data = datagram.get(0..4) == Some(&MAGIC.to_le_bytes()[..]);
            if is_data {
                let seq = u64::from_le_bytes(datagram[5..13].try_into().unwrap());
                if drop.contains(&seq) && dropped.insert(seq) {
                    continue;
                }
            }
            let _ = socket.send_to(datagram, to);
        }
    });
    addr
}

/// A sender with NACK and the given congestion control, a receiver with
/// NACK, connected through a proxy that drops `drop` once.
fn path(
    congestion: Option<CongestionConfig>,
    depth: u32,
    drop: &[u64],
) -> (Sender, Receiver, Arc<AtomicBool>) {
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    let mut receiver = Receiver::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let proxy = lossy_proxy(
        receiver.local_addr().unwrap(),
        drop.iter().copied().collect(),
        Arc::clone(&stop),
    );
    sender.connect(proxy).unwrap();
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut cfg = BackpressureConfig::new(any, any).with_nack(4096);
    cfg.target_queue_depth = depth;
    cfg.congestion = congestion;
    sender.enable_backpressure(cfg.clone()).unwrap();
    cfg.ack_target_addr = sender.ack_local_addr().unwrap();
    receiver.enable_backpressure(cfg).unwrap();
    (sender, receiver, stop)
}

/// A receiver draining on another thread, which keeps receiving, and so
/// acknowledging, until the sender has finished and every step below
/// `FRAMES` has arrived, or 20 s pass.
struct Drain {
    sent_all: Arc<AtomicBool>,
    handle: thread::JoinHandle<BTreeSet<u64>>,
}

fn drain(mut receiver: Receiver) -> Drain {
    let sent_all = Arc::new(AtomicBool::new(false));
    let done = Arc::clone(&sent_all);
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut steps = BTreeSet::new();
        while Instant::now() < deadline {
            if done.load(Ordering::Acquire) && steps.len() as u64 == FRAMES {
                break;
            }
            if let Ok((pulse, _, _)) = receiver.recv() {
                if pulse.chain_step < FRAMES {
                    steps.insert(pulse.chain_step);
                }
            }
        }
        steps
    });
    Drain { sent_all, handle }
}

impl Drain {
    /// Tell the receiver the sender has finished; returns the steps below
    /// `FRAMES` it received.
    fn finish(self) -> BTreeSet<u64> {
        self.sent_all.store(true, Ordering::Release);
        self.handle.join().unwrap()
    }
}

#[test]
fn the_window_grows_on_a_clean_path_halves_for_a_loss_and_every_frame_arrives() {
    let (mut sender, receiver, stop) = path(Some(CongestionConfig::default()), DEPTH, &[1_500]);
    assert_eq!(sender.congestion_window(), Some(4), "the initial window");
    let received = drain(receiver);
    let mut grown = 0;
    for step in 0..FRAMES + TAIL {
        sender.send(step, &pulse(step), &[]).unwrap();
        if step == 1_400 {
            grown = sender.congestion_window().unwrap();
        }
    }
    let steps = received.finish();
    stop.store(true, Ordering::Relaxed);
    assert!(
        grown > 4,
        "the window did not grow on the clean stretch: {grown}"
    );
    assert!(
        sender.congestion_decreases() >= 1,
        "the dropped frame's NACK did not decrease the window"
    );
    assert!(sender.smoothed_rtt().is_some(), "no round trip was sampled");
    assert!(sender.congestion_window().unwrap() <= DEPTH);
    assert_eq!(steps.len() as u64, FRAMES, "frames went missing");
}

#[test]
fn pacing_still_delivers_every_frame() {
    let (mut sender, receiver, stop) = path(
        Some(CongestionConfig::default().with_pacing()),
        DEPTH,
        &[100, 900],
    );
    let received = drain(receiver);
    for step in 0..FRAMES + TAIL {
        sender.send(step, &pulse(step), &[]).unwrap();
    }
    let steps = received.finish();
    stop.store(true, Ordering::Relaxed);
    assert_eq!(steps.len() as u64, FRAMES, "frames went missing");
    assert!(sender.smoothed_rtt().is_some());
}

#[test]
fn without_congestion_control_there_is_no_window() {
    let (mut sender, receiver, stop) = path(None, FIXED_DEPTH, &[10]);
    let received = drain(receiver);
    for step in 0..FRAMES + TAIL {
        sender.send(step, &pulse(step), &[]).unwrap();
    }
    let steps = received.finish();
    stop.store(true, Ordering::Relaxed);
    assert_eq!(sender.congestion_window(), None);
    assert_eq!(sender.smoothed_rtt(), None);
    assert_eq!(sender.congestion_decreases(), 0);
    assert_eq!(steps.len() as u64, FRAMES);
}

#[test]
fn reconfiguring_keeps_the_window_while_its_settings_hold() {
    let (mut sender, receiver, stop) = path(Some(CongestionConfig::default()), DEPTH, &[]);
    let received = drain(receiver);
    for step in 0..FRAMES + TAIL {
        sender.send(step, &pulse(step), &[]).unwrap();
    }
    received.finish();
    let grown = sender.congestion_window().unwrap();
    assert!(grown > 4);
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut cfg = BackpressureConfig::new(any, sender.ack_local_addr().unwrap())
        .with_nack(4096)
        .with_congestion_control(CongestionConfig::default());
    cfg.ack_bind_addr = sender.ack_local_addr().unwrap();
    cfg.target_queue_depth = DEPTH;
    sender.enable_backpressure(cfg.clone()).unwrap();
    assert_eq!(
        sender.congestion_window(),
        Some(grown),
        "same settings: the window carries over"
    );
    let mut wider = CongestionConfig::default();
    wider.initial_window = 8;
    cfg.congestion = Some(wider);
    sender.enable_backpressure(cfg).unwrap();
    assert_eq!(
        sender.congestion_window(),
        Some(8),
        "new settings: a new window"
    );
    stop.store(true, Ordering::Relaxed);
}
