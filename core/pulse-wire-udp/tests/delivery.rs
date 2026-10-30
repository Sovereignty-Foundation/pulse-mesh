// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! The delivery options end to end on loopback, through a proxy that
//! reorders, repeats or drops datagrams: in order, frames come out in
//! sequence order and a gap that never fills is skipped on time; unique,
//! each sequence number comes out once.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use pulse_canon::{Instruction, Pulse};
use pulse_wire_udp::order::{DeliveryConfig, Order};
use pulse_wire_udp::{ReassemblyConfig, Receiver, Sender, MAX_ENVELOPE};

fn pulse(step: u64) -> Pulse {
    let mut p = Pulse::zeroed();
    p.instruction = Instruction::Data as u16;
    p.chain_step = step;
    p.monotonic_nanos = 1;
    p
}

/// What the proxy does with the i-th datagram it reads.
#[derive(Clone, Copy)]
enum Act {
    Forward,
    Drop,
    /// Send it twice.
    Repeat,
    /// Send it after the next `n` datagrams, or when the line goes quiet.
    Hold(usize),
}

/// A proxy to `to` that does with each datagram what `plan` says.
fn proxy(
    to: SocketAddr,
    plan: impl Fn(usize) -> Act + Send + 'static,
    stop: Arc<AtomicBool>,
) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    let addr = socket.local_addr().unwrap();
    thread::spawn(move || {
        let mut held: Vec<(usize, Vec<u8>)> = Vec::new();
        let mut buf = vec![0u8; 2048];
        let mut i = 0;
        while !stop.load(Ordering::Relaxed) {
            let Ok(n) = socket.recv(&mut buf) else {
                for (_, d) in held.drain(..) {
                    let _ = socket.send_to(&d, to);
                }
                continue;
            };
            let d = buf[..n].to_vec();
            match plan(i) {
                Act::Forward => {
                    let _ = socket.send_to(&d, to);
                }
                Act::Drop => {}
                Act::Repeat => {
                    let _ = socket.send_to(&d, to);
                    let _ = socket.send_to(&d, to);
                }
                Act::Hold(after) => held.push((i + after, d)),
            }
            let (due, rest): (Vec<_>, Vec<_>) = held.drain(..).partition(|(at, _)| *at <= i);
            held = rest;
            for (_, d) in due {
                let _ = socket.send_to(&d, to);
            }
            i += 1;
        }
    });
    addr
}

/// A sender and a receiver with `cfg` through a proxy that follows
/// `plan`.
fn pair(
    cfg: DeliveryConfig,
    plan: impl Fn(usize) -> Act + Send + 'static,
) -> (Sender, Receiver, Arc<AtomicBool>) {
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    let mut receiver = Receiver::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    sender
        .connect(proxy(
            receiver.local_addr().unwrap(),
            plan,
            Arc::clone(&stop),
        ))
        .unwrap();
    receiver.enable_delivery(cfg);
    (sender, receiver, stop)
}

/// Send `sends` envelopes with `send`, paced, while `recv` runs on the
/// receiver in a thread of its own. Sent all at once, before anything
/// reads them, a few hundred datagrams overflow a Linux socket's default
/// receive buffer, the proxy's or the receiver's.
fn exchange<T: Send + 'static>(
    sender: &mut Sender,
    receiver: Receiver,
    sends: u64,
    mut send: impl FnMut(&mut Sender, u64),
    recv: impl FnOnce(&mut Receiver) -> T + Send + 'static,
) -> (Receiver, T) {
    let handle = thread::spawn(move || {
        let mut receiver = receiver;
        let got = recv(&mut receiver);
        (receiver, got)
    });
    for n in 0..sends {
        send(sender, n);
        if n % 8 == 7 {
            thread::sleep(Duration::from_millis(1));
        }
    }
    handle
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

/// In order from the sender's first number, with a gap timeout well past
/// the proxy's: a test of the order, not of the skipping.
fn in_order() -> DeliveryConfig {
    let mut cfg = DeliveryConfig::in_order().starting_at(0);
    cfg.gap_timeout = Duration::from_secs(2);
    cfg
}

#[test]
fn in_order_puts_reordered_frames_back_in_sequence() {
    const FRAMES: u64 = 400;
    let (mut sender, receiver, stop) = pair(in_order(), |i| {
        if i % 4 == 1 {
            Act::Hold(3)
        } else {
            Act::Forward
        }
    });
    assert_eq!(receiver.delivery_order(), Some(Order::InOrder));
    let first = sender.next_seq();
    let (receiver, ()) = exchange(
        &mut sender,
        receiver,
        FRAMES,
        |s, n| {
            s.send(n, &pulse(n), &n.to_le_bytes()).unwrap();
        },
        move |r| {
            for n in 0..FRAMES {
                let (p, env, meta) = r.recv().unwrap();
                assert_eq!((meta.seq, p.chain_step), (first + n, n), "out of order");
                assert_eq!(env, n.to_le_bytes());
            }
        },
    );
    assert_eq!(receiver.delivery_skipped_count(), 0);
    stop.store(true, Ordering::Relaxed);
}

#[test]
fn unique_drops_the_copies_a_repeating_network_makes() {
    const FRAMES: u64 = 200;
    let (mut sender, receiver, stop) = pair(DeliveryConfig::unique(), |_| Act::Repeat);
    let (mut receiver, ()) = exchange(
        &mut sender,
        receiver,
        FRAMES,
        |s, n| {
            s.send(n, &pulse(n), b"x").unwrap();
        },
        |r| {
            let mut seen = std::collections::BTreeSet::new();
            for _ in 0..FRAMES {
                let (_, _, meta) = r.recv().unwrap();
                assert!(seen.insert(meta.seq), "seq {} delivered twice", meta.seq);
            }
        },
    );
    receiver
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    assert!(
        receiver.recv().unwrap_err().is_timeout(),
        "a copy came through"
    );
    assert_eq!(receiver.delivery_duplicate_count(), FRAMES);
    stop.store(true, Ordering::Relaxed);
}

/// Nothing more arrives after the gap, and nothing brings it back: the
/// frames behind it come out once it has held them for the gap timeout,
/// though the caller's read timeout is far longer.
#[test]
fn a_gap_that_never_fills_is_skipped_on_time() {
    let mut cfg = DeliveryConfig::in_order().starting_at(0);
    cfg.gap_timeout = Duration::from_millis(30);
    let (mut sender, mut receiver, stop) =
        pair(cfg, |i| if i == 5 { Act::Drop } else { Act::Forward });
    let first = sender.next_seq();
    for n in 0..10 {
        sender.send(n, &pulse(n), b"x").unwrap();
    }
    for n in 0..5 {
        assert_eq!(receiver.recv().unwrap().2.seq, first + n);
    }
    let start = Instant::now();
    assert_eq!(receiver.recv().unwrap().2.seq, first + 6);
    let waited = start.elapsed();
    assert!(
        waited < Duration::from_secs(1),
        "the gap held delivery {waited:?}"
    );
    for n in 7..10 {
        assert_eq!(receiver.recv().unwrap().2.seq, first + n);
    }
    assert_eq!(receiver.delivery_skipped_count(), 1);
    stop.store(true, Ordering::Relaxed);
}

/// Runs of fragments among frames, reordered from the start: each comes
/// out after the numbers before it, a run counting for its whole span. The
/// order is not told where the stream starts, so it starts at the lowest
/// number its first gap timeout sees, though a frame overtakes the first
/// run.
#[test]
fn runs_and_frames_come_out_in_sequence_order() {
    const SENDS: u64 = 60;
    let mut cfg = DeliveryConfig::in_order();
    cfg.gap_timeout = Duration::from_millis(300);
    let (mut sender, mut receiver, stop) = pair(cfg, |i| {
        if i % 5 == 2 {
            Act::Hold(4)
        } else {
            Act::Forward
        }
    });
    sender.enable_fragmentation();
    receiver.enable_reassembly(ReassemblyConfig::default());
    fn envelope(n: u64) -> Vec<u8> {
        let len = if n.is_multiple_of(3) {
            MAX_ENVELOPE * 3 + 7
        } else {
            9
        };
        (0..len).map(|i| (i as u8) ^ (n as u8)).collect()
    }
    // A frame is one number, a run of this envelope three.
    let starts: Vec<u64> = (0..SENDS)
        .scan(sender.next_seq(), |next, n| {
            let start = *next;
            *next += if n.is_multiple_of(3) { 3 } else { 1 };
            Some(start)
        })
        .collect();
    let (receiver, ()) = exchange(
        &mut sender,
        receiver,
        SENDS,
        |s, n| {
            s.send(n, &pulse(n), &envelope(n)).unwrap();
        },
        move |r| {
            for (n, &start) in starts.iter().enumerate() {
                let (p, env, meta) = r.recv().unwrap();
                assert_eq!((p.chain_step, meta.seq), (n as u64, start), "out of order");
                assert!(env == envelope(n as u64), "envelope {n} changed");
            }
        },
    );
    assert_eq!(sender.next_seq(), SENDS + 2 * (SENDS / 3));
    assert_eq!(receiver.reassembled_count(), SENDS / 3);
    assert_eq!(receiver.delivery_skipped_count(), 0);
    stop.store(true, Ordering::Relaxed);
}

#[test]
fn a_batch_receive_delivers_in_order_too() {
    const FRAMES: u64 = 300;
    let (mut sender, receiver, stop) = pair(in_order(), |i| {
        if i % 7 == 3 {
            Act::Hold(5)
        } else {
            Act::Forward
        }
    });
    let first = sender.next_seq();
    exchange(
        &mut sender,
        receiver,
        FRAMES,
        |s, n| {
            s.send(n, &pulse(n), &n.to_le_bytes()).unwrap();
        },
        move |r| {
            let mut bufs = vec![vec![0u8; 64]; 16];
            let mut next = first;
            while next < first + FRAMES {
                let mut slots: Vec<&mut [u8]> = bufs.iter_mut().map(Vec::as_mut_slice).collect();
                let got = r.recv_batch_into(16, &mut slots).unwrap();
                assert!(got.errors.is_empty(), "{:?}", got.errors);
                for (i, (_, len, meta)) in got.frames.iter().enumerate() {
                    assert_eq!(meta.seq, next, "out of order");
                    assert_eq!(&bufs[i][..*len], &(next - first).to_le_bytes());
                    next += 1;
                }
            }
        },
    );
    stop.store(true, Ordering::Relaxed);
}

/// Turned off while frames are held behind a gap, the options deliver
/// them, in order, before anything else.
#[test]
fn turning_delivery_off_delivers_what_it_held() {
    let mut cfg = DeliveryConfig::in_order().starting_at(0);
    cfg.gap_timeout = Duration::from_secs(60);
    let (mut sender, mut receiver, stop) =
        pair(cfg, |i| if i == 1 { Act::Drop } else { Act::Forward });
    receiver
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let first = sender.next_seq();
    for n in 0..5 {
        sender.send(n, &pulse(n), b"x").unwrap();
    }
    assert_eq!(receiver.recv().unwrap().2.seq, first);
    // The caller's timeout, shorter than the gap's, ends the wait.
    assert!(receiver.recv().unwrap_err().is_timeout());
    assert_eq!(receiver.delivery_held_count(), 3);
    receiver.disable_delivery();
    assert_eq!(receiver.delivery_order(), None);
    for n in 2..5 {
        assert_eq!(receiver.recv().unwrap().2.seq, first + n);
    }
    stop.store(true, Ordering::Relaxed);
}
