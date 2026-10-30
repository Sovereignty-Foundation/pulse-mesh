// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Fragmentation end to end on loopback: envelopes up to MAX_MESSAGE go as
//! runs of fragments and come back whole; through a proxy that drops a
//! share of the datagrams, NACK retransmission or FEC fills the gaps.

use std::collections::BTreeSet;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use pulse_canon::{Instruction, Pulse};
use pulse_wire_udp::{
    BackpressureConfig, BatchSendError, ReassemblyConfig, Receiver, ReceiverError, Sender,
    SenderError, WireError, FEC_MAGIC, FRAG_MAGIC, MAX_ENVELOPE, MAX_MESSAGE,
};

fn pulse(step: u64) -> Pulse {
    let mut p = Pulse::zeroed();
    p.instruction = Instruction::Data as u16;
    p.chain_step = step;
    p.monotonic_nanos = 1;
    p
}

fn envelope(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31) ^ seed)
        .collect()
}

/// A proxy that forwards to `to`, dropping, the first time each passes,
/// the fragments and frames `drop` picks by sequence number. Parity
/// always passes.
fn proxy(
    to: SocketAddr,
    drop: impl Fn(u64) -> bool + Send + 'static,
    stop: Arc<AtomicBool>,
) -> SocketAddr {
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
            let d = &buf[..n];
            let magic = u32::from_le_bytes(d[..4].try_into().unwrap());
            if magic != FEC_MAGIC && n >= 13 {
                let seq = u64::from_le_bytes(d[5..13].try_into().unwrap());
                if drop(seq) && dropped.insert(seq) {
                    continue;
                }
            }
            let _ = socket.send_to(d, to);
        }
    });
    addr
}

/// A fragmenting sender and a reassembling receiver, through a proxy that
/// drops what `drop` picks.
fn pair(
    nack: bool,
    fec: Option<u16>,
    drop: impl Fn(u64) -> bool + Send + 'static,
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
            drop,
            Arc::clone(&stop),
        ))
        .unwrap();
    sender.enable_fragmentation();
    receiver.enable_reassembly(ReassemblyConfig::default());
    if nack {
        let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut cfg = BackpressureConfig::new(any, any).with_nack(4096);
        cfg.target_queue_depth = 256;
        sender.enable_backpressure(cfg.clone()).unwrap();
        cfg.ack_target_addr = sender.ack_local_addr().unwrap();
        receiver.enable_backpressure(cfg).unwrap();
    }
    if let Some(window) = fec {
        sender.enable_fec(window);
        receiver.enable_fec(window, 64);
    }
    (sender, receiver, stop)
}

#[test]
fn envelopes_up_to_max_message_cross_whole() {
    let (mut sender, mut receiver, stop) = pair(false, None, |_| false);
    assert_eq!(sender.envelope_limit(), MAX_MESSAGE);
    for (i, len) in [
        0,
        MAX_ENVELOPE,
        MAX_ENVELOPE + 1,
        5_000,
        40_000,
        MAX_MESSAGE,
    ]
    .into_iter()
    .enumerate()
    {
        let env = envelope(len, i as u8);
        let first = sender.send(i as u64, &pulse(i as u64), &env).unwrap();
        let (p, got, meta) = receiver.recv().unwrap();
        assert_eq!(got.len(), len);
        assert!(got == env, "envelope of {len} bytes changed");
        assert_eq!(
            (p.chain_step, meta.seq, meta.send_ns),
            (i as u64, first, i as u64)
        );
    }
    assert_eq!(
        receiver.reassembled_count(),
        4,
        "the four longer than a frame were runs"
    );
    stop.store(true, Ordering::Relaxed);
}

/// About one datagram in a hundred dropped: NACK brings each back, and
/// every envelope arrives intact. A sender retransmits only as it sends, so
/// it keeps sending small envelopes until the receiver has every run.
#[test]
fn with_one_percent_loss_nack_brings_every_run_back() {
    const RUNS: usize = 20;
    let (mut sender, mut receiver, stop) = pair(true, None, |seq| seq % 97 == 13);
    let envs: Vec<Vec<u8>> = (0..RUNS)
        .map(|i| envelope(MAX_MESSAGE - i * 1000, i as u8))
        .collect();
    let done = Arc::new(AtomicBool::new(false));
    let finished = Arc::clone(&done);
    let received = thread::spawn(move || {
        let mut got = std::collections::BTreeMap::new();
        while got.len() < RUNS {
            let (p, env, _) = receiver.recv().expect("every run arrives");
            if (p.chain_step as usize) < RUNS {
                got.insert(p.chain_step as usize, env);
            }
        }
        finished.store(true, Ordering::Release);
        (got, receiver.reassembly_dropped_count())
    });
    for (i, env) in envs.iter().enumerate() {
        sender.send(0, &pulse(i as u64), env).unwrap();
    }
    while !done.load(Ordering::Acquire) {
        sender.send(0, &pulse(1_000), b"tail").unwrap();
        thread::sleep(Duration::from_millis(2));
    }
    let (got, dropped) = received.join().unwrap();
    stop.store(true, Ordering::Relaxed);
    assert!(sender.retransmit_count() > 0, "nothing was lost and resent");
    assert_eq!(dropped, 0);
    for (i, env) in envs.iter().enumerate() {
        assert!(got[&i] == *env, "envelope {i} did not arrive intact");
    }
}

/// One fragment lost per FEC window is rebuilt from parity, without a
/// round trip, and the run completes.
#[test]
fn a_fragment_lost_from_a_window_is_rebuilt_by_fec() {
    let (mut sender, mut receiver, stop) = pair(false, Some(8), |seq| seq % 8 == 3);
    let env = envelope(20_000, 9);
    sender.send(0, &pulse(1), &env).unwrap();
    // Fill the last window, so its parity goes out.
    while sender.parity_sent_count() * 8 < sender.next_seq() {
        sender.send(0, &pulse(2), b"pad").unwrap();
    }
    let mut found = false;
    for _ in 0..16 {
        match receiver.recv() {
            Ok((p, got, _)) if p.chain_step == 1 => {
                assert!(got == env);
                found = true;
                break;
            }
            Ok(_) => {}
            Err(e) => panic!("{e}"),
        }
    }
    stop.store(true, Ordering::Relaxed);
    assert!(found, "the run was not rebuilt");
    assert!(receiver.fec_rebuilt_fragment_count() > 0);
}

/// The run's last fragment, shorter than the rest, lost: FEC rebuilds it
/// padded to its window's longest datagram, and the chunk length in its
/// header keeps the padding out of the envelope.
#[test]
fn a_short_last_fragment_rebuilt_with_padding_completes_its_run() {
    let env = envelope(10_000, 5);
    let probe = Sender::bind("127.0.0.1:0").unwrap();
    let mut with_fec = probe;
    with_fec.enable_fec(16);
    let count =
        pulse_wire_udp::fragment::encode_fragments(0, 0, &pulse(0), &env, with_fec.max_datagram())
            .unwrap()
            .len() as u64;
    let last = count - 1;
    let (mut sender, mut receiver, stop) = pair(false, Some(16), move |seq| seq == last);
    sender.send(0, &pulse(1), &env).unwrap();
    while sender.next_seq() % 16 != 0 {
        sender.send(0, &pulse(2), b"pad").unwrap();
    }
    let mut found = false;
    for _ in 0..32 {
        let (p, got, _) = receiver.recv().unwrap();
        if p.chain_step == 1 {
            assert!(got == env, "the padding reached the envelope");
            found = true;
            break;
        }
    }
    stop.store(true, Ordering::Relaxed);
    assert!(found, "the run was not completed");
}

#[test]
fn without_reassembly_fragments_are_dropped_and_counted() {
    let (mut sender, mut receiver, stop) = pair(false, None, |_| false);
    receiver.disable_reassembly();
    sender.send(0, &pulse(1), &envelope(5_000, 0)).unwrap();
    sender.send(0, &pulse(2), b"small").unwrap();
    let (p, env, _) = receiver.recv().unwrap();
    assert_eq!((p.chain_step, env.as_slice()), (2, &b"small"[..]));
    assert_eq!(receiver.fragments_dropped_count(), 4);
    stop.store(true, Ordering::Relaxed);
}

#[test]
fn what_cannot_go_is_refused_before_anything_is_sent() {
    let (mut sender, mut receiver, stop) = pair(false, None, |_| false);
    let next = sender.next_seq();
    assert!(matches!(
        sender.send(0, &pulse(0), &envelope(MAX_MESSAGE + 1, 0)),
        Err(SenderError::Encode(WireError::EnvelopeTooLarge {
            max: MAX_MESSAGE,
            ..
        }))
    ));
    assert_eq!(sender.next_seq(), next);
    // A batch goes frame by frame: no runs.
    let big = envelope(MAX_ENVELOPE + 1, 0);
    let p = pulse(0);
    let dest = receiver.local_addr().unwrap();
    assert!(matches!(
        sender.send_batch(&[(0, &p, big.as_slice())], dest),
        Err(BatchSendError::FrameError {
            index: 0,
            error: SenderError::Encode(WireError::EnvelopeTooLarge { .. })
        })
    ));
    // A run longer than the caller's buffer is reported, as a long frame is.
    sender.send(0, &pulse(3), &envelope(3_000, 0)).unwrap();
    let mut small = [0u8; 100];
    assert!(matches!(
        receiver.recv_into(&mut small),
        Err(ReceiverError::BufferTooSmall {
            needed: 3_000,
            provided: 100
        })
    ));
    let _ = FRAG_MAGIC;
    stop.store(true, Ordering::Relaxed);
}
