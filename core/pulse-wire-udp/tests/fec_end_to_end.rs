// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! FEC end to end over a loopback socket pair (`Sender::enable_fec`,
//! `Receiver::enable_fec`):
//!
//! - The sender emits a parity datagram per window of K frames.
//! - The receiver takes parity without handing it to the caller.
//! - A window that loses one frame has it rebuilt and delivered by a later
//!   `recv()`; one that loses two does not.
//! - With FEC off at the receiver, parity is dropped.
//!
//! Loss is made, not waited for: the frame to lose is sent to a black-hole
//! port, which gives a deterministic single-loss window.

use std::net::UdpSocket;
use std::time::Duration;

use pulse_canon::{Instruction, Pulse};
use pulse_wire_udp::{Receiver, Sender};

fn sample_pulse(seq: u64) -> Pulse {
    let mut p = Pulse::zeroed();
    p.instruction = Instruction::Data as u16;
    p.scope = 0xFEC0;
    p.chain_step = seq;
    p.monotonic_nanos = 1_000 + seq;
    p
}

fn pair_with_fec(window_size: u16) -> (Sender, Receiver, std::net::SocketAddr) {
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    let mut receiver = Receiver::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let recv_addr = receiver.local_addr().unwrap();
    sender.connect(recv_addr).unwrap();
    sender.enable_fec(window_size);
    receiver.enable_fec(window_size, 8);
    assert!(sender.fec_enabled());
    assert!(receiver.fec_enabled());
    (sender, receiver, recv_addr)
}

#[test]
fn fec_enable_flips_diagnostic_flags() {
    let (sender, receiver, _) = pair_with_fec(4);
    assert!(sender.fec_enabled());
    assert!(receiver.fec_enabled());
    assert_eq!(sender.parity_sent_count(), 0);
    assert_eq!(receiver.parity_received_count(), 0);
    assert_eq!(receiver.fec_recovered_count(), 0);
}

#[test]
fn full_window_no_loss_emits_parity_consumed_silently() {
    // K=4. Send 4 originals → 1 parity. Receiver should see the 4
    // originals, parity_received should bump to 1, fec_recovered
    // should stay 0 (no loss).
    let (mut sender, mut receiver, _) = pair_with_fec(4);
    for i in 0..4u64 {
        let p = sample_pulse(i);
        sender.send(i * 100, &p, b"abcd").unwrap();
    }
    // Two windows happen in this run: a single window of 4. After
    // the 4th send, parity is emitted.
    let mut got = Vec::new();
    for _ in 0..4 {
        let (_p, env, meta) = receiver.recv().unwrap();
        got.push((meta.seq, env));
    }
    let seqs: Vec<u64> = got.iter().map(|(s, _)| *s).collect();
    assert_eq!(seqs, vec![0, 1, 2, 3]);
    // Drain any pending parity by attempting one more recv with a
    // short timeout — parity should be transparently consumed.
    receiver
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let res = receiver.recv();
    assert!(res.is_err(), "expected timeout, got {res:?}");
    assert_eq!(sender.parity_sent_count(), 1);
    assert_eq!(receiver.parity_received_count(), 1);
    assert_eq!(receiver.fec_recovered_count(), 0);
}

#[test]
fn single_loss_within_window_is_recovered() {
    // K=4. Send seqs 0,1,2 then SKIP seq=3 by writing it to a
    // black-hole port, then the parity will be emitted automatically
    // by send_to of seq=3 and arrive at the receiver. With 3 of 4
    // originals + parity in hand, the decoder can recover seq=3.
    //
    // We simulate the "skip seq=3 on the wire" by pointing the
    // sender at the black hole for that one send, then back to the
    // real receiver for subsequent sends. The producer's seq counter
    // is unaffected (it increments on every send_to call).
    let (mut sender, mut receiver, recv_addr) = pair_with_fec(4);
    let blackhole = UdpSocket::bind("127.0.0.1:0").unwrap();
    let blackhole_addr = blackhole.local_addr().unwrap();
    drop(blackhole);

    for i in 0..4u64 {
        let dest = if i == 2 { blackhole_addr } else { recv_addr };
        let p = sample_pulse(i);
        sender.send_to(i * 100, &p, b"abcd", dest).unwrap();
    }
    // Three originals (0,1,3) + parity for window [0..4) arrive.
    // The receiver must recover seq=2 from parity.
    let mut got = Vec::new();
    for _ in 0..4 {
        let (_p, env, meta) = receiver.recv().unwrap();
        got.push((meta.seq, env));
    }
    let mut seqs: Vec<u64> = got.iter().map(|(s, _)| *s).collect();
    seqs.sort();
    assert_eq!(seqs, vec![0, 1, 2, 3]);
    assert_eq!(sender.parity_sent_count(), 1);
    assert!(
        receiver.parity_received_count() >= 1,
        "expected parity_received >= 1, got {}",
        receiver.parity_received_count()
    );
    assert_eq!(
        receiver.fec_recovered_count(),
        1,
        "expected exactly one recovered frame"
    );
    // The recovered frame must round-trip envelope bytes byte-for-byte.
    for (seq, env) in &got {
        if *seq == 2 {
            assert_eq!(env.as_slice(), b"abcd");
        }
    }
}

#[test]
fn double_loss_within_window_is_not_recovered() {
    // K=4. Drop seq=1 and seq=2. Decoder cannot recover with
    // single-parity XOR; expect 0 recoveries and only 2 originals
    // delivered.
    let (mut sender, mut receiver, recv_addr) = pair_with_fec(4);
    let blackhole = UdpSocket::bind("127.0.0.1:0").unwrap();
    let blackhole_addr = blackhole.local_addr().unwrap();
    drop(blackhole);

    for i in 0..4u64 {
        let dest = if i == 1 || i == 2 {
            blackhole_addr
        } else {
            recv_addr
        };
        let p = sample_pulse(i);
        sender.send_to(i * 100, &p, b"abcd", dest).unwrap();
    }
    let mut got = Vec::new();
    receiver
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    while let Ok((_, env, meta)) = receiver.recv() {
        got.push((meta.seq, env));
    }
    let mut seqs: Vec<u64> = got.iter().map(|(s, _)| *s).collect();
    seqs.sort();
    assert_eq!(seqs, vec![0, 3]);
    assert_eq!(receiver.fec_recovered_count(), 0);
}

#[test]
fn fec_disabled_receiver_drops_parity() {
    // Producer sends with FEC on, receiver does not enable FEC.
    // Parity datagrams must be silently dropped — receiver should
    // see exactly 4 originals and zero parity_received bumps.
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    let mut receiver = Receiver::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let recv_addr = receiver.local_addr().unwrap();
    sender.connect(recv_addr).unwrap();
    sender.enable_fec(4);

    for i in 0..4u64 {
        let p = sample_pulse(i);
        sender.send(i * 100, &p, b"abcd").unwrap();
    }
    let mut got = Vec::new();
    while let Ok((_, _, meta)) = receiver.recv() {
        got.push(meta.seq);
    }
    got.sort();
    assert_eq!(got, vec![0, 1, 2, 3]);
    assert_eq!(receiver.parity_received_count(), 0);
    assert_eq!(receiver.fec_recovered_count(), 0);
    assert_eq!(sender.parity_sent_count(), 1);
}

/// An address nothing listens on: a frame sent there is a frame lost.
fn blackhole() -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap()
}

/// Seq `i`'s envelope: distinct per frame, of varying length, so a rebuilt
/// frame is checked byte for byte and the parity pads shorter frames.
fn envelope(i: u64) -> Vec<u8> {
    vec![i as u8; 4 + (i % 3) as usize * 5]
}

/// Send seqs `range` to `dest`, except `lost`, which goes to a black hole.
/// A window's parity goes where its last frame goes, so a lost last frame
/// loses the parity too.
fn send_range(
    sender: &mut Sender,
    range: std::ops::Range<u64>,
    lost: &[u64],
    dest: std::net::SocketAddr,
) {
    let hole = blackhole();
    for i in range {
        let to = if lost.contains(&i) { hole } else { dest };
        assert_eq!(
            sender
                .send_to(i * 100, &sample_pulse(i), &envelope(i), to)
                .unwrap(),
            i
        );
    }
}

/// Receive `count` frames and check each is the frame sent: seqs in any
/// order, every envelope byte for byte. Returns the seqs sorted.
fn receive_frames(receiver: &mut Receiver, count: usize) -> Vec<u64> {
    let mut seqs = Vec::new();
    for _ in 0..count {
        let (_, env, meta) = receiver.recv().unwrap();
        assert_eq!(env, envelope(meta.seq), "seq {} envelope", meta.seq);
        seqs.push(meta.seq);
    }
    seqs.sort_unstable();
    seqs
}

/// A sender that turns FEC on at a sequence number that is not a multiple
/// of K starts at the next window, as the receiver files frames, and the
/// first full window recovers its loss.
#[test]
fn fec_enabled_mid_stream_recovers_a_loss_in_the_first_full_window() {
    const K: u16 = 4;
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    let mut receiver = Receiver::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    receiver.enable_fec(K, 8);
    let dest = receiver.local_addr().unwrap();

    // Seqs 0 to 4 without FEC; on at seq 5, inside window [4, 8). Seqs 5,
    // 6 and 7 go out without parity, and [8, 12), the first full window,
    // loses seq 10.
    send_range(&mut sender, 0..5, &[], dest);
    sender.enable_fec(K);
    send_range(&mut sender, 5..12, &[10], dest);
    assert_eq!(sender.parity_sent_count(), 1, "parity for [8, 12) only");

    assert_eq!(
        receive_frames(&mut receiver, 12),
        (0..12).collect::<Vec<_>>()
    );
    assert_eq!(receiver.fec_recovered_count(), 1);
    assert_eq!(receiver.fec_refused_count(), 0);
}

/// FEC switched off inside a window and on again inside another lines up
/// with the receiver each time, and so does enabling it again while on:
/// the window in progress goes without parity, and the next full window
/// recovers its loss.
#[test]
fn fec_switched_off_and_on_again_lines_up_with_the_receiver() {
    const K: u16 = 4;
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    let mut receiver = Receiver::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    receiver.enable_fec(K, 8);
    let dest = receiver.local_addr().unwrap();

    // On from seq 0: [0, 4) loses seq 1. Off at seq 6, inside [4, 8), and
    // on again at seq 9, inside [8, 12): [12, 16) loses seq 13.
    sender.enable_fec(K);
    send_range(&mut sender, 0..6, &[1], dest);
    sender.disable_fec();
    assert!(!sender.fec_enabled());
    send_range(&mut sender, 6..9, &[], dest);
    sender.enable_fec(K);
    send_range(&mut sender, 9..18, &[13], dest);
    // Enabled again while on, at seq 18 inside [16, 20): that window goes
    // without parity, and [20, 24) loses seq 22.
    sender.enable_fec(K);
    send_range(&mut sender, 18..24, &[22], dest);
    assert_eq!(
        sender.parity_sent_count(),
        3,
        "parity for [0, 4), [12, 16) and [20, 24)"
    );

    assert_eq!(
        receive_frames(&mut receiver, 24),
        (0..24).collect::<Vec<_>>()
    );
    assert_eq!(receiver.fec_recovered_count(), 3);
}

/// A few forged parity datagrams for windows far above the stream, which
/// anyone who can reach the receiver's port could send, cannot hold its
/// window table: parity alone never pushes out a window frames are filling,
/// and once frames have arrived, parity far beyond them is refused and
/// counted.
#[test]
fn a_burst_of_forged_parity_does_not_turn_recovery_off() {
    use pulse_wire_udp::{encode_fec, FecHeader};

    const K: u16 = 4;
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    let mut receiver = Receiver::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    receiver.enable_fec(K, 8);
    let dest = receiver.local_addr().unwrap();
    sender.enable_fec(K);

    let forger = UdpSocket::bind("127.0.0.1:0").unwrap();
    let burst = |starts: &mut dyn Iterator<Item = u64>, window_n: u16| {
        for window_start in starts {
            let mut datagram = Vec::new();
            let header = FecHeader {
                window_start,
                window_n,
                parity_len: 16,
            };
            encode_fec(header, &[0x5A; 16], &mut datagram);
            forger.send_to(&datagram, dest).unwrap();
        }
    };
    let high = u64::MAX / 4 * 4 - 1024;

    // Before any frame: eight windows far above the stream, sized and
    // aligned as the sender's, fill the table.
    burst(&mut (0..8).map(|i| high - 4 * i), K);
    // [0, 4) loses seq 2.
    send_range(&mut sender, 0..4, &[2], dest);
    // Now that frames have arrived: eight more far above them, two of
    // another window size and two unaligned.
    burst(&mut (8..16).map(|i| high - 4 * i), K);
    burst(&mut [8u64, 12].into_iter(), 2 * K);
    burst(&mut [9u64, 14].into_iter(), K);
    // [4, 8) loses seq 5 and [8, 12) loses seq 10.
    send_range(&mut sender, 4..12, &[5, 10], dest);

    assert_eq!(
        receive_frames(&mut receiver, 12),
        (0..12).collect::<Vec<_>>()
    );
    assert_eq!(receiver.fec_recovered_count(), 3);
    assert_eq!(receiver.fec_refused_count(), 12);
}
