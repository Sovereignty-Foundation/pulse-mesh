// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for [`Sender::send_batch`] and
//! [`Receiver::recv_batch_into`] — the explicit-batch sendmmsg(2) /
//! recvmmsg(2) paths. Each test exercises a sender + receiver pair on
//! `127.0.0.1` loopback. On Linux the fast paths are active; on other
//! substrates the fallback serial loops run.

use std::time::Duration;

use pulse_canon::Pulse;
use pulse_wire_udp::{
    BatchRecvError, BatchSendError, Receiver, Sender, SenderError, MAX_BATCH_FRAMES, MAX_ENVELOPE,
};

/// Send 10 frames via `send_batch` in a single syscall; receive all 10
/// individually. Asserts byte-exact wire equivalence with the
/// per-frame send_to path.
#[test]
fn batch_send_round_trips_ten_frames() {
    let mut receiver = Receiver::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .socket()
        .set_read_timeout(Some(Duration::from_secs(2)))
        .ok();
    let recv_addr = receiver.local_addr().expect("local_addr");

    let mut sender = Sender::bind("127.0.0.1:0").expect("bind sender");

    // Build 10 distinct frames with predictable envelope contents.
    let mut envelopes: Vec<Vec<u8>> = Vec::new();
    for i in 0u8..10 {
        // 64-byte envelope filled with the frame index so we can verify
        // ordering at the receiver.
        envelopes.push(vec![i; 64]);
    }
    let pulse = Pulse::zeroed();
    let frames: Vec<(u64, &Pulse, &[u8])> = (0..10)
        .map(|i| (1_000_000 + i as u64, &pulse, envelopes[i].as_slice()))
        .collect();

    let seqs = sender
        .send_batch(&frames, recv_addr)
        .expect("send_batch should succeed");
    assert_eq!(seqs.len(), 10);
    // Seqs should be 0..10 (sender starts at 0 in this fresh instance).
    for (i, seq) in seqs.iter().enumerate() {
        assert_eq!(*seq, i as u64);
    }

    // Receive 10 frames, each must match the corresponding envelope.
    for expected_i in 0u8..10 {
        let (_pulse, envelope, meta) = receiver
            .recv()
            .expect("recv should succeed for batched datagram");
        assert_eq!(envelope.len(), 64);
        assert!(
            envelope.iter().all(|&b| b == expected_i),
            "frame {} envelope bytes mismatch",
            expected_i
        );
        assert_eq!(meta.seq, expected_i as u64);
    }
}

/// Empty batch is a no-op that returns an empty seq vec.
#[test]
fn batch_send_empty_returns_empty() {
    let receiver = Receiver::bind("127.0.0.1:0").expect("bind receiver");
    let recv_addr = receiver.local_addr().expect("local_addr");
    let mut sender = Sender::bind("127.0.0.1:0").expect("bind sender");

    let frames: Vec<(u64, &Pulse, &[u8])> = Vec::new();
    let seqs = sender.send_batch(&frames, recv_addr).expect("send_batch");
    assert!(seqs.is_empty());
    assert_eq!(sender.next_seq(), 0);
}

/// Batch larger than [`MAX_BATCH_FRAMES`] is rejected with the proper
/// error variant.
#[test]
fn batch_too_large_rejected() {
    let receiver = Receiver::bind("127.0.0.1:0").expect("bind receiver");
    let recv_addr = receiver.local_addr().expect("local_addr");
    let mut sender = Sender::bind("127.0.0.1:0").expect("bind sender");

    let pulse = Pulse::zeroed();
    let env = vec![0u8; 16];
    // Build MAX_BATCH_FRAMES + 1 frames.
    let frames: Vec<(u64, &Pulse, &[u8])> = (0..MAX_BATCH_FRAMES + 1)
        .map(|i| (i as u64, &pulse, env.as_slice()))
        .collect();

    let err = sender.send_batch(&frames, recv_addr).unwrap_err();
    match err {
        BatchSendError::BatchTooLarge { got, max } => {
            assert_eq!(got, MAX_BATCH_FRAMES + 1);
            assert_eq!(max, MAX_BATCH_FRAMES);
        }
        other => panic!("expected BatchTooLarge, got {other:?}"),
    }
}

// ── recv_batch_into tests ────────────────────────────────────────────────────

/// Send 10 frames via [`Sender::send_batch`], receive all 10 in one
/// [`Receiver::recv_batch_into`] call. Asserts that every frame's
/// envelope, seq, and byte content round-trips correctly.
#[test]
fn batch_recv_round_trips_ten_frames() {
    let mut receiver = Receiver::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .socket()
        .set_read_timeout(Some(Duration::from_secs(2)))
        .ok();
    let recv_addr = receiver.local_addr().expect("local_addr");
    let mut sender = Sender::bind("127.0.0.1:0").expect("bind sender");

    let pulse = Pulse::zeroed();
    // Each frame's envelope is 64 bytes filled with its index (0..10).
    let envelopes: Vec<Vec<u8>> = (0u8..10).map(|i| vec![i; 64]).collect();
    let frames: Vec<(u64, &Pulse, &[u8])> = (0..10)
        .map(|i| (i as u64, &pulse, envelopes[i].as_slice()))
        .collect();
    sender.send_batch(&frames, recv_addr).expect("send_batch");

    // Let all 10 datagrams settle into the kernel socket buffer before
    // calling recv_batch_into (loopback delivery is essentially instant).
    std::thread::sleep(Duration::from_millis(5));

    // Caller-owned envelope buffers — one per potential frame. A call takes
    // the datagrams already queued, and a loopback that queues them
    // asynchronously (macOS) can split them across calls, so receive until
    // all ten have been read.
    let mut raw: Vec<Vec<u8>> = (0..10).map(|_| vec![0u8; MAX_ENVELOPE]).collect();
    let mut got: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut received = 0;
    while received < 10 {
        let result = {
            let mut refs: Vec<&mut [u8]> = raw.iter_mut().map(|b| b.as_mut_slice()).collect();
            receiver
                .recv_batch_into(10 - received, &mut refs)
                .expect("recv_batch_into")
        };
        assert!(
            result.errors.is_empty(),
            "unexpected frame errors: {:?}",
            result
                .errors
                .iter()
                .map(|e| format!("[{}] {}", e.frame_index, e.error))
                .collect::<Vec<_>>()
        );
        assert_eq!(result.frames.len(), result.received);
        received += result.received;
        for (j, (_p, env_len, meta)) in result.frames.iter().enumerate() {
            got.push((meta.seq, raw[j][..*env_len].to_vec()));
        }
    }
    assert_eq!(got.len(), 10, "expected 10 decoded frames");

    for (j, (seq, envelope)) in got.iter().enumerate() {
        assert_eq!(envelope.len(), 64, "frame {} envelope length", j);
        assert_eq!(*seq, j as u64, "frame {} seq", j);
        assert!(
            envelope.iter().all(|&b| b == j as u8),
            "frame {} envelope content mismatch",
            j
        );
    }
}

/// A corrupt datagram (bad magic bytes) in the middle of a batch is
/// returned in [`BatchRecvResult::errors`] while surrounding valid
/// frames are delivered normally.
///
/// Setup: 4 valid frames → 1 corrupt (bad magic) → recv_batch_into(5)
/// Expected: result.frames.len() == 4, result.errors.len() == 1,
///           errors[0].frame_index == 4
#[test]
fn batch_recv_partial_on_decode_error() {
    use std::net::UdpSocket;

    let mut receiver = Receiver::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .socket()
        .set_read_timeout(Some(Duration::from_secs(2)))
        .ok();
    let recv_addr = receiver.local_addr().expect("local_addr");
    let mut sender = Sender::bind("127.0.0.1:0").expect("bind sender");

    // Send 4 valid frames.
    let pulse = Pulse::zeroed();
    let env = vec![0xAB; 32];
    let frames: Vec<(u64, &Pulse, &[u8])> =
        (0..4).map(|i| (i as u64, &pulse, env.as_slice())).collect();
    sender.send_batch(&frames, recv_addr).expect("send_batch");

    // Send 1 corrupt datagram with bad magic (just 100 bytes of 0xFF).
    let raw_sock = UdpSocket::bind("127.0.0.1:0").expect("bind raw sender");
    raw_sock
        .send_to(&[0xFF; 100], recv_addr)
        .expect("send corrupt");

    std::thread::sleep(Duration::from_millis(5));

    // A call takes the datagrams already queued, so receive until all five
    // have been read, numbering each error by its datagram's position in
    // the whole sequence rather than in its call.
    let mut raw: Vec<Vec<u8>> = (0..5).map(|_| vec![0u8; MAX_ENVELOPE]).collect();
    let mut received = 0;
    let mut frames = 0;
    let mut errors = Vec::new();
    while received < 5 {
        let result = {
            let mut refs: Vec<&mut [u8]> = raw.iter_mut().map(|b| b.as_mut_slice()).collect();
            receiver
                .recv_batch_into(5 - received, &mut refs)
                .expect("recv_batch_into")
        };
        frames += result.frames.len();
        for e in result.errors {
            errors.push((received + e.frame_index, e.error));
        }
        received += result.received;
    }

    assert_eq!(received, 5, "5 datagrams should have been read");
    assert_eq!(frames, 4, "4 valid frames should decode successfully");
    assert_eq!(
        errors.len(),
        1,
        "exactly 1 frame should be in the error list"
    );
    // The corrupt datagram was sent last so it is the fifth datagram read.
    assert_eq!(errors[0].0, 4, "corrupt datagram is at position 4");
    assert!(
        matches!(
            errors[0].1,
            pulse_wire_udp::ReceiverError::Decode(pulse_wire_udp::WireError::BadMagic { .. })
        ),
        "{:?}",
        errors[0].1
    );
}

/// [`Receiver::recv_batch_into`] returns [`BatchRecvError::InsufficientBuffers`]
/// when the caller provides fewer envelope buffers than `max_frames`.
#[test]
fn batch_recv_insufficient_buffers_error() {
    let mut receiver = Receiver::bind("127.0.0.1:0").expect("bind receiver");

    // Only 3 envelope buffers for max_frames = 5.
    let mut raw: Vec<Vec<u8>> = (0..3).map(|_| vec![0u8; MAX_ENVELOPE]).collect();
    let mut refs: Vec<&mut [u8]> = raw.iter_mut().map(|b| b.as_mut_slice()).collect();

    let err = receiver.recv_batch_into(5, &mut refs).unwrap_err();
    match err {
        BatchRecvError::InsufficientBuffers { buffers, requested } => {
            assert_eq!(buffers, 3);
            assert_eq!(requested, 5);
        }
        other => panic!("expected InsufficientBuffers, got {other:?}"),
    }
}

/// Sequence numbers advance correctly when batch mixes with per-frame
/// `send_to` calls.
#[test]
fn batch_seq_interleaves_with_send_to() {
    let mut receiver = Receiver::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .socket()
        .set_read_timeout(Some(Duration::from_secs(2)))
        .ok();
    let recv_addr = receiver.local_addr().expect("local_addr");
    let mut sender = Sender::bind("127.0.0.1:0").expect("bind sender");

    let pulse = Pulse::zeroed();
    let env_a = vec![0xAA; 32];
    let env_b = vec![0xBB; 32];

    // 1) Single send_to → seq 0
    let s0 = sender.send_to(100, &pulse, &env_a, recv_addr).unwrap();
    // 2) Batch of 3 → seqs 1, 2, 3
    let batch: Vec<(u64, &Pulse, &[u8])> =
        (0..3).map(|_| (200, &pulse, env_b.as_slice())).collect();
    let batch_seqs = sender.send_batch(&batch, recv_addr).unwrap();
    // 3) Another single send_to → seq 4
    let s4 = sender.send_to(300, &pulse, &env_a, recv_addr).unwrap();

    assert_eq!(s0, 0);
    assert_eq!(batch_seqs, vec![1, 2, 3]);
    assert_eq!(s4, 4);
    assert_eq!(sender.next_seq(), 5);

    // Drain all 5 frames and verify each seq round-trips.
    let mut seen_seqs = Vec::new();
    for _ in 0..5 {
        let (_p, _env, meta) = receiver.recv().expect("recv");
        seen_seqs.push(meta.seq);
    }
    seen_seqs.sort();
    assert_eq!(seen_seqs, vec![0, 1, 2, 3, 4]);
}

/// Every sequence number `receiver` delivers until a read times out.
fn drain_seqs(receiver: &mut Receiver) -> Vec<u64> {
    receiver
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set read timeout");
    let mut seqs = Vec::new();
    loop {
        match receiver.recv() {
            Ok((_, _, meta)) => seqs.push(meta.seq),
            Err(e) if e.is_timeout() => return seqs,
            Err(e) => panic!("recv failed: {e}"),
        }
    }
}

/// A frame that cannot be encoded ends the batch at its index after the
/// frames before it went out, on every platform, so `FrameError`'s "the
/// frames before `index` were sent" holds for the `sendmmsg(2)` path too.
#[test]
fn a_frame_that_fails_to_encode_ends_the_batch_after_the_frames_before_it() {
    let mut receiver = Receiver::bind("127.0.0.1:0").expect("bind receiver");
    let recv_addr = receiver.local_addr().expect("local_addr");
    let mut sender = Sender::bind("127.0.0.1:0").expect("bind sender");

    let pulse = Pulse::zeroed();
    let small = vec![0x11; 16];
    let too_big = vec![0x22; MAX_ENVELOPE + 1];
    let frames: Vec<(u64, &Pulse, &[u8])> = vec![
        (0, &pulse, small.as_slice()),
        (1, &pulse, small.as_slice()),
        (2, &pulse, too_big.as_slice()),
        (3, &pulse, small.as_slice()),
    ];
    match sender.send_batch(&frames, recv_addr) {
        Err(BatchSendError::FrameError {
            index: 2,
            error: SenderError::Encode(_),
        }) => {}
        other => panic!("expected the third frame to fail its encode, got {other:?}"),
    }
    assert_eq!(
        sender.next_seq(),
        2,
        "only the frames before the failure use sequence numbers"
    );
    assert_eq!(drain_seqs(&mut receiver), vec![0, 1]);
}

/// On Linux `send_batch` goes through `sendmmsg(2)` under the same rule and
/// deadline as `send_to`: a batch four times the target depth waits for
/// the receiver's acknowledgements and arrives whole and in order, and once
/// the receiver stops acknowledging new frames the next batch sends exactly
/// the depth's worth and fails with `Stalled` at the deadline, leaving the
/// unsent frames' sequence numbers unused.
#[cfg(target_os = "linux")]
#[test]
fn a_sendmmsg_batch_past_the_depth_waits_for_the_receiver_then_stalls() {
    use std::net::SocketAddr;
    use std::thread;
    use std::time::Instant;

    use pulse_wire_udp::BackpressureConfig;

    const DEPTH: u32 = 4;
    const BATCH: usize = 16;
    const PAUSE: Duration = Duration::from_millis(100);
    const DEADLINE: Duration = Duration::from_millis(500);

    let mut receiver = Receiver::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    let recv_addr = receiver.local_addr().expect("local_addr");
    let mut sender = Sender::bind("127.0.0.1:0").expect("bind sender");
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut cfg = BackpressureConfig::new(any, any).with_stall_timeout(Some(DEADLINE));
    cfg.target_queue_depth = DEPTH;
    sender.enable_backpressure(cfg.clone()).unwrap();
    cfg.ack_target_addr = sender.ack_local_addr().unwrap();
    receiver.enable_backpressure(cfg).unwrap();

    let pulse = Pulse::zeroed();
    let envelopes: Vec<Vec<u8>> = (0..BATCH).map(|i| vec![i as u8; 32]).collect();
    let frames: Vec<(u64, &Pulse, &[u8])> = envelopes
        .iter()
        .enumerate()
        .map(|(i, e)| (i as u64, &pulse, e.as_slice()))
        .collect();

    // The receiver starts reading only after a pause, so the batch puts
    // DEPTH frames in flight and then has to wait for acknowledgements.
    let reader = thread::spawn(move || {
        thread::sleep(PAUSE);
        let seqs: Vec<u64> = (0..BATCH)
            .map(|_| receiver.recv().expect("recv").2.seq)
            .collect();
        (receiver, seqs)
    });
    let started = Instant::now();
    let seqs = sender
        .send_batch(&frames, recv_addr)
        .expect("the batch waits for the receiver");
    let took = started.elapsed();
    let (mut receiver, delivered) = reader.join().unwrap();
    assert_eq!(seqs, (0..BATCH as u64).collect::<Vec<_>>());
    assert_eq!(delivered, seqs, "every frame arrives, once and in order");
    assert!(
        took >= PAUSE / 2,
        "the batch did not wait for the receiver: {took:?}"
    );

    // The receiver stops reading, so its cursor, and every ACK it sends,
    // stays at BATCH.
    let converged = Instant::now();
    while sender.observed_recv_cursor() != BATCH as u64
        && converged.elapsed() < Duration::from_secs(2)
    {
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(sender.observed_recv_cursor(), BATCH as u64);
    let started = Instant::now();
    match sender.send_batch(&frames, recv_addr) {
        Err(BatchSendError::FrameError {
            index,
            error: SenderError::Stalled { in_flight, waited },
        }) => {
            assert_eq!(
                index, DEPTH as usize,
                "the batch stopped at the wrong frame"
            );
            assert_eq!(in_flight, u64::from(DEPTH));
            assert!(waited >= DEADLINE, "gave up after {waited:?}");
        }
        other => panic!("expected frame {DEPTH} to stall, got {other:?}"),
    }
    let took = started.elapsed();
    assert!(
        took >= DEADLINE && took < 4 * DEADLINE,
        "the stall lasted {took:?} against a {DEADLINE:?} deadline"
    );
    let resume_at = BATCH as u64 + u64::from(DEPTH);
    assert_eq!(
        sender.next_seq(),
        resume_at,
        "the unsent frames must not use sequence numbers"
    );
    // Exactly the depth's worth of the second batch went out, in order.
    assert_eq!(
        drain_seqs(&mut receiver),
        (BATCH as u64..resume_at).collect::<Vec<_>>()
    );
}

/// Every datagram waiting on `socket`, in arrival order, until a read
/// times out.
#[cfg(target_os = "linux")]
fn drain_datagrams(socket: &std::net::UdpSocket) -> Vec<Vec<u8>> {
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set read timeout");
    let mut buf = vec![0u8; pulse_wire_udp::MTU_BYTES];
    let mut datagrams = Vec::new();
    while let Ok(n) = socket.recv(&mut buf) {
        datagrams.push(buf[..n].to_vec());
    }
    datagrams
}

/// With NACK on, every frame a `sendmmsg(2)` batch sends is cached, and a
/// NACK for one is answered with the bytes it first went out with. The
/// request is drained ahead of the next batch's frames, as `send_to`
/// drains it ahead of its frame.
#[cfg(target_os = "linux")]
#[test]
fn a_nack_for_a_batch_frame_is_answered_with_its_cached_bytes() {
    use std::net::{SocketAddr, UdpSocket};
    use std::thread;
    use std::time::Instant;

    use pulse_wire_udp::{encode_nack, wire, BackpressureConfig};

    let sink = UdpSocket::bind("127.0.0.1:0").expect("bind sink");
    let sink_addr = sink.local_addr().expect("local_addr");
    let mut sender = Sender::bind("127.0.0.1:0").expect("bind sender");
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    // A loose depth: nobody acknowledges, and the test is about NACKs.
    let mut cfg = BackpressureConfig::new(any, any).with_nack(64);
    cfg.target_queue_depth = 4096;
    sender.enable_backpressure(cfg).unwrap();

    let pulse = Pulse::zeroed();
    let envelopes: Vec<Vec<u8>> = (0..8u8)
        .map(|i| vec![0xA0 | i; 16 + usize::from(i)])
        .collect();
    let frames: Vec<(u64, &Pulse, &[u8])> = envelopes
        .iter()
        .enumerate()
        .map(|(i, e)| (i as u64, &pulse, e.as_slice()))
        .collect();
    assert_eq!(
        sender.send_batch(&frames, sink_addr).unwrap(),
        (0..8).collect::<Vec<_>>()
    );
    let originals = drain_datagrams(&sink);
    assert_eq!(originals.len(), 8);
    assert_eq!(wire::decode(&originals[3]).unwrap().seq, 3);

    // The receiver asks for seq 3 again.
    let requester = UdpSocket::bind("127.0.0.1:0").expect("bind requester");
    let mut nack = Vec::new();
    encode_nack(3, &mut nack);
    requester
        .send_to(&nack, sender.ack_local_addr().unwrap())
        .unwrap();

    // The feedback thread stages the request as it arrives, and the next
    // batch drains it; send one-frame batches until one has.
    let started = Instant::now();
    let mut next = 8u64;
    while sender.retransmit_count() == 0 && started.elapsed() < Duration::from_secs(2) {
        thread::sleep(Duration::from_millis(5));
        let one = [(next, &pulse, envelopes[0].as_slice())];
        assert_eq!(sender.send_batch(&one, sink_addr).unwrap(), vec![next]);
        next += 1;
    }
    assert_eq!(sender.retransmit_count(), 1, "the NACK was never answered");
    assert_eq!(
        sender.cache_miss_count(),
        0,
        "the batch frame was not cached"
    );

    // Every one-frame batch went out, and the one that drained the request
    // sent the retransmission first: seq 3, byte for byte as it first went.
    let after = drain_datagrams(&sink);
    assert_eq!(after.len() as u64, next - 8 + 1);
    assert_eq!(
        after[after.len() - 2],
        originals[3],
        "the retransmission is not the frame as first sent"
    );
    assert_eq!(wire::decode(&after[after.len() - 1]).unwrap().seq, next - 1);
}

/// With FEC on, a `sendmmsg(2)` batch feeds every frame it sends to the
/// parity encoder and sends each window's parity right after the window's
/// last frame, so a frame lost from a batch window is rebuilt from the
/// batch's own parity.
#[cfg(target_os = "linux")]
#[test]
fn a_frame_lost_from_a_batch_window_is_rebuilt_from_the_batch_parity() {
    use std::net::UdpSocket;

    use pulse_wire_udp::{decode_fec, wire};

    const K: u16 = 4;
    // The batch goes to a relay that plays a lossy link to the receiver.
    let relay = UdpSocket::bind("127.0.0.1:0").expect("bind relay");
    let mut receiver = Receiver::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    receiver.enable_fec(K, 8);
    let mut sender = Sender::bind("127.0.0.1:0").expect("bind sender");
    sender.enable_fec(K);

    // Envelopes of different lengths, so the parity pads the shorter
    // frames; the one lost below is the shortest of its window.
    let pulse = Pulse::zeroed();
    let envelopes: Vec<Vec<u8>> = (0..8u8)
        .map(|i| vec![0xC0 | i; 8 + 8 * usize::from((i + 1) % 3)])
        .collect();
    let frames: Vec<(u64, &Pulse, &[u8])> = envelopes
        .iter()
        .enumerate()
        .map(|(i, e)| (i as u64, &pulse, e.as_slice()))
        .collect();
    assert_eq!(
        sender
            .send_batch(&frames, relay.local_addr().unwrap())
            .unwrap(),
        (0..8).collect::<Vec<_>>()
    );
    assert_eq!(sender.parity_sent_count(), 2);

    // On the wire: each window's four frames, then that window's parity.
    let datagrams = drain_datagrams(&relay);
    let seqs_on_wire: Vec<Option<u64>> = datagrams
        .iter()
        .map(|d| wire::decode(d).ok().map(|f| f.seq))
        .collect();
    assert_eq!(
        seqs_on_wire,
        vec![
            Some(0),
            Some(1),
            Some(2),
            Some(3),
            None,
            Some(4),
            Some(5),
            Some(6),
            Some(7),
            None
        ]
    );
    for (at, window_start) in [(4usize, 0u64), (9, 4)] {
        let (header, _) = decode_fec(&datagrams[at]).expect("a parity datagram");
        assert_eq!((header.window_start, header.window_n), (window_start, K));
    }

    // The link loses seq 2 and delivers everything else in order.
    let link = UdpSocket::bind("127.0.0.1:0").expect("bind link");
    let recv_addr = receiver.local_addr().unwrap();
    for (at, datagram) in datagrams.iter().enumerate() {
        if at != 2 {
            link.send_to(datagram, recv_addr).unwrap();
        }
    }
    let mut delivered = Vec::new();
    for _ in 0..8 {
        let (_, envelope, meta) = receiver.recv().expect("recv");
        delivered.push((meta.seq, envelope));
    }
    let seqs: Vec<u64> = delivered.iter().map(|(seq, _)| *seq).collect();
    assert_eq!(
        seqs,
        vec![0, 1, 3, 2, 4, 5, 6, 7],
        "seq 2 must be rebuilt when its window's parity arrives"
    );
    assert_eq!(receiver.fec_recovered_count(), 1);
    for (seq, envelope) in &delivered {
        assert_eq!(envelope, &envelopes[*seq as usize], "seq {seq} envelope");
    }
}

/// A `sendmmsg(2)` batch sent after FEC was switched on inside a window
/// keeps the receiver's windows: the rest of that window goes without
/// parity, the first full window's parity goes out right after its last
/// frame, and a frame lost from that window is rebuilt.
#[cfg(target_os = "linux")]
#[test]
fn a_batch_after_fec_is_switched_on_mid_window_keeps_the_receivers_windows() {
    use std::net::UdpSocket;

    use pulse_wire_udp::{decode_fec, wire};

    const K: u16 = 4;
    let relay = UdpSocket::bind("127.0.0.1:0").expect("bind relay");
    let relay_addr = relay.local_addr().unwrap();
    let mut receiver = Receiver::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    receiver.enable_fec(K, 8);
    let mut sender = Sender::bind("127.0.0.1:0").expect("bind sender");

    let pulse = Pulse::zeroed();
    let envelopes: Vec<Vec<u8>> = (0..14u8)
        .map(|i| vec![0xD0 | (i & 0x0F); 8 + 8 * usize::from(i % 3)])
        .collect();
    let frames: Vec<(u64, &Pulse, &[u8])> = envelopes
        .iter()
        .enumerate()
        .map(|(i, e)| (i as u64, &pulse, e.as_slice()))
        .collect();
    // Seqs 0 to 4 without FEC, then FEC on at seq 5, inside [4, 8): [8, 12)
    // is the first full window, and [12, 16) is still open at seq 13.
    sender.send_batch(&frames[..5], relay_addr).unwrap();
    sender.enable_fec(K);
    assert_eq!(
        sender.send_batch(&frames[5..], relay_addr).unwrap(),
        (5..14).collect::<Vec<_>>()
    );
    assert_eq!(sender.parity_sent_count(), 1);

    // On the wire: seqs 0 to 11, the parity for [8, 12), then 12 and 13.
    let datagrams = drain_datagrams(&relay);
    let seqs_on_wire: Vec<Option<u64>> = datagrams
        .iter()
        .map(|d| wire::decode(d).ok().map(|f| f.seq))
        .collect();
    let mut expected: Vec<Option<u64>> = (0..12).map(Some).collect();
    expected.extend([None, Some(12), Some(13)]);
    assert_eq!(seqs_on_wire, expected);
    let (header, _) = decode_fec(&datagrams[12]).expect("a parity datagram");
    assert_eq!((header.window_start, header.window_n), (8, K));

    // The link loses seq 9 and delivers everything else in order.
    let link = UdpSocket::bind("127.0.0.1:0").expect("bind link");
    let recv_addr = receiver.local_addr().unwrap();
    for (at, datagram) in datagrams.iter().enumerate() {
        if at != 9 {
            link.send_to(datagram, recv_addr).unwrap();
        }
    }
    let mut delivered = Vec::new();
    for _ in 0..14 {
        let (_, envelope, meta) = receiver.recv().expect("recv");
        delivered.push((meta.seq, envelope));
    }
    let mut seqs: Vec<u64> = delivered.iter().map(|(seq, _)| *seq).collect();
    seqs.sort_unstable();
    assert_eq!(seqs, (0..14).collect::<Vec<_>>(), "seq 9 must be rebuilt");
    assert_eq!(receiver.fec_recovered_count(), 1);
    for (seq, envelope) in &delivered {
        assert_eq!(envelope, &envelopes[*seq as usize], "seq {seq} envelope");
    }
}
