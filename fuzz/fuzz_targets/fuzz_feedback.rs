// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: the UDP transport's feedback channel on the sender's side.
// `decode_ack` and `decode_nack` over arbitrary bytes, and the sender's
// handling of feedback datagrams: `FeedbackIntake`, what the sender's
// feedback thread does with each datagram it receives, and the send path's
// two steps with the requests it queued, taking them oldest first within a
// budget and serving each from the `SendCache`.
//
// The input describes a sender's configuration (NACK on or off, the cache
// capacity that also caps the request queue, a feedback peer or none) and
// a run: datagrams from sources the input picks (the peer, another
// address, the peer's IPv4-mapped IPv6 form, any port), mostly well-formed
// ACKs and NACKs with any value, sometimes bytes that only start like one,
// and sends from a base sequence number, each followed by the send path
// serving queued requests. The intake is given what the feedback thread's
// receive leaves of each datagram: the thread lends the socket a buffer one
// byte longer than the longer of the two formats, 12 bytes, and the socket
// copies what fits and drops the rest, so a longer datagram reaches the
// intake cut to 13 bytes. The model judges each datagram as it was sent,
// not as the buffer cut it.
//
// Invariants:
// - `decode_ack` and `decode_nack` accept exactly the 12-byte datagrams
//   that start with their magic (`PMSA`, `PMSN`) and return the
//   little-endian u64 after it, as the module's wire format states; no
//   datagram decodes as both; `encode_*` writes what they read back;
// - a datagram longer than 12 bytes is neither an ACK nor a NACK, one that
//   starts like one included, though the intake sees only its first 13
//   bytes;
// - the cursor the sender sees is the highest ACK cursor taken from an
//   admitted source, zero before any: it never goes down;
// - a NACK from an admitted source is queued, in arrival order, while NACK
//   is on and fewer requests than the cap wait, and counted as dropped
//   when the queue is full; with NACK off nothing is queued or counted;
// - a datagram from a source the filter does not admit changes nothing but
//   the rejection count; a source and its IPv4-mapped form are one source;
// - a datagram that is neither an ACK nor a NACK changes nothing;
// - the send path takes queued requests oldest first, at most its budget at
//   a time, and serves each from the cache exactly when the cache still
//   holds the frame sent under that number, one of the last `capacity`
//   sent, with that frame's bytes.

#![no_main]

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use pulse_mesh_fuzz::take;
use pulse_wire_udp::backpressure::{FeedbackIntake, SendCache};
use pulse_wire_udp::{
    decode_ack, decode_nack, encode_ack, encode_nack, BackpressureConfig, ACK_BYTES, ACK_MAGIC,
    MAX_NACKS_PER_CYCLE, NACK_BYTES, NACK_MAGIC,
};

/// Most steps in one run.
const MAX_STEPS: usize = 256;
/// Largest cache capacity drawn.
const MAX_CAPACITY: usize = 64;
/// The feedback thread's receive buffer: a byte longer than the longer
/// feedback format, so that a longer datagram arrives too long to decode
/// rather than cut to look like one.
const FEEDBACK_BUF: usize = if ACK_BYTES > NACK_BYTES {
    ACK_BYTES + 1
} else {
    NACK_BYTES + 1
};

/// The sources a datagram comes from.
const PEERS: [IpAddr; 4] = [
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
    IpAddr::V6(Ipv6Addr::LOCALHOST),
    // 127.0.0.1 in its IPv4-mapped IPv6 form: the same source as the first.
    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001)),
];

fuzz_target!(|data: &[u8]| {
    let _ = fuzz(data);
});

fn fuzz(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    check_decoders(take(&mut u, 16)?);

    let any: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut cfg = BackpressureConfig::new(any, any);
    let capacity = u.int_in_range(0..=MAX_CAPACITY)?;
    if u.arbitrary()? {
        cfg = cfg.with_nack(capacity);
    } else {
        cfg.send_cache_capacity = capacity;
    }
    let peer = if u.arbitrary()? {
        Some(PEERS[u.choose_index(PEERS.len())?])
    } else {
        None
    };
    if let Some(peer) = peer {
        cfg = cfg.with_feedback_peer(peer);
    }
    let mut intake = FeedbackIntake::new(&cfg);
    let mut cache = SendCache::new(capacity);
    let cap = capacity.max(1);

    // The model.
    let mut cursor = 0u64;
    let mut queue: VecDeque<u64> = VecDeque::new();
    let (mut dropped, mut rejected) = (0u64, 0u64);
    let mut next_seq: u64 = u.int_in_range(0..=u64::MAX - MAX_STEPS as u64 - 1)?;
    let first_seq = next_seq;

    for _ in 0..MAX_STEPS {
        if u.is_empty() {
            break;
        }
        if u.ratio(1, 3)? {
            // A send: the frame is cached, and the requests queued before it
            // are served first, within the budget.
            let budget = if u.ratio(3, 4)? {
                MAX_NACKS_PER_CYCLE
            } else {
                u.int_in_range(0..=4)?
            };
            serve(
                &intake, &cache, &mut queue, budget, first_seq, next_seq, cap,
            );
            cache.store(next_seq, &frame(next_seq));
            next_seq += 1;
            continue;
        }
        let from = SocketAddr::new(PEERS[u.choose_index(PEERS.len())?], u.arbitrary()?);
        let mut datagram = Vec::new();
        match u.int_in_range(0..=5u8)? {
            0 | 1 => encode_ack(value(&mut u, next_seq)?, &mut datagram),
            2 | 3 => encode_nack(value(&mut u, next_seq)?, &mut datagram),
            4 => {
                // The start of a feedback datagram and whatever follows.
                let magic = if u.arbitrary()? {
                    ACK_MAGIC
                } else {
                    NACK_MAGIC
                };
                datagram.extend_from_slice(&magic.to_le_bytes());
                datagram.extend_from_slice(take(&mut u, 12)?);
            }
            _ => datagram.extend_from_slice(take(&mut u, 16)?),
        }
        check_decoders(&datagram);
        // What the feedback thread's buffer keeps of the datagram; the model
        // below judges the datagram as sent.
        let received = &datagram[..datagram.len().min(FEEDBACK_BUF)];

        let admitted = peer.is_none_or(|p| p.to_canonical() == from.ip().to_canonical());
        if !admitted {
            rejected += 1;
        } else if let Some(ack) = parse(&datagram, ACK_MAGIC) {
            cursor = cursor.max(ack);
        } else if let Some(seq) = parse(&datagram, NACK_MAGIC) {
            if cfg.nack_enabled {
                if queue.len() < cap {
                    queue.push_back(seq);
                } else {
                    dropped += 1;
                }
            }
        }
        intake.take(received, from);
        assert_eq!(
            intake.recv_cursor(),
            cursor,
            "the cursor is not the highest ACK admitted"
        );
        assert_eq!(
            intake.pending_nacks(),
            Vec::from(queue.clone()),
            "the queued requests are not the NACKs admitted, in order"
        );
        assert_eq!(intake.nack_drop_count(), dropped, "the dropped NACKs");
        assert_eq!(intake.rejected_count(), rejected, "the rejected datagrams");
    }
    serve(
        &intake,
        &cache,
        &mut queue,
        usize::MAX,
        first_seq,
        next_seq,
        cap,
    );
    assert!(
        intake.pending_nacks().is_empty(),
        "requests left after an unbounded drain"
    );
    Ok(())
}

/// The send path's two steps: take up to `budget` queued requests, oldest
/// first, and serve each from the cache, which must hold exactly the frames
/// among the last `cap` sent (sequence numbers `first..next`).
fn serve(
    intake: &FeedbackIntake,
    cache: &SendCache,
    queue: &mut VecDeque<u64>,
    budget: usize,
    first: u64,
    next: u64,
    cap: usize,
) {
    let taken = intake.drain_nacks(budget);
    let want: Vec<u64> = queue.drain(..queue.len().min(budget)).collect();
    assert_eq!(taken, want, "the send path took other requests");
    for seq in taken {
        let held = seq >= first && seq < next && next - seq <= cap as u64;
        match cache.lookup(seq) {
            Some(cached) => {
                assert!(held, "the cache served {seq}, which it cannot still hold");
                assert_eq!(cached.seq, seq);
                assert_eq!(cached.encoded, frame(seq), "the cache served another frame");
            }
            None => assert!(!held, "the cache lost {seq}, one of the last {cap} sent"),
        }
    }
}

/// The frame sent as `seq`: bytes that name it.
fn frame(seq: u64) -> Vec<u8> {
    let mut bytes = b"frame".to_vec();
    bytes.extend_from_slice(&seq.to_le_bytes());
    bytes
}

/// An ACK cursor or NACK number: near the sender's, or anywhere.
fn value(u: &mut Unstructured<'_>, next: u64) -> Result<u64> {
    Ok(match u.int_in_range(0..=3u8)? {
        0 => u.arbitrary()?,
        _ => next.wrapping_add_signed(u.int_in_range(-80..=8)?),
    })
}

/// The module's wire format, read independently: 12 bytes, the magic
/// little-endian, then the value little-endian.
fn parse(datagram: &[u8], magic: u32) -> Option<u64> {
    let bytes: &[u8; 12] = datagram.try_into().ok()?;
    let (head, value) = bytes.split_at(4);
    (u32::from_le_bytes(head.try_into().ok()?) == magic)
        .then(|| u64::from_le_bytes(value.try_into().unwrap_or_default()))
}

/// Both decoders against the format, and the encoders against both.
fn check_decoders(datagram: &[u8]) {
    let ack = decode_ack(datagram);
    let nack = decode_nack(datagram);
    assert_eq!(
        ack,
        parse(datagram, ACK_MAGIC),
        "decode_ack misread {datagram:02x?}"
    );
    assert_eq!(
        nack,
        parse(datagram, NACK_MAGIC),
        "decode_nack misread {datagram:02x?}"
    );
    assert!(
        ack.is_none() || nack.is_none(),
        "one datagram decoded as both"
    );
    let mut out = Vec::new();
    if let Some(cursor) = ack {
        encode_ack(cursor, &mut out);
        assert_eq!(
            out, datagram,
            "encode_ack does not write what decode_ack read"
        );
    }
    if let Some(seq) = nack {
        encode_nack(seq, &mut out);
        assert_eq!(
            out, datagram,
            "encode_nack does not write what decode_nack read"
        );
    }
}
