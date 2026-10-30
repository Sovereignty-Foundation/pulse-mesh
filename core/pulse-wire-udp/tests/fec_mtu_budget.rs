// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! FEC parity always fits the receive buffer.
//!
//! A parity datagram is 18 bytes of FEC header and the XOR of its window's
//! frames, as long as the longest, so full-size envelopes would make parity
//! of 1,490 bytes against a receive buffer of 1,472. A sender with FEC on
//! refuses an envelope larger than `FEC_MAX_ENVELOPE` with
//! `EnvelopeTooLarge`, so the largest parity is exactly `MTU_BYTES`, and a
//! receiver counts every parity datagram it cannot decode.

use std::collections::BTreeMap;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use pulse_canon::Pulse;
use pulse_wire_udp::{
    encode_fec, wire, BatchSendError, FecHeader, Receiver, Sender, SenderError, WireError,
    FEC_HEADER_BYTES, FEC_MAGIC, FEC_MAX_ENVELOPE, MAX_ENVELOPE, MTU_BYTES,
};

const K: u16 = 4;

/// Every datagram waiting on `socket`, whole, until a read times out.
fn drain(socket: &UdpSocket) -> Vec<Vec<u8>> {
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let mut datagrams = Vec::new();
    while let Ok(n) = socket.recv(&mut buf) {
        datagrams.push(buf[..n].to_vec());
    }
    datagrams
}

fn fec_receiver(timeout: Duration) -> (Receiver, SocketAddr) {
    let mut receiver = Receiver::bind("127.0.0.1:0").unwrap();
    receiver.set_read_timeout(Some(timeout)).unwrap();
    receiver.enable_fec(K, 8);
    let addr = receiver.local_addr().unwrap();
    (receiver, addr)
}

fn expect_timeout(receiver: &mut Receiver) {
    match receiver.recv() {
        Err(e) if e.is_timeout() => {}
        other => panic!("expected a read timeout, got {other:?}"),
    }
}

/// A window of frames with envelopes of the largest size FEC allows makes
/// parity of exactly one MTU, and a frame lost from it is rebuilt.
#[test]
fn the_largest_envelope_fec_allows_is_rebuilt_when_lost() {
    let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    sender.enable_fec(K);
    assert_eq!(sender.envelope_limit(), FEC_MAX_ENVELOPE);
    let envelopes: Vec<Vec<u8>> = (0..4u8).map(|i| vec![0xA0 | i; FEC_MAX_ENVELOPE]).collect();
    for (seq, envelope) in envelopes.iter().enumerate() {
        let sent = sender
            .send_to(seq as u64, &Pulse::zeroed(), envelope, relay_addr)
            .unwrap();
        assert_eq!(sent, seq as u64);
    }

    let datagrams = drain(&relay);
    assert_eq!(datagrams.len(), 5, "four frames and their parity");
    for frame in &datagrams[..4] {
        assert_eq!(frame.len(), MTU_BYTES - FEC_HEADER_BYTES);
    }
    assert_eq!(datagrams[4].len(), MTU_BYTES, "the parity is one MTU");

    // The link loses seq 1 and delivers the rest, parity included.
    let (mut receiver, recv_addr) = fec_receiver(Duration::from_secs(2));
    let link = UdpSocket::bind("127.0.0.1:0").unwrap();
    for (at, datagram) in datagrams.iter().enumerate() {
        if at != 1 {
            link.send_to(datagram, recv_addr).unwrap();
        }
    }
    let mut delivered = BTreeMap::new();
    for _ in 0..4 {
        let (_, envelope, meta) = receiver.recv().unwrap();
        delivered.insert(meta.seq, envelope);
    }
    assert_eq!(
        delivered.keys().copied().collect::<Vec<_>>(),
        vec![0, 1, 2, 3]
    );
    for (seq, envelope) in &delivered {
        assert_eq!(envelope, &envelopes[*seq as usize], "seq {seq} envelope");
    }
    assert_eq!(receiver.fec_recovered_count(), 1);
    assert_eq!(receiver.parity_undecodable_count(), 0);
}

/// One byte over the limit is refused before anything is sent, singly and
/// in a batch; with FEC off, the same envelope fits `MAX_ENVELOPE`.
#[test]
fn one_byte_more_is_refused_at_send() {
    let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
    let sink_addr = sink.local_addr().unwrap();
    let mut sender = Sender::bind("127.0.0.1:0").unwrap();
    sender.connect(sink_addr).unwrap();
    sender.enable_fec(K);
    let pulse = Pulse::zeroed();
    let fits = vec![0x11; FEC_MAX_ENVELOPE];
    let too_big = vec![0x22; FEC_MAX_ENVELOPE + 1];

    match sender.send(0, &pulse, &too_big) {
        Err(SenderError::Encode(WireError::EnvelopeTooLarge { got, max })) => {
            assert_eq!((got, max), (FEC_MAX_ENVELOPE + 1, FEC_MAX_ENVELOPE));
        }
        other => panic!("expected EnvelopeTooLarge, got {other:?}"),
    }
    assert_eq!(
        sender.next_seq(),
        0,
        "the refused frame used a sequence number"
    );

    // A batch goes out up to the frame that is too large.
    let frames: Vec<(u64, &Pulse, &[u8])> = vec![
        (0, &pulse, &fits),
        (1, &pulse, &fits),
        (2, &pulse, &too_big),
        (3, &pulse, &fits),
    ];
    match sender.send_batch(&frames, sink_addr) {
        Err(BatchSendError::FrameError {
            index: 2,
            error:
                SenderError::Encode(WireError::EnvelopeTooLarge {
                    max: FEC_MAX_ENVELOPE,
                    ..
                }),
        }) => {}
        other => panic!("expected the third frame to be refused, got {other:?}"),
    }
    assert_eq!(sender.next_seq(), 2);
    let seqs: Vec<u64> = drain(&sink)
        .iter()
        .map(|d| wire::decode(d).unwrap().seq)
        .collect();
    assert_eq!(seqs, vec![0, 1], "only the frames before it went out");

    sender.disable_fec();
    assert_eq!(sender.envelope_limit(), MAX_ENVELOPE);
    assert_eq!(sender.send(0, &pulse, &too_big).unwrap(), 2);
}

/// Parity the receiver cannot decode is counted, whether the datagram
/// itself fails (cut short by the receive buffer, a zero window, shorter
/// than the header) or the frame rebuilt from it does.
#[test]
fn parity_the_receiver_cannot_decode_is_counted() {
    let (mut receiver, recv_addr) = fec_receiver(Duration::from_millis(300));
    let injector = UdpSocket::bind("127.0.0.1:0").unwrap();
    let parity = |window_start: u64, window_n: u16, bytes: &[u8]| {
        let mut datagram = Vec::new();
        let header = FecHeader {
            window_start,
            window_n,
            parity_len: bytes.len() as u32,
        };
        encode_fec(header, bytes, &mut datagram);
        datagram
    };

    // Parity as a sender made it before the cap, for full-size frames: 1,490
    // bytes, which the 1,472-byte receive buffer cuts short.
    let oversized = parity(0, K, &vec![0x5A; MTU_BYTES]);
    assert_eq!(oversized.len(), 1490);
    injector.send_to(&oversized, recv_addr).unwrap();
    // A window of zero frames, and a datagram shorter than the header.
    injector.send_to(&parity(0, 0, &[0; 4]), recv_addr).unwrap();
    injector
        .send_to(&FEC_MAGIC.to_le_bytes(), recv_addr)
        .unwrap();
    expect_timeout(&mut receiver);
    assert_eq!(receiver.parity_undecodable_count(), 3);
    assert_eq!(receiver.parity_received_count(), 0);

    // The batch receive counts it too: it takes the same path.
    injector.send_to(&oversized, recv_addr).unwrap();
    let mut slots = vec![vec![0u8; MAX_ENVELOPE]; 4];
    let batch = {
        let mut refs: Vec<&mut [u8]> = slots.iter_mut().map(|s| s.as_mut_slice()).collect();
        receiver.recv_batch_into(4, &mut refs).unwrap()
    };
    assert_eq!(batch.received, 1);
    assert!(batch.frames.is_empty() && batch.errors.is_empty());
    assert_eq!(receiver.parity_undecodable_count(), 4);

    // Frames 0, 1 and 3 of window [0, 4) arrive with parity that is not
    // their XOR with frame 2: the frame rebuilt from it fails its checks.
    for seq in [0u64, 1, 3] {
        let frame = wire::encode(seq, 0, &Pulse::zeroed(), b"real").unwrap();
        injector.send_to(&frame, recv_addr).unwrap();
    }
    injector
        .send_to(&parity(0, K, &[0xEE; 200]), recv_addr)
        .unwrap();
    let seqs: Vec<u64> = (0..3).map(|_| receiver.recv().unwrap().2.seq).collect();
    assert_eq!(seqs, vec![0, 1, 3]);
    expect_timeout(&mut receiver);
    assert_eq!(receiver.parity_received_count(), 1);
    assert_eq!(receiver.fec_recovered_count(), 0);
    assert_eq!(receiver.parity_undecodable_count(), 5);
}
