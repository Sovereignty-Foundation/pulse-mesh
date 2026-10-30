// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! `Receiver::recv_batch_into` does for every datagram what `recv` does.
//! A data frame advances the ACK cursor, so a backpressured sender keeps
//! going, and feeds gap tracking, so a lost frame is requested and its
//! retransmission arrives. A parity datagram goes to the FEC decoder,
//! never into the errors, and a frame the decoder rebuilds reaches the
//! caller, in the same call when a slot is free and otherwise from the
//! next call, before that call reads the socket. The tests run on every
//! Unix platform: on Linux they exercise the `recvmmsg(2)` path, elsewhere
//! the one-read-per-datagram path, which must behave the same. Windows
//! is left out because its later reads wait for a datagram rather than
//! take only what is queued.

#[cfg(unix)]
mod batch_path {
    use std::net::{SocketAddr, UdpSocket};
    use std::thread;
    use std::time::{Duration, Instant};

    use pulse_canon::Pulse;
    use pulse_wire_udp::{BackpressureConfig, BatchRecvResult, Receiver, Sender, MAX_ENVELOPE};

    const SLOTS: usize = 16;

    fn any_loopback() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    /// One batch receive into `SLOTS` envelope buffers of `MAX_ENVELOPE`
    /// bytes, returned alongside the result.
    fn receive(receiver: &mut Receiver, max_frames: usize) -> (BatchRecvResult, Vec<Vec<u8>>) {
        let mut slots = vec![vec![0u8; MAX_ENVELOPE]; SLOTS];
        let result = {
            let mut refs: Vec<&mut [u8]> = slots.iter_mut().map(|s| s.as_mut_slice()).collect();
            receiver
                .recv_batch_into(max_frames, &mut refs)
                .expect("batch receive")
        };
        (result, slots)
    }

    /// The sequence numbers of the next `count` frames the batch receiver
    /// delivers, across as many calls as that takes; no call may report an
    /// error.
    fn receive_seqs(receiver: &mut Receiver, count: usize) -> Vec<u64> {
        let mut seqs = Vec::new();
        while seqs.len() < count {
            let (batch, _) = receive(receiver, SLOTS);
            assert!(batch.errors.is_empty(), "errors: {:?}", batch.errors);
            seqs.extend(batch.frames.iter().map(|(_, _, meta)| meta.seq));
        }
        seqs
    }

    /// Batch-receive until the calls have read `datagrams` datagrams between
    /// them, however the socket splits them across calls, and return each
    /// frame delivered with its envelope bytes. No call may report an error:
    /// parity datagrams are among those read and must never be.
    fn receive_datagrams(receiver: &mut Receiver, datagrams: usize) -> Vec<(u64, Vec<u8>)> {
        let mut read = 0;
        let mut frames = Vec::new();
        while read < datagrams {
            let (batch, slots) = receive(receiver, SLOTS);
            assert!(
                batch.errors.is_empty(),
                "parity or frames reported as errors: {:?}",
                batch.errors
            );
            read += batch.received;
            for (slot, (_, len, meta)) in batch.frames.iter().enumerate() {
                frames.push((meta.seq, slots[slot][..*len].to_vec()));
            }
        }
        assert_eq!(read, datagrams);
        frames
    }

    /// Every datagram waiting on `socket`, in arrival order, until a read
    /// times out.
    fn drain_datagrams(socket: &UdpSocket) -> Vec<Vec<u8>> {
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut buf = vec![0u8; pulse_wire_udp::MTU_BYTES];
        let mut datagrams = Vec::new();
        while let Ok(n) = socket.recv(&mut buf) {
            datagrams.push(buf[..n].to_vec());
        }
        datagrams
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

    /// A sender with FEC over windows of `k`, whose batch of `count` frames
    /// goes to a relay socket, and the datagrams the relay caught, parity
    /// included, in the order they went out.
    fn fec_batch_through_relay(k: u16, count: u8) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut sender = Sender::bind("127.0.0.1:0").unwrap();
        sender.enable_fec(k);
        let pulse = Pulse::zeroed();
        let envelopes: Vec<Vec<u8>> = (0..count)
            .map(|i| vec![0xB0 | (i & 0x0F); 8 + 8 * usize::from(i % 3)])
            .collect();
        let frames: Vec<(u64, &Pulse, &[u8])> = envelopes
            .iter()
            .enumerate()
            .map(|(i, e)| (i as u64, &pulse, e.as_slice()))
            .collect();
        sender
            .send_batch(&frames, relay.local_addr().unwrap())
            .unwrap();
        (drain_datagrams(&relay), envelopes)
    }

    /// The batch receiver advances the ACK cursor for every frame it takes,
    /// so a sender held to a depth of four delivers a batch sixteen times
    /// that size without stalling.
    #[test]
    fn a_backpressured_sender_against_a_batch_receiver_does_not_stall() {
        const FRAMES: usize = 64;
        let mut receiver = Receiver::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let recv_addr = receiver.local_addr().unwrap();
        let mut sender = Sender::bind("127.0.0.1:0").unwrap();
        let mut cfg = BackpressureConfig::new(any_loopback(), any_loopback())
            .with_stall_timeout(Some(Duration::from_secs(1)));
        cfg.target_queue_depth = 4;
        sender.enable_backpressure(cfg.clone()).unwrap();
        cfg.ack_target_addr = sender.ack_local_addr().unwrap();
        receiver.enable_backpressure(cfg).unwrap();

        let reader = thread::spawn(move || {
            let seqs = receive_seqs(&mut receiver, FRAMES);
            (receiver, seqs)
        });
        let pulse = Pulse::zeroed();
        let frames: Vec<(u64, &Pulse, &[u8])> = (0..FRAMES as u64)
            .map(|i| (i, &pulse, &b"batch"[..]))
            .collect();
        let sent = sender
            .send_batch(&frames, recv_addr)
            .unwrap_or_else(|e| panic!("the sender stalled against the batch receiver: {e}"));
        let (receiver, delivered) = reader.join().unwrap();
        assert_eq!(sent, (0..FRAMES as u64).collect::<Vec<_>>());
        assert_eq!(delivered, sent, "every frame arrives, once and in order");
        assert_eq!(receiver.published_recv_cursor(), FRAMES as u64);
        assert_eq!(receiver.contiguous_head(), FRAMES as u64);
    }

    /// A gap the batch receiver sees is staged and requested as one `recv`
    /// sees, and the sender's retransmission arrives through the batch receive
    /// and closes it.
    #[test]
    fn a_gap_seen_by_a_batch_receiver_is_requested_and_the_retransmission_arrives() {
        let mut receiver = Receiver::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let recv_addr = receiver.local_addr().unwrap();
        let mut sender = Sender::bind("127.0.0.1:0").unwrap();
        // A loose depth: this test is about the NACK, not the window.
        let mut cfg = BackpressureConfig::new(any_loopback(), any_loopback()).with_nack(64);
        cfg.target_queue_depth = 4096;
        sender.enable_backpressure(cfg.clone()).unwrap();
        cfg.ack_target_addr = sender.ack_local_addr().unwrap();
        receiver.enable_backpressure(cfg).unwrap();

        // Seq 3 is lost on the way: it goes to a socket nobody reads.
        let lost = UdpSocket::bind("127.0.0.1:0").unwrap();
        let pulse = Pulse::zeroed();
        let batch = |from: u64, to: u64| -> Vec<(u64, &Pulse, &[u8])> {
            (from..to).map(|i| (i, &pulse, &b"gap"[..])).collect()
        };
        sender.send_batch(&batch(0, 3), recv_addr).unwrap();
        sender
            .send_to(3, &pulse, b"gap", lost.local_addr().unwrap())
            .unwrap();
        sender.send_batch(&batch(4, 8), recv_addr).unwrap();

        assert_eq!(receive_seqs(&mut receiver, 7), vec![0, 1, 2, 4, 5, 6, 7]);
        assert_eq!(receiver.contiguous_head(), 3, "the gap at 3 holds the head");
        assert!(
            wait_for(|| receiver.nacks_sent() >= 1),
            "the batch receiver never requested seq 3"
        );

        // The sender answers from its cache ahead of its next batch; send
        // one-frame batches until one has.
        let mut next = 8u64;
        let started = Instant::now();
        while sender.retransmit_count() == 0 && started.elapsed() < Duration::from_secs(2) {
            thread::sleep(Duration::from_millis(5));
            sender
                .send_batch(&batch(next, next + 1), recv_addr)
                .unwrap();
            next += 1;
        }
        // The receiver repeats a request while the sequence is still missing,
        // and the sender answers every request it drains, so seq 3 can come
        // back more than once.
        let retransmits = sender.retransmit_count();
        assert!(retransmits >= 1, "the NACK was never answered");

        // The retransmissions and the new frames arrive through the batch
        // receive, and the head moves past everything sent.
        let rest = receive_seqs(&mut receiver, (next - 8 + retransmits) as usize);
        assert!(rest.contains(&3), "seq 3 never arrived: {rest:?}");
        assert_eq!(receiver.contiguous_head(), next);
        assert_eq!(receiver.nack_drop_count(), 0);
    }

    /// With FEC on, parity datagrams go to the decoder rather than into the
    /// errors, and a frame lost from a window is rebuilt and delivered by the
    /// call that read the last datagram it needed, after that call's frames.
    #[test]
    fn a_frame_lost_in_a_window_is_rebuilt_and_delivered_by_the_batch_receiver() {
        let (datagrams, envelopes) = fec_batch_through_relay(4, 8);
        assert_eq!(datagrams.len(), 10, "eight frames and two parity datagrams");
        let mut receiver = Receiver::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        receiver.enable_fec(4, 8);

        // The link loses seq 2 and delivers the rest, parity included.
        let link = UdpSocket::bind("127.0.0.1:0").unwrap();
        for (at, datagram) in datagrams.iter().enumerate() {
            if at != 2 {
                link.send_to(datagram, receiver.local_addr().unwrap())
                    .unwrap();
            }
        }
        let delivered = receive_datagrams(&mut receiver, 9);
        let seqs: Vec<u64> = delivered.iter().map(|(seq, _)| *seq).collect();
        let mut sorted = seqs.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..8).collect::<Vec<_>>(), "delivered {seqs:?}");
        let at = |seq: u64| seqs.iter().position(|&s| s == seq).unwrap();
        assert!(
            at(2) > at(3),
            "seq 2 was delivered before it could be rebuilt"
        );
        for (seq, envelope) in &delivered {
            assert_eq!(envelope, &envelopes[*seq as usize], "seq {seq} envelope");
        }
        assert_eq!(receiver.parity_received_count(), 2);
        assert_eq!(receiver.fec_recovered_count(), 1);
    }

    /// With FEC off, a parity datagram is dropped as `recv` drops it: it is
    /// read and counted in `received`, and never reported as an error.
    #[test]
    fn parity_is_never_reported_as_a_decode_error() {
        let (datagrams, _) = fec_batch_through_relay(4, 8);
        let mut receiver = Receiver::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let link = UdpSocket::bind("127.0.0.1:0").unwrap();
        for datagram in &datagrams {
            link.send_to(datagram, receiver.local_addr().unwrap())
                .unwrap();
        }
        let delivered = receive_datagrams(&mut receiver, 10);
        let seqs: Vec<u64> = delivered.iter().map(|(seq, _)| *seq).collect();
        assert_eq!(seqs, (0..8).collect::<Vec<_>>());
        assert_eq!(receiver.parity_received_count(), 0);
    }

    /// A frame rebuilt when the call has no free slot is held, and the next
    /// call returns it first, without reading the socket. A call that reads
    /// only parity delivers nothing and reports nothing. Each call takes one
    /// slot, so each reads exactly one datagram, whenever it arrives.
    #[test]
    fn a_rebuilt_frame_with_no_free_slot_is_held_for_the_next_call() {
        let (datagrams, envelopes) = fec_batch_through_relay(4, 4);
        assert_eq!(datagrams.len(), 5, "four frames, then their parity");
        let mut receiver = Receiver::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        receiver.enable_fec(4, 8);
        let recv_addr = receiver.local_addr().unwrap();

        // The parity overtakes the window, and seq 2 is lost.
        let link = UdpSocket::bind("127.0.0.1:0").unwrap();
        for at in [4usize, 0, 1, 3] {
            link.send_to(&datagrams[at], recv_addr).unwrap();
        }
        let (parity_only, _) = receive(&mut receiver, 1);
        assert_eq!(parity_only.received, 1);
        assert!(parity_only.frames.is_empty() && parity_only.errors.is_empty());

        // Seqs 0 and 1, then seq 3, which completes the window: the rebuilt
        // seq 2 has no slot left in that call.
        for expected in [0u64, 1, 3] {
            let (one, _) = receive(&mut receiver, 1);
            assert_eq!(one.received, 1);
            assert!(one.errors.is_empty(), "errors: {:?}", one.errors);
            let seqs: Vec<u64> = one.frames.iter().map(|(_, _, meta)| meta.seq).collect();
            assert_eq!(seqs, vec![expected]);
        }
        assert_eq!(receiver.fec_recovered_count(), 1);

        // The next call returns it without reading the socket.
        let (held, slots) = receive(&mut receiver, 3);
        assert_eq!(held.received, 0, "a call with a held frame read the socket");
        assert_eq!(held.frames.len(), 1);
        let (_, len, meta) = &held.frames[0];
        assert_eq!(meta.seq, 2);
        assert_eq!(&slots[0][..*len], envelopes[2].as_slice());

        // Nothing is held or queued now, so the next call waits out the read
        // timeout and reports it.
        let mut spare = vec![0u8; MAX_ENVELOPE];
        let mut refs: Vec<&mut [u8]> = vec![spare.as_mut_slice()];
        match receiver.recv_batch_into(1, &mut refs) {
            Err(pulse_wire_udp::BatchRecvError::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            other => panic!("expected a read timeout, got {other:?}"),
        }
    }
}
