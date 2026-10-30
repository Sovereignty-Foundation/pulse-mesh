// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Sealed datagrams end to end: two nodes on loopback, each a sender and a
//! receiver on one socket sealed with one key, allowlisted to each other.
//!
//! Loss is made by a relay between them that forwards every datagram both
//! ways and drops the sealed datagrams it is told to; forged, replayed and
//! reordered datagrams are sealed with the sender's own session and put on
//! the wire from a socket of the test's, or handed to the receiving sealing
//! directly where the source address matters (a loopback test cannot send
//! from anywhere else), as the receiver's own tests do with the source
//! filter.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use pulse_canon::{Instruction, Pulse, PulseEnvelope};
use pulse_wire_udp::sealed::Opened;
use pulse_wire_udp::{
    bind_sealed_pair_with, wire, Allowlist, BackpressureConfig, NodeKey, PublicKey,
    ReassemblyConfig, Receiver, RecvMeta, SealCounts, SealError, Sealing, SealingConfig, Sender,
    SenderError, FEC_MAX_ENVELOPE, MAX_ENVELOPE, MAX_MESSAGE, MTU_BYTES, SEALED_FEC_MAX_ENVELOPE,
    SEALED_INNER_BUDGET, SEALED_MAX_ENVELOPE, SEALED_OVERHEAD,
};

const PATIENCE: Duration = Duration::from_secs(5);

fn pulse(seq: u64) -> Pulse {
    let mut p = Pulse::zeroed();
    p.instruction = Instruction::Data as u16;
    p.chain_step = seq;
    p.monotonic_nanos = 1;
    p
}

struct Node {
    tx: Sender,
    rx: Receiver,
    key: PublicKey,
    addr: SocketAddr,
}

impl Node {
    fn sealing(&self) -> &Sealing {
        self.tx.sealing().unwrap()
    }
}

fn node(key: NodeKey, peers: &[PublicKey], config: &SealingConfig) -> Node {
    let public = key.public_key();
    let allow = peers.iter().copied().collect::<Allowlist>();
    let (tx, rx) = bind_sealed_pair_with("127.0.0.1:0", key, allow, config.clone()).unwrap();
    let addr = rx.local_addr().unwrap();
    Node {
        tx,
        rx,
        key: public,
        addr,
    }
}

/// Two nodes that admit each other.
fn nodes(config: &SealingConfig) -> (Node, Node) {
    let (ka, kb) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
    let (pa, pb) = (ka.public_key(), kb.public_key());
    (node(ka, &[pb], config), node(kb, &[pa], config))
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(1));
    }
}

/// Frames as `Receiver::recv` returns them.
type Frames = Vec<(Pulse, Vec<u8>, RecvMeta)>;

/// Receive on `rx` in a thread until `stop` is set, keeping what arrives.
struct Receiving {
    stop: Arc<AtomicBool>,
    got: Arc<Mutex<Frames>>,
    thread: JoinHandle<Receiver>,
}

impl Receiving {
    fn start(mut rx: Receiver) -> Self {
        rx.set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let got = Arc::new(Mutex::new(Vec::new()));
        let thread = {
            let (stop, got) = (Arc::clone(&stop), Arc::clone(&got));
            thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    match rx.recv() {
                        Ok(frame) => got.lock().unwrap().push(frame),
                        Err(e) if e.is_timeout() => {}
                        Err(e) => panic!("receive failed: {e}"),
                    }
                }
                rx
            })
        };
        Self { stop, got, thread }
    }

    fn count(&self) -> usize {
        self.got.lock().unwrap().len()
    }

    fn finish(self) -> (Receiver, Frames) {
        self.stop.store(true, Ordering::Release);
        let rx = self.thread.join().unwrap();
        let got = std::mem::take(&mut *self.got.lock().unwrap());
        (rx, got)
    }
}

/// `a` connects to `b` at `via` (`b`'s own address, or a relay's) while
/// `b`'s receiver answers in a thread, which is stopped once `b` has
/// confirmed the session.
fn connect(a: &Node, b: Node, via: SocketAddr) -> Node {
    let b_sealing = b.tx.sealing().unwrap().clone();
    let confirmed_before = b_sealing.counts().sessions_established;
    let answering = Receiving::start(b.rx);
    a.sealing().connect(via, &b.key, PATIENCE).unwrap();
    // The responder counts a session established when the initiator's first
    // datagram confirms it. Waiting for that count, not for a session to the
    // initiator's key, matters after a restart: the responder still holds
    // the initiator's old session then, so a session to its key is no sign
    // the new one is confirmed, and the initiator's address may be a relay's.
    wait_until("the responder to confirm", || {
        b_sealing.counts().sessions_established > confirmed_before
    });
    let (rx, got) = answering.finish();
    assert!(got.is_empty(), "the handshake delivered frames: {got:?}");
    Node { rx, ..b }
}

fn connected(config: &SealingConfig) -> (Node, Node) {
    let (a, b) = nodes(config);
    let b_addr = b.addr;
    let b = connect(&a, b, b_addr);
    (a, b)
}

/// The refusals in `after` beyond those in `before`.
fn refusals(before: &SealCounts, after: &SealCounts) -> u64 {
    let sum = |c: &SealCounts| {
        c.unauthentic
            + c.replayed
            + c.too_old
            + c.unknown_session
            + c.malformed
            + c.plaintext_refused
            + c.handshakes_refused
            + c.handshakes_failed
    };
    sum(after) - sum(before)
}

fn expect_nothing(rx: &mut Receiver) {
    rx.set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    match rx.recv() {
        Err(e) if e.is_timeout() => {}
        other => panic!("a datagram that should be refused was delivered: {other:?}"),
    }
}

/// A path between two nodes that forwards every datagram both ways, and
/// loses the sealed datagrams from the front whose places, counting the
/// sealed datagrams from the front from 0, are in `lose`.
struct Relay {
    front: SocketAddr,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    /// Every datagram forwarded from the front, as it went.
    forwarded: Arc<Mutex<Vec<Vec<u8>>>>,
    lost: Arc<AtomicUsize>,
}

impl Relay {
    fn new(back: SocketAddr, lose: &[usize]) -> Self {
        let front = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rear = UdpSocket::bind("127.0.0.1:0").unwrap();
        for s in [&front, &rear] {
            s.set_read_timeout(Some(Duration::from_millis(10))).unwrap();
        }
        let front_addr = front.local_addr().unwrap();
        let (front, rear) = (Arc::new(front), Arc::new(rear));
        let stop = Arc::new(AtomicBool::new(false));
        let forwarded = Arc::new(Mutex::new(Vec::new()));
        let lost = Arc::new(AtomicUsize::new(0));
        let caller: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
        let ahead = {
            let (front, rear, stop) = (Arc::clone(&front), Arc::clone(&rear), Arc::clone(&stop));
            let (forwarded, lost, caller) = (
                Arc::clone(&forwarded),
                Arc::clone(&lost),
                Arc::clone(&caller),
            );
            let lose = lose.to_vec();
            thread::spawn(move || {
                let mut buf = [0u8; 2048];
                let mut sealed = 0usize;
                while !stop.load(Ordering::Acquire) {
                    let Ok((n, from)) = front.recv_from(&mut buf) else {
                        continue;
                    };
                    *caller.lock().unwrap() = Some(from);
                    let d = &buf[..n];
                    if n >= SEALED_OVERHEAD && d[4] == 2 && d[5] == 3 {
                        sealed += 1;
                        if lose.contains(&(sealed - 1)) {
                            lost.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    }
                    forwarded.lock().unwrap().push(d.to_vec());
                    rear.send_to(d, back).unwrap();
                }
            })
        };
        let behind = {
            let (front, rear, stop) = (Arc::clone(&front), Arc::clone(&rear), Arc::clone(&stop));
            thread::spawn(move || {
                let mut buf = [0u8; 2048];
                while !stop.load(Ordering::Acquire) {
                    let Ok((n, _)) = rear.recv_from(&mut buf) else {
                        continue;
                    };
                    let to = *caller.lock().unwrap();
                    if let Some(to) = to {
                        front.send_to(&buf[..n], to).unwrap();
                    }
                }
            })
        };
        Self {
            front: front_addr,
            stop,
            threads: vec![ahead, behind],
            forwarded,
            lost,
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

#[test]
fn pulses_and_envelopes_cross_sealed_both_ways() {
    let (mut a, b) = connected(&SealingConfig::new());
    let receiving = Receiving::start(b.rx);
    let envelopes: Vec<PulseEnvelope> = (0..16u64)
        .map(|i| PulseEnvelope::typed("jobs/new", format!("job {i}").into_bytes()))
        .collect();
    for (i, envelope) in envelopes.iter().enumerate() {
        let seq =
            a.tx.send_to(
                i as u64,
                &pulse(i as u64),
                &envelope.to_canonical_bytes(),
                b.addr,
            )
            .unwrap();
        assert_eq!(seq, i as u64);
    }
    // The largest envelope a sealing sender takes still fits a datagram.
    let largest = vec![0x5a; SEALED_MAX_ENVELOPE];
    a.tx.send_to(99, &pulse(16), &largest, b.addr).unwrap();
    wait_until("17 frames", || receiving.count() == 17);
    let (rx_b, got) = receiving.finish();
    for (i, (p, bytes, meta)) in got.iter().take(16).enumerate() {
        assert_eq!(
            (meta.seq, meta.send_ns, p.chain_step),
            (i as u64, i as u64, i as u64)
        );
        assert_eq!(
            meta.sealed_by,
            Some(a.key),
            "opened by the sender's session"
        );
        let envelope = PulseEnvelope::from_canonical_bytes(bytes).unwrap();
        assert!(envelope.verify());
        assert_eq!(envelope, envelopes[i]);
    }
    assert_eq!(got[16].1, largest);

    // Back the other way on the same session: the responder learned where
    // the initiator's socket is from the datagrams that confirmed it.
    let mut b = Node { rx: rx_b, ..b };
    a.rx.set_read_timeout(Some(PATIENCE)).unwrap();
    for i in 0..4u64 {
        b.tx.send_to(i, &pulse(100 + i), b"reply", a.addr).unwrap();
        let (p, bytes, meta) = a.rx.recv().unwrap();
        assert_eq!(
            (meta.seq, p.chain_step, bytes.as_slice()),
            (i, 100 + i, &b"reply"[..])
        );
        assert_eq!(meta.sealed_by, Some(b.key));
    }
    for n in [&a, &b] {
        let counts = n.sealing().counts();
        assert_eq!(refusals(&SealCounts::default(), &counts), 0, "{counts:?}");
        assert_eq!(counts.sessions_established, 1);
    }
    assert_eq!(
        b.sealing().counts().opened,
        1 + 17,
        "the keepalive and 17 frames"
    );
}

#[test]
fn sealed_datagrams_carry_no_plaintext() {
    let (a, b) = nodes(&SealingConfig::new());
    let relay = Relay::new(b.addr, &[]);
    let b = connect(&a, b, relay.front);
    let mut a = a;
    let receiving = Receiving::start(b.rx);
    let secret = b"a payload nobody on the path reads";
    for i in 0..8u64 {
        a.tx.send_to(0, &pulse(i), secret, relay.front).unwrap();
    }
    wait_until("8 frames", || receiving.count() == 8);
    let (_, got) = receiving.finish();
    assert!(got.iter().all(|(_, e, _)| e == secret));
    let forwarded = relay.forwarded.lock().unwrap();
    assert!(
        forwarded.len() >= 10,
        "two handshake-side datagrams and eight frames"
    );
    for d in forwarded.iter() {
        assert!(
            !d.windows(secret.len()).any(|w| w == secret),
            "plaintext on the wire"
        );
        assert_eq!(
            &d[..5],
            &[0x50, 0x4d, 0x53, 0x57, 2],
            "a sealed-family datagram"
        );
    }
}

#[test]
fn a_send_without_a_session_is_refused_before_it_uses_a_sequence_number() {
    let (mut a, b) = nodes(&SealingConfig::new());
    match a.tx.send_to(0, &pulse(0), b"early", b.addr) {
        Err(SenderError::Seal(SealError::NoSession(to))) => assert_eq!(to, b.addr),
        other => panic!("expected NoSession, got {other:?}"),
    }
    assert_eq!(a.tx.next_seq(), 0);
    assert_eq!(a.sealing().counts().no_session, 0, "refused before sealing");
}

#[test]
fn the_budget_is_an_mtu_less_the_overhead() {
    let (mut a, b) = nodes(&SealingConfig::new());
    assert_eq!(a.tx.max_inner_datagram(), MTU_BYTES - SEALED_OVERHEAD);
    assert_eq!(b.rx.max_inner_datagram(), SEALED_INNER_BUDGET);
    assert_eq!(a.tx.envelope_limit(), SEALED_MAX_ENVELOPE);
    a.tx.enable_fec(4);
    assert_eq!(a.tx.envelope_limit(), SEALED_FEC_MAX_ENVELOPE);
    let plain = Sender::bind("127.0.0.1:0").unwrap();
    assert_eq!(plain.max_inner_datagram(), MTU_BYTES);
    assert_eq!(plain.envelope_limit(), MAX_ENVELOPE);
    let plain = Receiver::bind("127.0.0.1:0").unwrap();
    assert_eq!(plain.max_inner_datagram(), MTU_BYTES);
    // Sealing installed after construction changes the answer.
    let late = Sender::bind("127.0.0.1:0")
        .unwrap()
        .with_sealing(a.sealing().clone());
    assert_eq!(late.max_inner_datagram(), SEALED_INNER_BUDGET);
}

#[test]
fn batches_are_sealed_and_opened() {
    let (mut a, b) = connected(&SealingConfig::new());
    let pulses: Vec<Pulse> = (0..32).map(pulse).collect();
    let frames: Vec<(u64, &Pulse, &[u8])> = pulses
        .iter()
        .map(|p| (p.chain_step, p, &b"batch"[..]))
        .collect();
    let seqs = a.tx.send_batch(&frames, b.addr).unwrap();
    assert_eq!(seqs, (0..32).collect::<Vec<_>>());
    let mut rx = b.rx;
    rx.set_read_timeout(Some(PATIENCE)).unwrap();
    let mut slots = vec![vec![0u8; MAX_ENVELOPE]; 32];
    let mut seen = Vec::new();
    while seen.len() < 32 {
        let mut refs: Vec<&mut [u8]> = slots.iter_mut().map(|s| s.as_mut_slice()).collect();
        let batch = rx.recv_batch_into(32, &mut refs).unwrap();
        assert!(batch.errors.is_empty(), "{:?}", batch.errors);
        for (i, (_, len, meta)) in batch.frames.iter().enumerate() {
            assert_eq!(&slots[i][..*len], b"batch");
            seen.push(meta.seq);
        }
    }
    assert_eq!(seen, (0..32).collect::<Vec<_>>());
}

#[test]
fn acks_and_nacks_are_sealed_and_a_lost_frame_is_retransmitted() {
    let (a, b) = nodes(&SealingConfig::new());
    // The relay loses the fourth sealed datagram from the sender: frame 2,
    // after the keepalive and frames 0 and 1.
    let relay = Relay::new(b.addr, &[3]);
    let b = connect(&a, b, relay.front);
    let (mut a, mut b) = (a, b);
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut cfg = BackpressureConfig::new(any, any).with_nack(256);
    cfg.target_queue_depth = 1024;
    a.tx.enable_backpressure(cfg.clone()).unwrap();
    let ack_addr = a.tx.ack_local_addr().unwrap();
    cfg.ack_target_addr = ack_addr;
    b.rx.enable_backpressure(cfg).unwrap();

    // A forged plaintext ACK at the sender's feedback socket moves nothing.
    let forger = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut ack = Vec::new();
    pulse_wire_udp::encode_ack(1_000_000, &mut ack);
    forger.send_to(&ack, ack_addr).unwrap();
    wait_until("the forged ACK to be refused", || {
        a.sealing().counts().plaintext_refused == 1
    });
    assert_eq!(a.tx.observed_recv_cursor(), 0);

    let receiving = Receiving::start(b.rx);
    const N: u64 = 24;
    for i in 0..N {
        a.tx.send_to(0, &pulse(i), b"nack me", relay.front).unwrap();
        thread::sleep(Duration::from_millis(2));
    }
    // Frames after the loss carry the retransmission when the NACK is in.
    let mut extra = N;
    wait_until("the lost frame to be retransmitted", || {
        if a.tx.retransmit_count() == 0 {
            a.tx.send_to(0, &pulse(extra), b"nack me", relay.front)
                .unwrap();
            extra += 1;
            thread::sleep(Duration::from_millis(2));
        }
        a.tx.retransmit_count() > 0
    });
    wait_until("every frame", || {
        let got = receiving.got.lock().unwrap();
        let mut seqs: Vec<u64> = got.iter().map(|(_, _, m)| m.seq).collect();
        seqs.sort_unstable();
        seqs.dedup();
        seqs.len() as u64 == extra
    });
    wait_until("the cursor to come back sealed", || {
        a.tx.observed_recv_cursor() == extra
    });
    let (rx, got) = receiving.finish();
    b.rx = rx;
    assert_eq!(relay.lost.load(Ordering::Relaxed), 1);
    assert!(got.iter().any(|(_, _, m)| m.seq == 2), "frame 2 arrived");
    assert!(b.rx.nacks_sent() >= 1);
    let (ca, cb) = (a.sealing().counts(), b.sealing().counts());
    // Every ACK and NACK the sender took, it opened.
    assert!(ca.opened > 0, "{ca:?}");
    assert_eq!(
        refusals(&SealCounts::default(), &ca),
        1,
        "only the forged ACK: {ca:?}"
    );
    assert_eq!(refusals(&SealCounts::default(), &cb), 0, "{cb:?}");
}

#[test]
fn parity_is_sealed_and_rebuilds_a_lost_frame() {
    let (a, b) = nodes(&SealingConfig::new());
    // The keepalive is sealed datagram 0, frames 0 to 3 are 1 to 4 and
    // their parity 5: lose frame 2.
    let relay = Relay::new(b.addr, &[3]);
    let b = connect(&a, b, relay.front);
    let (mut a, mut b) = (a, b);
    a.tx.enable_fec(4);
    b.rx.enable_fec(4, 8);
    for i in 0..4u64 {
        a.tx.send_to(0, &pulse(i), format!("frame {i}").as_bytes(), relay.front)
            .unwrap();
    }
    assert_eq!(a.tx.parity_sent_count(), 1);
    b.rx.set_read_timeout(Some(PATIENCE)).unwrap();
    let mut seqs: Vec<u64> = (0..4)
        .map(|_| {
            let (p, envelope, meta) = b.rx.recv().unwrap();
            assert_eq!(envelope, format!("frame {}", p.chain_step).into_bytes());
            meta.seq
        })
        .collect();
    seqs.sort_unstable();
    assert_eq!(seqs, vec![0, 1, 2, 3]);
    assert_eq!(relay.lost.load(Ordering::Relaxed), 1);
    assert_eq!(b.rx.parity_received_count(), 1, "the parity was opened");
    assert_eq!(b.rx.fec_recovered_count(), 1);
    assert_eq!(refusals(&SealCounts::default(), &b.sealing().counts()), 0);
}

/// One of the sender's datagrams for `b`, sealed but not sent.
fn sealed_frame(a: &Node, b: &Node, seq: u64, envelope: &[u8]) -> Vec<u8> {
    let inner = wire::encode(seq, 0, &pulse(seq), envelope).unwrap();
    let mut out = Vec::new();
    a.sealing().seal_to(b.addr, &inner, &mut out).unwrap();
    out
}

#[test]
fn a_flipped_byte_anywhere_is_refused_and_counted() {
    let (a, mut b) = connected(&SealingConfig::new());
    let sealed = sealed_frame(&a, &b, 7, b"flip me");
    let src: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let before = b.sealing().counts();
    let mut tried = 0;
    for i in 0..sealed.len() {
        for bit in [0x01u8, 0x80] {
            let mut d = sealed.clone();
            d[i] ^= bit;
            let len = d.len();
            assert_eq!(
                b.sealing().open(&mut d, len, src),
                Opened::Consumed,
                "byte {i}"
            );
            tried += 1;
        }
    }
    let after = b.sealing().counts();
    assert_eq!(refusals(&before, &after), tried);
    assert_eq!(after.opened, before.opened);
    assert!(
        after.unauthentic > before.unauthentic && after.unknown_session > before.unknown_session
    );

    // On the wire too; and the untouched datagram still opens after all
    // that, so no refusal moved the replay window.
    let tap = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut flipped = sealed.clone();
    *flipped.last_mut().unwrap() ^= 1;
    tap.send_to(&flipped, b.addr).unwrap();
    expect_nothing(&mut b.rx);
    assert_eq!(b.sealing().counts().unauthentic, after.unauthentic + 1);
    tap.send_to(&sealed, b.addr).unwrap();
    let (_, envelope, meta) = b.rx.recv().unwrap();
    assert_eq!((meta.seq, envelope.as_slice()), (7, &b"flip me"[..]));
}

#[test]
fn replays_are_refused_and_reordering_within_the_window_is_not() {
    let (a, mut b) = connected(&SealingConfig::new());
    let tap = UdpSocket::bind("127.0.0.1:0").unwrap();
    b.rx.set_read_timeout(Some(PATIENCE)).unwrap();
    let frames: Vec<Vec<u8>> = (0..2100u64)
        .map(|seq| sealed_frame(&a, &b, seq, b"r"))
        .collect();

    // Out of order within the window: each taken once.
    for i in [5usize, 3, 4] {
        tap.send_to(&frames[i], b.addr).unwrap();
        assert_eq!(b.rx.recv().unwrap().2.seq, i as u64);
    }
    // The same datagram again.
    let before = b.sealing().counts();
    tap.send_to(&frames[4], b.addr).unwrap();
    expect_nothing(&mut b.rx);
    assert_eq!(b.sealing().counts().replayed, before.replayed + 1);

    // Far ahead: the window slides past the start.
    b.rx.set_read_timeout(Some(PATIENCE)).unwrap();
    tap.send_to(&frames[2099], b.addr).unwrap();
    assert_eq!(b.rx.recv().unwrap().2.seq, 2099);
    let before = b.sealing().counts();
    tap.send_to(&frames[0], b.addr).unwrap();
    expect_nothing(&mut b.rx);
    let after = b.sealing().counts();
    assert_eq!(after.too_old, before.too_old + 1, "{after:?}");
    // One not yet seen, inside the window's far end, is still taken.
    b.rx.set_read_timeout(Some(PATIENCE)).unwrap();
    tap.send_to(&frames[100], b.addr).unwrap();
    assert_eq!(b.rx.recv().unwrap().2.seq, 100);
    assert_eq!(refusals(&before, &b.sealing().counts()), 1);
}

#[test]
fn an_initiation_from_a_key_not_on_the_allowlist_is_dropped_and_counted() {
    let (a, b) = nodes(&SealingConfig::new());
    let stranger = node(
        NodeKey::generate().unwrap(),
        &[b.key],
        &SealingConfig::new(),
    );
    let b_sealing = b.sealing().clone();
    let answering = Receiving::start(b.rx);
    match stranger
        .sealing()
        .connect(b.addr, &b.key, Duration::from_millis(300))
    {
        Err(SealError::HandshakeTimeout { addr, .. }) => assert_eq!(addr, b.addr),
        other => panic!("the stranger was answered: {other:?}"),
    }
    let (_, got) = answering.finish();
    assert!(got.is_empty());
    let counts = b_sealing.counts();
    assert!(counts.handshakes_refused >= 1, "{counts:?}");
    assert!(!b_sealing.has_session(&stranger.key));
    assert_eq!(counts.sessions_established, 0);
    // A node connects only to a key on its own allowlist.
    match a.sealing().connect(b.addr, &stranger.key, PATIENCE) {
        Err(SealError::NotAllowed(key)) => assert_eq!(key, stranger.key),
        other => panic!("expected NotAllowed, got {other:?}"),
    }
}

#[test]
fn plaintext_is_refused_from_anywhere_but_loopback_with_the_flag() {
    let (_, mut b) = nodes(&SealingConfig::new());
    let frame = wire::encode(0, 0, &pulse(0), b"plain").unwrap();

    // From loopback, with the flag off, on the wire.
    let tap = UdpSocket::bind("127.0.0.1:0").unwrap();
    tap.send_to(&frame, b.addr).unwrap();
    expect_nothing(&mut b.rx);
    assert_eq!(b.sealing().counts().plaintext_refused, 1);

    // From an address that is not loopback (a documentation address; a
    // test cannot send from one, so the datagram is handed over as the
    // receiver would hand it).
    let remote: SocketAddr = "192.0.2.7:4000".parse().unwrap();
    let mut d = frame.clone();
    assert_eq!(
        b.sealing().open(&mut d, frame.len(), remote),
        Opened::Consumed
    );
    assert_eq!(b.sealing().counts().plaintext_refused, 2);

    // With the flag on: loopback is admitted, unchanged, and nothing else.
    let lenient = SealingConfig::new().with_loopback_plaintext(true);
    let (_, mut c) = nodes(&lenient);
    let mut d = frame.clone();
    assert_eq!(
        c.sealing().open(&mut d, frame.len(), remote),
        Opened::Consumed
    );
    assert_eq!(c.sealing().counts().plaintext_refused, 1);
    let mapped: SocketAddr = "[::ffff:127.0.0.1]:4000".parse().unwrap();
    let mut d = frame.clone();
    assert_eq!(
        c.sealing().open(&mut d, frame.len(), mapped),
        Opened::Inner(frame.len())
    );
    assert_eq!(d, frame);
    tap.send_to(&frame, c.addr).unwrap();
    c.rx.set_read_timeout(Some(PATIENCE)).unwrap();
    let (_, envelope, _) = c.rx.recv().unwrap();
    assert_eq!(envelope, b"plain");
    assert_eq!(c.sealing().counts().plaintext_admitted, 2);
}

#[test]
fn traffic_continues_across_rekeys_with_nothing_lost() {
    let config = SealingConfig::new().with_rekey_after(Duration::from_millis(150));
    let (mut a, b) = connected(&config);
    let b_sealing = b.sealing().clone();
    let receiving = Receiving::start(b.rx);
    const N: u64 = 400;
    let start = Instant::now();
    for i in 0..N {
        a.tx.send_to(
            start.elapsed().as_nanos() as u64,
            &pulse(i),
            b"steady",
            b.addr,
        )
        .unwrap();
        thread::sleep(Duration::from_millis(2));
    }
    wait_until("every frame", || receiving.count() as u64 == N);
    let (_, got) = receiving.finish();
    let seqs: Vec<u64> = got.iter().map(|(_, _, m)| m.seq).collect();
    assert_eq!(
        seqs,
        (0..N).collect::<Vec<_>>(),
        "each frame once, in order"
    );
    let (ca, cb) = (a.sealing().counts(), b_sealing.counts());
    assert!(
        ca.sessions_established >= 3 && cb.sessions_established >= 3,
        "two rekeys at least: {ca:?} {cb:?}"
    );
    assert_eq!(refusals(&SealCounts::default(), &ca), 0, "{ca:?}");
    assert_eq!(refusals(&SealCounts::default(), &cb), 0, "{cb:?}");
}

#[test]
fn removing_a_peer_from_the_allowlist_ends_its_sessions() {
    let (mut a, b) = connected(&SealingConfig::new());
    assert!(b.sealing().has_session(&a.key));
    b.sealing().set_allowlist(Allowlist::new());
    assert!(!b.sealing().has_session(&a.key));
    // What the initiator still sends is refused.
    a.tx.send_to(0, &pulse(0), b"gone", b.addr).unwrap();
    let mut rx = b.rx;
    expect_nothing(&mut rx);
    assert_eq!(b.tx.sealing().unwrap().counts().unknown_session, 1);
}

#[cfg(unix)]
#[test]
fn the_key_file_is_private_and_a_readable_one_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.key");
    let key = NodeKey::load_or_generate(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert_eq!(NodeKey::load(&path).unwrap().public_key(), key.public_key());
    assert_eq!(
        NodeKey::load_or_generate(&path).unwrap().public_key(),
        key.public_key(),
        "a second start loads the key the first made"
    );
    match key.save(&path) {
        Err(SealError::KeyFile { source, .. }) => {
            assert_eq!(source.kind(), std::io::ErrorKind::AlreadyExists);
        }
        other => panic!("saving over the key file: {other:?}"),
    }

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    match NodeKey::load(&path) {
        Err(SealError::KeyFileExposed { mode, .. }) => assert_eq!(mode, 0o644),
        other => panic!("a readable key file was loaded: {other:?}"),
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(
        NodeKey::load(&path),
        Err(SealError::KeyFileExposed { .. })
    ));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
    assert_eq!(NodeKey::load(&path).unwrap().public_key(), key.public_key());
}

/// Send `count` frames from `from` to `to` and see each arrive, `to`'s
/// receiver receiving in a thread.
fn exchange(from: &mut Node, to: Node, count: u64) -> Node {
    let receiving = Receiving::start(to.rx);
    for i in 0..count {
        from.tx
            .send_to(0, &pulse(i), b"either way", to.addr)
            .unwrap();
    }
    wait_until("the frames", || receiving.count() as u64 == count);
    let (rx, _) = receiving.finish();
    Node { rx, ..to }
}

/// Both nodes connect at the same moment: whatever the two handshakes'
/// order on each node, both settle on one session, and traffic still
/// crosses both ways once the replaced sessions' grace has passed.
#[test]
fn nodes_that_connect_to_each_other_at_once_agree_on_a_session() {
    let grace = Duration::from_millis(100);
    let config = SealingConfig::new().with_old_session_grace(grace);
    for _ in 0..10 {
        let (a, b) = nodes(&config);
        let (sa, sb) = (a.sealing().clone(), b.sealing().clone());
        let (ka, kb, aa, ab) = (a.key, b.key, a.addr, b.addr);
        let (ra, rb) = (Receiving::start(a.rx), Receiving::start(b.rx));
        let ta = thread::spawn(move || sa.connect(ab, &kb, PATIENCE));
        let tb = thread::spawn(move || sb.connect(aa, &ka, PATIENCE));
        ta.join().unwrap().unwrap();
        tb.join().unwrap().unwrap();
        let (rx_a, _) = ra.finish();
        let (rx_b, _) = rb.finish();
        let (mut a, mut b) = (Node { rx: rx_a, ..a }, Node { rx: rx_b, ..b });
        // Past the grace, any session one side still sent on and the other
        // had replaced would be gone.
        thread::sleep(grace * 3);
        let settled = (a.sealing().counts(), b.sealing().counts());
        // Crossed initiations: the lower key's stood, the other was dropped.
        assert!(settled.0.handshakes_refused + settled.1.handshakes_refused <= 1);
        b = exchange(&mut a, b, 8);
        a = exchange(&mut b, a, 8);
        b = exchange(&mut a, b, 8);
        let (ca, cb) = (a.sealing().counts(), b.sealing().counts());
        assert_eq!(refusals(&settled.0, &ca), 0, "{ca:?}");
        assert_eq!(refusals(&settled.1, &cb), 0, "{cb:?}");
        assert_eq!(ca.sessions_established, settled.0.sessions_established);
    }
}

/// A node that restarts, its key kept, just after its peer switched
/// sessions connects afresh, and the peer takes the new session.
#[test]
fn a_restarted_node_is_taken_back_at_once() {
    let grace = Duration::from_millis(100);
    let config = SealingConfig::new().with_old_session_grace(grace);
    let (ka, kb) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
    // Whichever key is higher restarts: the case a key-order rule gets
    // wrong.
    let (low, high) = if ka.public_key() < kb.public_key() {
        (ka, kb)
    } else {
        (kb, ka)
    };
    let (pl, ph) = (low.public_key(), high.public_key());
    let a = node(low, &[ph], &config);
    let b = node(high.clone(), &[pl], &config);
    let b_addr = b.addr;
    let b = connect(&a, b, b_addr);
    drop(b);
    // Restarted: the same key on a new socket, at once.
    let b = node(high, &[pl], &config);
    let a_addr = a.addr;
    let mut a = connect(&b, a, a_addr);
    let mut b = b;
    thread::sleep(grace * 3);
    b = exchange(&mut a, b, 8);
    let _ = exchange(&mut b, a, 8);
    assert_eq!(refusals(&SealCounts::default(), &b.sealing().counts()), 0);
}

/// The lower-keyed node sent an initiation where its peer is not, and it
/// was never answered. Once that initiation is no longer fresh (older than
/// a second, the interval at which `connect` sends a fresh one), it no
/// longer counts as crossing: the peer's handshake from its real address is
/// answered at the first try, not refused until the stale initiation lapses
/// at the handshake retry period (five seconds).
#[test]
fn a_stale_initiation_of_the_lower_key_does_not_block_the_peers_handshake() {
    let (ka, kb) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
    let (low, high) = if ka.public_key() < kb.public_key() {
        (ka, kb)
    } else {
        (kb, ka)
    };
    let (pl, ph) = (low.public_key(), high.public_key());
    let config = SealingConfig::new();
    let a = node(low, &[ph], &config);
    let mut b = node(high, &[pl], &config);
    // Where the peer is not: a socket that answers nothing.
    let nowhere = UdpSocket::bind("127.0.0.1:0").unwrap();
    a.sealing()
        .initiate(&b.key, nowhere.local_addr().unwrap())
        .unwrap();
    thread::sleep(Duration::from_millis(1100));

    let a_sealing = a.sealing().clone();
    let answering = Receiving::start(a.rx);
    let started = Instant::now();
    b.sealing()
        .connect(a.addr, &a.key, Duration::from_secs(3))
        .unwrap();
    let took = started.elapsed();
    // A refused first initiation would be sent again only after a second.
    assert!(
        took < Duration::from_millis(900),
        "the handshake took {took:?}"
    );
    wait_until("the lower key to confirm", || a_sealing.has_session(&b.key));
    let (rx, _) = answering.finish();
    let a = Node { rx, ..a };
    let _ = exchange(&mut b, a, 4);
    let counts = a_sealing.counts();
    assert_eq!(counts.handshakes_refused, 0, "{counts:?}");
    assert_eq!(counts.sessions_established, 1, "{counts:?}");
}

/// A 64 KiB envelope of bytes that do not repeat within a run's chunk.
fn message(seed: u8) -> Vec<u8> {
    (0..MAX_MESSAGE)
        .map(|i| (i as u8).wrapping_mul(31) ^ (i >> 8) as u8 ^ seed)
        .collect()
}

#[test]
fn fragments_are_sized_to_leave_room_for_the_seal() {
    let (mut a, _b) = nodes(&SealingConfig::new());
    a.tx.enable_fragmentation();
    assert_eq!(a.tx.max_datagram(), SEALED_INNER_BUDGET);
    a.tx.enable_fec(4);
    assert_eq!(
        a.tx.max_datagram(),
        SEALED_INNER_BUDGET - (MAX_ENVELOPE - FEC_MAX_ENVELOPE)
    );
    assert_eq!(a.tx.envelope_limit(), MAX_MESSAGE);
    // Plaintext sizes are as they were.
    let mut plain = Sender::bind("127.0.0.1:0").unwrap();
    plain.enable_fragmentation();
    assert_eq!(plain.max_datagram(), MTU_BYTES);
    plain.enable_fec(4);
    assert_eq!(
        plain.max_datagram(),
        MTU_BYTES - (MAX_ENVELOPE - FEC_MAX_ENVELOPE)
    );
}

/// A sealed sender with fragmentation on and a sealed receiver with
/// reassembly on, `b` reached through `relay`, which loses what it is told.
fn fragmenting(lose: &[usize]) -> (Node, Node, Relay) {
    let (a, b) = nodes(&SealingConfig::new());
    let relay = Relay::new(b.addr, lose);
    let mut b = connect(&a, b, relay.front);
    let mut a = a;
    a.tx.enable_fragmentation();
    b.rx.enable_reassembly(ReassemblyConfig::default());
    (a, b, relay)
}

/// Every datagram the relay forwarded was sealed and fitted one MTU, and
/// no stretch of `envelope` crossed it in the clear.
fn assert_sealed_on_the_wire(relay: &Relay, envelope: &[u8]) {
    let forwarded = relay.forwarded.lock().unwrap();
    assert!(
        forwarded.len() > MAX_MESSAGE / MTU_BYTES,
        "a run of fragments"
    );
    for d in forwarded.iter() {
        assert!(
            d.len() <= MTU_BYTES,
            "a sealed fragment of {} bytes",
            d.len()
        );
        assert_eq!(
            &d[..5],
            &[0x50, 0x4d, 0x53, 0x57, 2],
            "a sealed-family datagram"
        );
        let stretch = &envelope[1000..1032];
        assert!(
            !d.windows(stretch.len()).any(|w| w == stretch),
            "plaintext on the wire"
        );
    }
}

#[test]
fn a_64_kib_envelope_crosses_sealed_as_a_run_of_fragments() {
    let (mut a, b, relay) = fragmenting(&[]);
    let receiving = Receiving::start(b.rx);
    let big = message(7);
    let first = a.tx.send_to(5, &pulse(1), &big, relay.front).unwrap();
    // A frame after the run, which arrives after it.
    a.tx.send_to(6, &pulse(2), b"after", relay.front).unwrap();
    wait_until("the run and the frame", || receiving.count() == 2);
    let (rx, got) = receiving.finish();
    assert_eq!(got[0].0.chain_step, 1);
    assert_eq!((got[0].2.seq, got[0].2.send_ns), (first, 5));
    assert_eq!(got[0].2.sealed_by, Some(a.key), "a run is its sender's");
    assert!(got[0].1 == big, "the envelope arrived whole and unchanged");
    assert_eq!(got[1].1, b"after");
    assert_eq!(rx.reassembled_count(), 1);
    assert_sealed_on_the_wire(&relay, &big);
    let counts = b.tx.sealing().unwrap().counts();
    assert_eq!(refusals(&SealCounts::default(), &counts), 0, "{counts:?}");
    let fragments = a.tx.next_seq() - 1 - first;
    assert_eq!(
        counts.opened,
        1 + fragments + 1,
        "the keepalive, the run, the frame"
    );
}

#[test]
fn a_sealed_fragment_lost_on_the_way_is_retransmitted_and_the_run_completes() {
    // The keepalive is sealed datagram 0, so 10 is fragment 9.
    let (mut a, mut b, relay) = fragmenting(&[10]);
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut cfg = BackpressureConfig::new(any, any).with_nack(256);
    cfg.target_queue_depth = 1024;
    a.tx.enable_backpressure(cfg.clone()).unwrap();
    cfg.ack_target_addr = a.tx.ack_local_addr().unwrap();
    b.rx.enable_backpressure(cfg).unwrap();
    let receiving = Receiving::start(b.rx);
    let big = message(9);
    a.tx.send_to(0, &pulse(1), &big, relay.front).unwrap();
    // The retransmission goes before a later send, once the NACK is in.
    let mut step = 2;
    wait_until("the lost fragment to be retransmitted", || {
        if a.tx.retransmit_count() == 0 {
            a.tx.send_to(0, &pulse(step), b"later", relay.front)
                .unwrap();
            step += 1;
            thread::sleep(Duration::from_millis(2));
        }
        a.tx.retransmit_count() > 0
    });
    wait_until("the run", || {
        receiving
            .got
            .lock()
            .unwrap()
            .iter()
            .any(|(_, e, _)| e.len() == MAX_MESSAGE)
    });
    let (rx, got) = receiving.finish();
    let run = got.iter().find(|(_, e, _)| e.len() == MAX_MESSAGE).unwrap();
    assert!(run.1 == big, "the envelope arrived whole and unchanged");
    assert_eq!(relay.lost.load(Ordering::Relaxed), 1);
    assert!(rx.nacks_sent() >= 1);
    assert_eq!(
        (rx.reassembled_count(), rx.reassembly_dropped_count()),
        (1, 0)
    );
    assert_sealed_on_the_wire(&relay, &big);
    for counts in [a.sealing().counts(), b.tx.sealing().unwrap().counts()] {
        assert_eq!(refusals(&SealCounts::default(), &counts), 0, "{counts:?}");
    }
}

#[test]
fn a_sealed_fragment_lost_on_the_way_is_rebuilt_from_sealed_parity() {
    // The keepalive is sealed datagram 0, fragments 0 to 3 are 1 to 4 and
    // their parity 5: lose fragment 2.
    let (mut a, mut b, relay) = fragmenting(&[3]);
    a.tx.enable_fec(4);
    b.rx.enable_fec(4, 64);
    let receiving = Receiving::start(b.rx);
    let big = message(11);
    a.tx.send_to(0, &pulse(1), &big, relay.front).unwrap();
    wait_until("the run", || receiving.count() == 1);
    let (rx, got) = receiving.finish();
    assert!(got[0].1 == big, "the envelope arrived whole and unchanged");
    assert_eq!(relay.lost.load(Ordering::Relaxed), 1);
    assert_eq!(rx.fec_rebuilt_fragment_count(), 1);
    assert_eq!(rx.reassembled_count(), 1);
    assert_sealed_on_the_wire(&relay, &big);
    let counts = b.tx.sealing().unwrap().counts();
    assert_eq!(refusals(&SealCounts::default(), &counts), 0, "{counts:?}");
}
