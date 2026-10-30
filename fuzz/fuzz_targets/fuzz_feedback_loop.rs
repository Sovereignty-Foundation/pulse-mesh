// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: the sender's feedback loop, `FeedbackIntake::run`, all that
// the sender's feedback thread does but for its socket and its thread: it
// receives datagrams into its buffer until it is told to stop, takes each
// through the feedback-peer filter and the ACK and NACK formats into the
// cursor and the bounded NACK queue, and counts, and pauses after, every
// receive error that is not a timeout or an interrupted call.
//
// The target plays the socket and the thread's pause. It answers the
// loop's receives, one at a time, from a script the input writes, in
// stretches: datagrams of any length from sources the input picks (the
// peer, another address, the peer's IPv4-mapped form, any port), mostly
// well-formed ACKs and NACKs with any value, sometimes bytes that only
// start like one, or one with bytes after it or cut short, or raw bytes;
// and receive errors, timeouts and interrupted calls among them. It copies
// a datagram into the buffer the loop lends it as a UDP socket does, as
// much as fits, and returns how much it copied. At the end of each stretch
// it sets the stop flag and answers with a timeout; between stretches the
// send path takes some of the queued requests. The input also picks the
// sender's configuration: NACK on or off, the cache capacity that bounds
// the queue, and a feedback peer or none.
//
// The model is the wire format of section 6.2 and the socket's contract,
// not the code: a datagram is an ACK or a NACK when it is 12 bytes, the
// magic (`PMSA`, `PMSN`) and then a little-endian u64, as it was sent, not
// as the loop's buffer cut it. A UDP socket copies what fits in the buffer
// and drops the rest unannounced, so the loop must lend a buffer longer
// than 12 bytes: one only 12 long would pass a longer datagram that starts
// with a well-formed ACK or NACK as one.
//
// Invariants, after every stretch and at every receive:
// - the loop lends the socket a buffer longer than the longest feedback
//   datagram, 12 bytes, so that none is cut short and no longer datagram
//   is cut to look like one;
// - the cursor is the highest ACK cursor received from an admitted source,
//   zero before any: it moves only forward, and only on an ACK;
// - the NACK queue holds exactly the NACKs received from admitted sources
//   while NACK is on, in arrival order, less those the send path took,
//   never more than its bound: a NACK that finds it full is dropped and
//   counted, and the queued ones stay;
// - a datagram from a source the filter does not admit changes nothing but
//   the rejection count; a source and its IPv4-mapped form are one source;
// - a datagram that is neither an ACK nor a NACK, a short one after a
//   longer one included, changes nothing;
// - a receive error that is not a timeout or an interrupted call is
//   counted and paused on, once, before the next receive; a timeout or an
//   interrupted call is neither counted nor paused on;
// - the loop receives until the stop flag is set, whatever the errors, and
//   not once after; nothing else ends it.

#![no_main]

use std::cell::Cell;
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use pulse_mesh_fuzz::{take, udp};
use pulse_wire_udp::backpressure::FeedbackIntake;
use pulse_wire_udp::BackpressureConfig;

/// Most stretches in one input.
const MAX_STRETCHES: usize = 32;
/// Most receives in one stretch.
const MAX_EVENTS: usize = 24;
/// Largest cache capacity drawn.
const MAX_CAPACITY: usize = 48;
/// An ACK or a NACK on the wire: the magic and a u64.
const FEEDBACK_BYTES: usize = 12;

/// The sources a datagram comes from.
const PEERS: [IpAddr; 4] = [
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
    IpAddr::V6(Ipv6Addr::LOCALHOST),
    // 127.0.0.1 in its IPv4-mapped IPv6 form: the same source as the first.
    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001)),
];

/// What a receive returns, but for timeouts and interrupted calls, which
/// only ask the loop to go round again: every error kind the socket could
/// report, and a few more.
const ERRORS: [ErrorKind; 9] = [
    ErrorKind::WouldBlock,
    ErrorKind::TimedOut,
    ErrorKind::Interrupted,
    ErrorKind::ConnectionRefused,
    ErrorKind::ConnectionReset,
    ErrorKind::PermissionDenied,
    ErrorKind::OutOfMemory,
    ErrorKind::InvalidData,
    ErrorKind::Other,
];

/// One receive, as the socket answers it.
enum Event {
    Datagram(Vec<u8>, SocketAddr),
    Error(ErrorKind),
}

/// The sender's feedback state as the specification has it.
struct Model {
    nack: bool,
    cap: usize,
    peer: Option<IpAddr>,
    cursor: u64,
    queue: VecDeque<u64>,
    dropped: u64,
    rejected: u64,
    errors: u64,
}

impl Model {
    /// The loop received `bytes` from `from`.
    fn datagram(&mut self, bytes: &[u8], from: SocketAddr) {
        if self
            .peer
            .is_some_and(|p| udp::source(p) != udp::source(from.ip()))
        {
            self.rejected += 1;
        } else if let Some(cursor) = parse(bytes, *b"PMSA") {
            self.cursor = self.cursor.max(cursor);
        } else if let Some(seq) = parse(bytes, *b"PMSN").filter(|_| self.nack) {
            if self.queue.len() < self.cap {
                self.queue.push_back(seq);
            } else {
                self.dropped += 1;
            }
        }
    }

    /// The loop's receive failed with `kind`.
    fn error(&mut self, kind: ErrorKind) {
        let retry = matches!(
            kind,
            ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
        );
        if !retry {
            self.errors += 1;
        }
    }

    /// What the intake shows matches the model.
    fn check(&self, intake: &FeedbackIntake, errors: &AtomicU64, pauses: u64) {
        assert_eq!(
            intake.recv_cursor(),
            self.cursor,
            "the cursor is not the highest ACK admitted"
        );
        assert_eq!(
            intake.pending_nacks(),
            Vec::from(self.queue.clone()),
            "the queued requests are not the NACKs admitted, in order"
        );
        assert_eq!(intake.nack_drop_count(), self.dropped, "the dropped NACKs");
        assert_eq!(
            intake.rejected_count(),
            self.rejected,
            "the rejected datagrams"
        );
        assert_eq!(
            errors.load(Ordering::Relaxed),
            self.errors,
            "the receive errors counted"
        );
        assert_eq!(pauses, self.errors, "the pauses after receive errors");
    }
}

/// The wire format of section 6.2: 12 bytes, `magic`, then a little-endian
/// u64.
fn parse(bytes: &[u8], magic: [u8; 4]) -> Option<u64> {
    let bytes: &[u8; FEEDBACK_BYTES] = bytes.try_into().ok()?;
    let (head, value) = bytes.split_at(4);
    (head == magic).then(|| u64::from_le_bytes(value.try_into().unwrap_or_default()))
}

fuzz_target!(|data: &[u8]| {
    let _ = fuzz(data);
});

fn fuzz(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
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
    let mut model = Model {
        nack: cfg.nack_enabled,
        cap: capacity.max(1),
        peer,
        cursor: 0,
        queue: VecDeque::new(),
        dropped: 0,
        rejected: 0,
        errors: 0,
    };

    // The script, written before the loop runs, with values around one
    // the input picks.
    let near: u64 = u.arbitrary()?;
    let mut stretches = Vec::new();
    for _ in 0..MAX_STRETCHES {
        if u.is_empty() {
            break;
        }
        let mut events = Vec::new();
        for _ in 0..u.int_in_range(0..=MAX_EVENTS)? {
            events.push(event(&mut u, near)?);
        }
        let budget = u.int_in_range(0..=20usize)?;
        stretches.push((events, budget));
    }

    let mut intake = FeedbackIntake::new(&cfg);
    let errors = AtomicU64::new(0);
    let pauses = Cell::new(0u64);
    for (events, budget) in stretches {
        let stop = AtomicBool::new(false);
        let mut script = events.into_iter();
        let mut ended = false;
        intake.run(
            &stop,
            &errors,
            |buf| {
                assert!(
                    !stop.load(Ordering::Acquire),
                    "the loop received after it was told to stop"
                );
                assert!(
                    buf.len() > FEEDBACK_BYTES,
                    "the loop's buffer of {} bytes cuts feedback short or cuts a longer datagram to look like feedback",
                    buf.len()
                );
                assert_eq!(
                    pauses.get(),
                    model.errors,
                    "the loop received again without pausing after an error, or paused without one"
                );
                match script.next() {
                    Some(Event::Datagram(bytes, from)) => {
                        // A UDP socket copies what fits and drops the rest.
                        let n = bytes.len().min(buf.len());
                        buf[..n].copy_from_slice(&bytes[..n]);
                        // The model judges the datagram as it was sent.
                        model.datagram(&bytes, from);
                        Ok((n, from))
                    }
                    Some(Event::Error(kind)) => {
                        model.error(kind);
                        Err(kind.into())
                    }
                    None => {
                        // The end of the stretch: stop, and let the read
                        // time out, as the sender's drop does.
                        ended = true;
                        stop.store(true, Ordering::Release);
                        Err(ErrorKind::WouldBlock.into())
                    }
                }
            },
            || pauses.set(pauses.get() + 1),
        );
        assert!(ended, "the loop ended before it was told to stop");
        model.check(&intake, &errors, pauses.get());

        // The send path takes up to its budget, oldest first.
        let taken = intake.drain_nacks(budget);
        let want: Vec<u64> = model.queue.drain(..model.queue.len().min(budget)).collect();
        assert_eq!(taken, want, "the send path took other requests");
        model.check(&intake, &errors, pauses.get());
    }
    Ok(())
}

/// One receive: mostly a datagram from any source, sometimes an error.
fn event(u: &mut Unstructured<'_>, near: u64) -> Result<Event> {
    if u.ratio(1, 6)? {
        return Ok(Event::Error(ERRORS[u.choose_index(ERRORS.len())?]));
    }
    let from = SocketAddr::new(PEERS[u.choose_index(PEERS.len())?], u.arbitrary()?);
    let magic = if u.arbitrary()? { *b"PMSA" } else { *b"PMSN" };
    let mut bytes = magic.to_vec();
    match u.int_in_range(0..=5u8)? {
        // A well-formed ACK or NACK.
        0..=2 => bytes.extend_from_slice(&value(u, near)?.to_le_bytes()),
        // One with bytes after it, or cut short.
        3 => {
            bytes.extend_from_slice(&value(u, near)?.to_le_bytes());
            if u.arbitrary()? {
                bytes.extend_from_slice(take(u, 16)?);
            } else {
                bytes.truncate(u.int_in_range(0..=FEEDBACK_BYTES - 1)?);
            }
        }
        // The magic and whatever follows.
        4 => bytes.extend_from_slice(take(u, 16)?),
        // Raw bytes.
        _ => bytes = take(u, 20)?.to_vec(),
    }
    Ok(Event::Datagram(bytes, from))
}

/// An ACK cursor or NACK number: near the sender's, or anywhere.
fn value(u: &mut Unstructured<'_>, near: u64) -> Result<u64> {
    Ok(match u.int_in_range(0..=3u8)? {
        0 => u.arbitrary()?,
        _ => near.wrapping_add_signed(u.int_in_range(-40..=40)?),
    })
}
