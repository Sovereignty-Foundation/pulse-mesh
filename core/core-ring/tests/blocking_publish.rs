// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The blocking publishes wait for the slowest reader, up to a deadline.
//!
//! `publish_blocking` and `publish_batch_blocking` spin until the reader's
//! read cursor leaves room, and return `RingError::Stalled`, with the
//! positions still unread, when the reader has not freed it by their
//! deadline; a reader that keeps up never causes it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_ring::{PositionRead, PulseRing, RingError};
use pulse_canon::Pulse;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// How long the publishes in the stalled cases wait.
const TIMEOUT: Duration = Duration::from_millis(50);

/// How late after its deadline a stalled publish may return on a loaded
/// host. The wait reads the clock every few dozen spins, so an idle host
/// returns within microseconds of the deadline.
const SLACK: Duration = Duration::from_secs(2);

/// Raises the flag when dropped, so the reader stops once the writer is
/// gone, even when a failed assertion unwinds it, and the test fails at once
/// instead of waiting out the reader.
struct FlagOnDrop<'a>(&'a AtomicBool);

impl Drop for FlagOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// A ring name no other test, checkout or concurrent run can share.
fn name(tag: &str) -> String {
    format!("/blk-{tag}-{:x}", std::process::id())
}

/// A pulse carrying `position` in its chain step.
fn marked(position: u64) -> Pulse {
    let mut pulse = Pulse::zeroed();
    pulse.instruction = pulse_canon::Instruction::Data as u16;
    pulse.chain_step = position;
    pulse
}

/// Run `publish` with the writer's handle on a thread of its own, so that a
/// wait with no working deadline fails the test instead of hanging it, fail
/// unless it stalled at its deadline with `unread` positions in flight, and
/// hand the handle back.
fn assert_stalls_at_deadline<F>(
    what: &str,
    unread: u64,
    mut ring: PulseRing,
    publish: F,
) -> PulseRing
where
    F: FnOnce(&mut PulseRing) -> Result<u64, RingError> + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let started = Instant::now();
        let published = publish(&mut ring);
        let _ = tx.send((published, started.elapsed(), ring));
    });
    let Ok((published, elapsed, ring)) = rx.recv_timeout(TIMEOUT + SLACK) else {
        panic!("{what}: still waiting {SLACK:?} after its deadline");
    };
    match published {
        Err(RingError::Stalled {
            in_flight, waited, ..
        }) => {
            assert_eq!(in_flight, unread, "{what}: positions in flight");
            assert!(
                waited >= TIMEOUT && elapsed >= TIMEOUT,
                "{what}: gave up after {waited:?} ({elapsed:?} in all), before its deadline"
            );
        }
        other => panic!("{what}: expected Stalled with {unread} positions unread, got {other:?}"),
    }
    ring
}

#[test]
fn a_blocking_publish_whose_reader_stopped_fails_at_its_deadline() {
    let ring_name = name("one");
    let mut ring = PulseRing::create_exclusive(&ring_name, 8).expect("create ring");
    let reader = PulseRing::open(&ring_name, 8).expect("attach the reader");
    for position in 0..8 {
        ring.publish_blocking(&marked(position), TIMEOUT)
            .expect("an empty ring has room");
    }
    // The reader reads three positions and stops.
    reader.advance_read_cursor(3);
    for position in 8..11 {
        ring.publish_blocking(&marked(position), TIMEOUT)
            .expect("a slot the reader freed");
    }
    // The ring is full, and the reader never frees another slot.
    let mut ring = assert_stalls_at_deadline("publish_blocking", 8, ring, |ring| {
        ring.publish_blocking(&marked(11), TIMEOUT)
    });
    // A zero timeout gives up at once on a full ring.
    let started = Instant::now();
    match ring.publish_blocking(&marked(11), Duration::ZERO) {
        Err(RingError::Stalled { in_flight: 8, .. }) => {}
        other => panic!("expected Stalled from a zero timeout, got {other:?}"),
    }
    assert!(started.elapsed() < SLACK, "a zero timeout waited");
    // Nothing was published, and the call can be retried once the reader
    // resumes.
    assert_eq!((ring.cursor_position(), ring.write_count()), (11, 11));
    reader.advance_read_cursor(4);
    assert_eq!(
        ring.publish_blocking(&marked(11), TIMEOUT)
            .expect("the reader freed a slot"),
        12
    );
}

#[test]
fn a_blocking_batch_whose_reader_stopped_fails_at_its_deadline() {
    let ring_name = name("bat");
    let mut ring = PulseRing::create_exclusive(&ring_name, 8).expect("create ring");
    let reader = PulseRing::open(&ring_name, 8).expect("attach the reader");
    let first: Vec<Pulse> = (0..8).map(marked).collect();
    ring.publish_batch_blocking(&first, TIMEOUT)
        .expect("an empty ring has room");
    // The reader reads three positions and stops: five unread, three free.
    reader.advance_read_cursor(3);
    let second: Vec<Pulse> = (8..12).map(marked).collect();
    let mut ring = assert_stalls_at_deadline("publish_batch_blocking", 5, ring, |ring| {
        let batch: Vec<Pulse> = (8..12).map(marked).collect();
        ring.publish_batch_blocking(&batch, TIMEOUT)
    });
    // Nothing of the batch was published; the three that fit are.
    assert_eq!(
        ring.cursor_position(),
        8,
        "part of the stalled batch was published"
    );
    assert_eq!(
        ring.publish_batch_blocking(&second[..3], TIMEOUT)
            .expect("three pulses fit three free slots"),
        11
    );
    for position in 3..11 {
        match ring.read_position(position) {
            PositionRead::Pulse(pulse) => assert_eq!(pulse.chain_step, position),
            other => panic!("position {position}: {other:?}"),
        }
    }
}

#[test]
fn a_blocking_publish_with_no_deadline_waits_until_the_reader_frees_a_slot() {
    let ring_name = name("max");
    let mut ring = PulseRing::create_exclusive(&ring_name, 8).expect("create ring");
    let reader = PulseRing::open(&ring_name, 8).expect("attach the reader");
    for position in 0..8 {
        ring.publish(&marked(position));
    }
    let (tx, rx) = mpsc::channel();
    let writer = std::thread::spawn(move || {
        let _ = tx.send(ring.publish_blocking(&marked(8), Duration::MAX));
        ring
    });
    assert!(
        rx.recv_timeout(TIMEOUT * 4).is_err(),
        "the publish returned while the ring was full"
    );
    reader.advance_read_cursor(1);
    let published = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the writer resumes once the reader has freed a slot");
    assert_eq!(published.expect("a slot the reader freed"), 9);
    writer.join().expect("writer");
}

#[test]
fn a_reader_that_keeps_up_never_stalls_a_blocking_publish() {
    const CAPACITY: u64 = 8;
    const PULSES: u64 = 100_000;
    // Long enough that only a reader that stopped could exhaust it.
    const KEEP_UP: Duration = Duration::from_secs(5);
    let ring_name = name("keep");
    let mut ring = PulseRing::create_exclusive(&ring_name, CAPACITY).expect("create ring");
    // The reader's own handle: the writer publishes through `ring`.
    let reader = PulseRing::open(&ring_name, CAPACITY).expect("attach the reader");
    let writer_gone = AtomicBool::new(false);
    let waits = std::thread::scope(|s| {
        s.spawn(|| {
            // Reads every position in order and frees each slot once it is
            // read, pausing a little after each, so the writer finds the
            // ring full over and over.
            let mut position = 0u64;
            let give_up = Instant::now() + Duration::from_secs(60);
            while position < PULSES {
                match reader.read_position(position) {
                    PositionRead::Pulse(pulse) => {
                        assert_eq!(pulse.chain_step, position, "a pulse read under another position");
                        position += 1;
                        reader.advance_read_cursor(position);
                        for _ in 0..32 {
                            std::hint::spin_loop();
                        }
                    }
                    PositionRead::NotWritten if writer_gone.load(Ordering::Relaxed) => return,
                    PositionRead::NotWritten => {
                        assert!(Instant::now() < give_up, "the reader starved at {position}");
                        std::hint::spin_loop();
                    }
                    PositionRead::Lost { next } => panic!(
                        "a blocking writer overwrote positions {position}..{next} before they were read"
                    ),
                }
            }
        });
        // Single publishes and batches of every size up to the capacity, in
        // turn; `waits` counts the publishes that found too little room and
        // had to wait for the reader.
        let _gone = FlagOnDrop(&writer_gone);
        let (mut next, mut size, mut waits) = (0u64, 1u64, 0u64);
        while next < PULSES {
            let end = (next + size).min(PULSES);
            let unread = ring
                .cursor_position()
                .saturating_sub(ring.read_cursor_position());
            if unread + (end - next) > CAPACITY {
                waits += 1;
            }
            let published = if end - next == 1 {
                ring.publish_blocking(&marked(next), KEEP_UP)
            } else {
                let batch: Vec<Pulse> = (next..end).map(marked).collect();
                ring.publish_batch_blocking(&batch, KEEP_UP)
            };
            assert_eq!(
                published.expect("a reader that keeps up never stalls the writer"),
                end
            );
            next = end;
            size = size % CAPACITY + 1;
        }
        waits
    });
    assert!(waits > 0, "the writer never had to wait for the reader");
}
