// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Batched publishing keeps the ring's overrun rule.
//!
//! [`PulseRing::read_position`] relies on every publish path filling a slot
//! first and moving the write cursor after, so that the slot of a position
//! is refilled only once the cursor has reached the next lap. A batch that
//! moved the cursor once, at its end, would let a reader less than a
//! capacity behind read the batch's pulses under the positions a lap
//! earlier; batches of seven on an eight-slot ring show it within seconds.
//!
//! A batch larger than the ring is refused by both batch paths, the
//! blocking one without waiting for room that can never exist.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_ring::{PositionRead, PulseRing, RingError};
use pulse_canon::Pulse;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

/// A ring name no other test, checkout or concurrent run can share.
fn name(tag: &str) -> String {
    format!("/bat-{tag}-{:x}", std::process::id())
}

/// A pulse carrying `position` in its chain step.
fn marked(position: u64) -> Pulse {
    let mut pulse = Pulse::zeroed();
    pulse.instruction = pulse_canon::Instruction::Data as u16;
    pulse.chain_step = position;
    pulse
}

/// Raises the flag when dropped, so the writer stops even when a failed
/// assertion unwinds the reader, and the test fails instead of hanging.
struct StopOnDrop<'a>(&'a AtomicBool);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// What an in-order reader saw while a writer published batches of `batch`
/// pulses into a ring of `capacity` slots for at least `run`.
struct Tally {
    read: u64,
    lost: u64,
    wrong: u64,
    first_wrong: Vec<(u64, u64)>,
}

fn race_batches(tag: &str, capacity: u64, batch: u64, run: Duration) -> Tally {
    let ring_name = name(tag);
    let mut ring = PulseRing::create_exclusive(&ring_name, capacity).expect("create ring");
    // The reader's own handle: the writer's is borrowed by its thread.
    let reader = PulseRing::open(&ring_name, capacity).expect("attach a reader");
    let stop = AtomicBool::new(false);
    std::thread::scope(|s| {
        s.spawn(|| {
            let mut next = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let pulses: Vec<Pulse> = (next..next + batch).map(marked).collect();
                ring.publish_batch(&pulses)
                    .expect("the batch fits the ring");
                next += batch;
            }
        });
        let _stop = StopOnDrop(&stop);
        let mut tally = Tally {
            read: 0,
            lost: 0,
            wrong: 0,
            first_wrong: Vec::new(),
        };
        let mut position = 0u64;
        let started = Instant::now();
        loop {
            let elapsed = started.elapsed();
            let exercised = tally.read > 0 && tally.lost > 0;
            if (exercised && elapsed >= run) || elapsed >= Duration::from_secs(20) {
                break;
            }
            match reader.read_position(position) {
                PositionRead::Pulse(pulse) => {
                    if pulse.chain_step != position {
                        tally.wrong += 1;
                        if tally.first_wrong.len() < 5 {
                            tally.first_wrong.push((position, pulse.chain_step));
                        }
                    }
                    tally.read += 1;
                    position += 1;
                }
                PositionRead::Lost { next } => {
                    assert!(next > position, "lost must move the reader forward");
                    tally.lost += next - position;
                    position = next;
                }
                PositionRead::NotWritten => std::hint::spin_loop(),
            }
        }
        tally
    })
}

/// Fails unless the writer lapped the reader and no read returned a pulse
/// under a position other than its own.
fn assert_clean(what: &str, tally: &Tally) {
    assert!(
        tally.read > 0 && tally.lost > 0,
        "{what}: the writer must lap the reader: {} read, {} lost",
        tally.read,
        tally.lost
    );
    assert_eq!(
        tally.wrong, 0,
        "{what}: {} of {} reads returned a pulse under another position; the \
         first (position asked, position of the pulse returned): {:?}",
        tally.wrong, tally.read, tally.first_wrong
    );
}

#[test]
fn batches_of_seven_on_eight_slots_never_read_a_pulse_under_another_position() {
    let tally = race_batches("7on8", 8, 7, Duration::from_secs(1));
    assert_clean("batches of 7 on 8 slots", &tally);
}

#[test]
fn batches_of_every_size_up_to_the_capacity_keep_the_rule() {
    for batch in [1, 2, 3, 8] {
        let tally = race_batches(&format!("b{batch}"), 8, batch, Duration::from_millis(200));
        assert_clean(&format!("batches of {batch} on 8 slots"), &tally);
    }
}

/// The mark of the pulse `ring` holds at `position`, or `None` for any
/// other outcome.
fn mark_at(ring: &PulseRing, position: u64) -> Option<u64> {
    match ring.read_position(position) {
        PositionRead::Pulse(pulse) => Some(pulse.chain_step),
        _ => None,
    }
}

#[test]
fn a_batch_returns_the_write_number_of_its_last_pulse() {
    let mut ring = PulseRing::create_exclusive(&name("num"), 8).expect("create ring");
    let first: Vec<Pulse> = (0..3).map(marked).collect();
    assert_eq!(ring.publish_batch(&first).expect("fits"), 3);
    ring.publish(&marked(3));
    let second: Vec<Pulse> = (4..8).map(marked).collect();
    assert_eq!(
        ring.publish_batch_blocking(&second, Duration::ZERO)
            .expect("fits"),
        8
    );
    // An empty batch writes nothing and reports the write count.
    assert_eq!(ring.publish_batch(&[]).expect("empty"), 8);
    assert_eq!(
        ring.publish_batch_blocking(&[], Duration::ZERO)
            .expect("empty"),
        8
    );
    assert_eq!((ring.cursor_position(), ring.write_count()), (8, 8));
    for position in 0..8 {
        assert_eq!(mark_at(&ring, position), Some(position));
    }
    // A batch of exactly the capacity overwrites the whole ring, and the
    // reader finds the old lap gone and the new one at its own positions.
    let third: Vec<Pulse> = (8..16).map(marked).collect();
    assert_eq!(ring.publish_batch(&third).expect("fits"), 16);
    assert!(matches!(
        ring.read_position(0),
        PositionRead::Lost { next: 8 }
    ));
    for position in 8..16 {
        assert_eq!(mark_at(&ring, position), Some(position));
    }
}

#[test]
fn a_batch_larger_than_the_ring_is_refused_by_both_variants_without_waiting() {
    let ring_name = name("big");
    let mut ring = PulseRing::create_exclusive(&ring_name, 8).expect("create ring");
    let observer = Arc::new(PulseRing::open(&ring_name, 8).expect("attach the reader"));
    let batch: Vec<Pulse> = (0..9).map(marked).collect();
    match ring.publish_batch(&batch) {
        Err(RingError::BatchTooLarge {
            len: 9,
            capacity: 8,
        }) => {}
        other => panic!("expected BatchTooLarge for 9 pulses in 8 slots, got {other:?}"),
    }
    // The blocking variant: a reader keeps the read
    // cursor at the write cursor, so the ring is never short of room it
    // could free, and the batch still never fits. It is refused before any
    // wait, even with no deadline. The call runs on a thread of its own, so
    // a call that spins fails the test rather than hanging it.
    let stop = Arc::new(AtomicBool::new(false));
    let reader = {
        let (ring, stop) = (Arc::clone(&observer), Arc::clone(&stop));
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                ring.advance_read_cursor(ring.cursor_position());
                std::hint::spin_loop();
            }
        })
    };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(ring.publish_batch_blocking(&batch, Duration::MAX));
    });
    let refused = rx.recv_timeout(Duration::from_secs(10));
    stop.store(true, Ordering::Relaxed);
    reader.join().expect("reader");
    match refused {
        Ok(Err(RingError::BatchTooLarge {
            len: 9,
            capacity: 8,
        })) => {}
        Ok(other) => panic!("expected BatchTooLarge from the blocking variant, got {other:?}"),
        Err(_) => panic!("publish_batch_blocking was still waiting after 10 s"),
    }
    // Neither call wrote anything.
    assert_eq!((observer.cursor_position(), observer.write_count()), (0, 0));
    assert!(matches!(
        observer.read_position(0),
        PositionRead::NotWritten
    ));
}

#[test]
fn a_blocking_batch_waits_until_the_reader_frees_room_for_all_of_it() {
    let ring_name = name("room");
    let mut ring = PulseRing::create_exclusive(&ring_name, 8).expect("create ring");
    let reader = PulseRing::open(&ring_name, 8).expect("attach the reader");
    let full: Vec<Pulse> = (0..8).map(marked).collect();
    assert_eq!(
        ring.publish_batch_blocking(&full, Duration::ZERO)
            .expect("fits"),
        8
    );
    let (tx, rx) = mpsc::channel();
    let writer = std::thread::spawn(move || {
        let next: Vec<Pulse> = (8..11).map(marked).collect();
        let _ = tx.send(ring.publish_batch_blocking(&next, Duration::MAX));
        ring
    });
    // Nothing read: the ring is full and the batch of three waits, with no
    // deadline.
    assert!(
        rx.recv_timeout(Duration::from_millis(100)).is_err(),
        "the batch was published into a full ring"
    );
    // Two read: two free slots are not room for three.
    reader.advance_read_cursor(2);
    assert!(
        rx.recv_timeout(Duration::from_millis(100)).is_err(),
        "a batch of three was published into two free slots"
    );
    assert_eq!(
        reader.cursor_position(),
        8,
        "part of the batch was published"
    );
    // Three read: room for the whole batch.
    reader.advance_read_cursor(3);
    let published = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the writer resumes once the reader has freed room");
    assert_eq!(published.expect("fits"), 11);
    writer.join().expect("writer");
    for position in 3..11 {
        assert_eq!(mark_at(&reader, position), Some(position));
    }
}
