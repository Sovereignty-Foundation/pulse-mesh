// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! An in-order reader racing a writer that laps it.
//!
//! The writer publishes, as fast as it can, pulses that carry their own
//! write position, into a ring small enough to lap the reader over and over;
//! the reader pauses now and then so that it is lapped, and each time it
//! resumes exactly a capacity behind the writer, in the slot the writer
//! fills next. A pulse returned under a position other than its own, or a
//! position returned twice, is the overrun `read_position` exists to
//! prevent.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_ring::{PositionRead, PulseRing};
use pulse_canon::Pulse;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Raises the flag when dropped, so the writer stops even when a failed
/// assertion unwinds the reader, and the test fails instead of hanging.
struct StopOnDrop<'a>(&'a AtomicBool);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

#[test]
fn a_lapped_reader_never_reads_a_pulse_under_another_position() {
    let name = format!("/rpos-{:x}", std::process::id());
    let mut ring = PulseRing::create(&name, 8).expect("create ring");
    // The reader's own handle: the writer's is borrowed by its thread.
    let reader = PulseRing::open(&name, 8).expect("attach the reader");
    let stop = AtomicBool::new(false);
    let (read, lost) = std::thread::scope(|s| {
        s.spawn(|| {
            let mut position = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let mut pulse = Pulse::zeroed();
                pulse.chain_step = position;
                ring.publish(&pulse);
                position += 1;
            }
        });
        let _stop = StopOnDrop(&stop);
        let (mut read, mut lost, mut position) = (0u64, 0u64, 0u64);
        let started = Instant::now();
        loop {
            let elapsed = started.elapsed();
            let exercised = read > 0 && lost > 0;
            if (exercised && elapsed >= Duration::from_millis(300))
                || elapsed >= Duration::from_secs(10)
            {
                break;
            }
            match reader.read_position(position) {
                PositionRead::Pulse(pulse) => {
                    assert_eq!(
                        pulse.chain_step, position,
                        "a pulse read under another position"
                    );
                    read += 1;
                    position += 1;
                    if position % 256 == 0 {
                        std::thread::sleep(Duration::from_micros(50));
                    }
                }
                PositionRead::Lost { next } => {
                    assert!(next > position, "lost must move the reader forward");
                    lost += next - position;
                    position = next;
                }
                PositionRead::NotWritten => std::hint::spin_loop(),
            }
        }
        (read, lost)
    });
    assert!(
        read > 0 && lost > 0,
        "the writer must lap the reader: {read} read, {lost} lost"
    );
}

/// A position at the top of the `u64` range, on a one-slot ring, is a lap
/// number whose counter does not fit in a `u64`. The readers compute it as
/// the writer advances the counter, wrapping, so the read reports the
/// position not written (or lost) instead of overflowing; a fuzz input with
/// such a cursor in a ring's header found the overflow.
#[test]
fn positions_past_half_the_u64_range_read_without_overflow() {
    for (tag, v2) in [("v1", false), ("v2", true)] {
        let name = format!("/rtop-{tag}-{:x}", std::process::id());
        let ring = if v2 {
            PulseRing::create_exclusive_v2(&name, 1)
        } else {
            PulseRing::create_exclusive(&name, 1)
        }
        .expect("create a one-slot ring");
        for position in [1u64 << 63, (1 << 63) + 1, u64::MAX - 1, u64::MAX] {
            for read in [
                ring.read_position_by_counter(position),
                ring.read_position_by_ready(position),
                ring.read_position(position),
            ] {
                assert!(
                    matches!(read, PositionRead::NotWritten | PositionRead::Lost { .. }),
                    "{tag} position {position}: {read:?}"
                );
            }
        }
    }
}

/// A cursor that runs ahead of its slots, which no writer under the
/// single-writer contract leaves (a bent header, a foreign writer), reads as
/// not written at those positions, since `read_position` reads the slot's
/// counter before the cursor; once the writer laps the slot, the position
/// reads as lost. Neither a duplicate nor a reader stuck for good. A fuzz
/// input with such a region found that the fuzz oracle expected `Lost` here.
#[test]
fn a_cursor_ahead_of_its_slots_reads_as_not_written_until_lapped() {
    let name = format!("/rahead-{:x}", std::process::id());
    let mut ring = PulseRing::create_exclusive(&name, 4).expect("create ring");
    for _ in 0..3 {
        ring.publish(&Pulse::zeroed());
    }
    // The cursor says positions 0..3 are written; slot 0's counter says no
    // write ever completed there.
    ring.slot_seq_atomic(0).store(0, Ordering::Release);
    assert_eq!(ring.cursor_position(), 3);
    assert!(matches!(ring.read_position(0), PositionRead::NotWritten));
    assert!(matches!(ring.read_position(1), PositionRead::Pulse(_)));
    // The writer laps slot 0 (positions 3, 4): position 0 is now lost, with
    // every position up to the oldest the ring holds.
    ring.publish(&Pulse::zeroed());
    ring.publish(&Pulse::zeroed());
    assert!(
        matches!(ring.read_position(0), PositionRead::Lost { next: 1 }),
        "{:?}",
        ring.read_position(0)
    );
}
