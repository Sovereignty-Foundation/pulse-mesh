// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Version-2 rings made by name, and readers that watch each slot's ready
//! line (`read_position_by_ready`): every position comes back once, as
//! itself, or is reported lost, as with the counter read.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_ring::{PositionRead, PulseRing};
use pulse_canon::Pulse;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// A ring name no other test or concurrent run can share.
fn name(tag: &str) -> String {
    format!("/rdy-{tag}-{:x}", std::process::id())
}

/// A pulse carrying `mark` in its chain step.
fn marked(mark: u64) -> Pulse {
    let mut pulse = Pulse::zeroed();
    pulse.chain_step = mark;
    pulse
}

/// The mark of the pulse a read returned, or `None` for any other outcome.
fn mark(read: PositionRead) -> Option<u64> {
    match read {
        PositionRead::Pulse(pulse) => Some(pulse.chain_step),
        _ => None,
    }
}

/// Unlinks the ring's name when dropped, so a failed assertion leaves no
/// object behind in `/dev/shm`.
struct Unlink(String);

impl Drop for Unlink {
    fn drop(&mut self) {
        let _ = PulseRing::unlink(&self.0);
    }
}

#[test]
fn a_version_2_ring_is_made_by_name_and_any_reader_opens_it() {
    let n = name("open");
    let _unlink = Unlink(n.clone());
    let ring = PulseRing::create_exclusive_v2(&n, 8).expect("create a v2 ring");
    assert!(ring.is_v2());
    assert!(ring.ready_line_atomic(0).is_some());
    let reader = PulseRing::open_existing(&n).expect("open it");
    assert!(reader.is_v2());
    assert_eq!(reader.capacity(), 8);
    assert!(
        PulseRing::open(&n, 8).is_err(),
        "an open that expects 128-byte slots refuses it"
    );
}

#[test]
fn each_position_comes_back_once_in_order() {
    let n = name("order");
    let _unlink = Unlink(n.clone());
    let mut ring = PulseRing::create_exclusive_v2(&n, 8).expect("create a v2 ring");
    let reader = PulseRing::open_existing(&n).expect("open it");
    for m in 0..5 {
        ring.publish(&marked(m));
    }
    for position in 0..5 {
        assert_eq!(
            mark(reader.read_position_by_ready(position)),
            Some(position)
        );
    }
    assert!(matches!(
        reader.read_position_by_ready(5),
        PositionRead::NotWritten
    ));
}

#[test]
fn the_ready_line_counts_the_writes_of_its_slot() {
    let n = name("count");
    let _unlink = Unlink(n.clone());
    let mut ring = PulseRing::create_exclusive_v2(&n, 8).expect("create a v2 ring");
    for m in 0..20 {
        ring.publish(&marked(m));
    }
    // Slot 0 took positions 0, 8 and 16; slot 7 took 7 and 15.
    let ready = |slot| {
        ring.ready_line_atomic(slot)
            .unwrap()
            .load(Ordering::Acquire)
    };
    assert_eq!(ready(0), 3);
    assert_eq!(ready(7), 2);
}

#[test]
fn a_lapped_reader_resumes_at_the_oldest_position_held() {
    let n = name("lap");
    let _unlink = Unlink(n.clone());
    let mut ring = PulseRing::create_exclusive_v2(&n, 8).expect("create a v2 ring");
    for m in 0..20 {
        ring.publish(&marked(m));
    }
    assert!(matches!(
        ring.read_position_by_ready(0),
        PositionRead::Lost { next: 12 }
    ));
    for position in 12..20 {
        assert_eq!(mark(ring.read_position_by_ready(position)), Some(position));
    }
    assert!(matches!(
        ring.read_position_by_ready(20),
        PositionRead::NotWritten
    ));
}

#[test]
fn on_a_version_1_ring_it_reads_by_the_counter() {
    let n = name("v1");
    let _unlink = Unlink(n.clone());
    let mut ring = PulseRing::create_exclusive(&n, 8).expect("create a v1 ring");
    assert!(ring.ready_line_atomic(0).is_none());
    for m in 0..3 {
        ring.publish(&marked(m));
    }
    for position in 0..3 {
        assert_eq!(mark(ring.read_position_by_ready(position)), Some(position));
    }
    assert!(matches!(
        ring.read_position_by_ready(3),
        PositionRead::NotWritten
    ));
}

/// Raises the flag when dropped, so the writer stops even when a failed
/// assertion unwinds the reader, and the test fails instead of hanging.
struct StopOnDrop<'a>(&'a AtomicBool);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

#[test]
fn a_lapped_ready_reader_never_reads_a_pulse_under_another_position() {
    let n = name("race");
    let _unlink = Unlink(n.clone());
    let mut ring = PulseRing::create_exclusive_v2(&n, 8).expect("create a v2 ring");
    let reader = PulseRing::open_existing(&n).expect("open it");
    let stop = AtomicBool::new(false);
    let (read, lost) = std::thread::scope(|s| {
        s.spawn(|| {
            let mut position = 0u64;
            while !stop.load(Ordering::Relaxed) {
                ring.publish(&marked(position));
                position += 1;
            }
        });
        let _stop = StopOnDrop(&stop);
        let (mut read, mut lost, mut position) = (0u64, 0u64, 0u64);
        let started = Instant::now();
        loop {
            let elapsed = started.elapsed();
            if (read > 0 && lost > 0 && elapsed >= Duration::from_millis(300))
                || elapsed >= Duration::from_secs(10)
            {
                break;
            }
            match reader.read_position_by_ready(position) {
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
