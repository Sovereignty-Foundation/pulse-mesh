// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Every publish path that moves the write cursor keeps the ring's overrun
//! rule for every in-order reader.
//!
//! [`PulseRing::read_position`] relies on a rule its code cannot check: a
//! slot is refilled only once the write cursor has reached the position it
//! is refilled for, so the cursor trails a refilled slot by at most one
//! position. `read_position_by_counter` and `read_position_by_ready` rely on
//! the ring being written only through its cursor. `tests/batch_publish.rs`
//! races the batch path; this file races every cursor path against all
//! three readers, and refuses a publish path it does not know, so a new one
//! is raced here before it can merge.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_ring::{PositionRead, PulseRing};
use pulse_canon::Pulse;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const CAPACITY: u64 = 8;
/// A batch one short of the ring: the size that shows a cursor moved once
/// per batch fastest (`tests/batch_publish.rs`).
const BATCH: u64 = 7;
const WAIT: Duration = Duration::from_secs(5);

/// The publish paths that move the write cursor, each raced below.
const CURSOR_PATHS: [&str; 6] = [
    "publish",
    "publish_returning_slot",
    "publish_with_crc",
    "publish_batch",
    "publish_blocking",
    "publish_batch_blocking",
];

/// Publish paths that do not move the write cursor, and why they are not
/// raced: `read_position` tolerates them, and the counter and ready-line
/// readers exclude a ring they write (spec 4.3).
const NON_CURSOR_PATHS: [(&str, &str); 1] = [(
    "publish_at_slot",
    "overwrites one slot in place and moves neither count",
)];

#[test]
fn every_publish_path_is_raced_here_or_excluded_with_a_reason() {
    let source = include_str!("../src/lib.rs");
    let found: Vec<&str> = source
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("pub fn "))
        .filter(|rest| rest.starts_with("publish"))
        .map(|rest| rest.split(['(', '<']).next().unwrap_or(rest))
        .collect();
    for path in &found {
        assert!(
            CURSOR_PATHS.contains(path) || NON_CURSOR_PATHS.iter().any(|(p, _)| p == path),
            "`PulseRing::{path}` is a publish path this file does not race: add it to \
             CURSOR_PATHS and to `publish`'s match, or to NON_CURSOR_PATHS with the reason \
             no in-order reader can be handed another position's pulse through it"
        );
    }
    for path in CURSOR_PATHS
        .iter()
        .chain(NON_CURSOR_PATHS.iter().map(|(p, _)| p))
    {
        assert!(
            found.contains(path),
            "`PulseRing::{path}` is listed here but no longer exists"
        );
    }
}

/// A ring name no other test, checkout or concurrent run can share.
fn name(tag: &str) -> String {
    format!("/pp-{tag}-{:x}", std::process::id())
}

/// A pulse carrying `position` in its chain step.
fn marked(position: u64) -> Pulse {
    let mut pulse = Pulse::zeroed();
    pulse.instruction = pulse_canon::Instruction::Data as u16;
    pulse.chain_step = position;
    pulse
}

/// Raises the flag when dropped, so the writer stops even
/// when a failed assertion unwinds the reader, and the test fails instead
/// of hanging.
struct StopOnDrop<'a>(&'a AtomicBool);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Publish the pulses for positions `next..` through `path`; the next
/// position to publish.
fn publish(ring: &mut PulseRing, path: &str, next: u64) -> u64 {
    match path {
        "publish" => {
            ring.publish(&marked(next));
            next + 1
        }
        "publish_returning_slot" => {
            ring.publish_returning_slot(&marked(next));
            next + 1
        }
        "publish_with_crc" => {
            ring.publish_with_crc(&marked(next));
            next + 1
        }
        "publish_batch" => {
            let pulses: Vec<Pulse> = (next..next + BATCH).map(marked).collect();
            ring.publish_batch(&pulses)
                .expect("the batch fits the ring");
            next + BATCH
        }
        "publish_blocking" => {
            free_room(ring);
            ring.publish_blocking(&marked(next), WAIT)
                .expect("the room was freed");
            next + 1
        }
        "publish_batch_blocking" => {
            let pulses: Vec<Pulse> = (next..next + BATCH).map(marked).collect();
            free_room(ring);
            ring.publish_batch_blocking(&pulses, WAIT)
                .expect("the room was freed");
            next + BATCH
        }
        other => panic!("no race for publish path `{other}`"),
    }
}

/// Report every written position read, on the writer's own handle, so a
/// blocking path never waits while the in-order reader, which never
/// reports, is lapped like any other. Done here rather than by a third
/// spinning thread, which a machine with few cores (the gate's Linux
/// container) can starve past the publish deadline.
fn free_room(ring: &PulseRing) {
    ring.advance_read_cursor(ring.cursor_position());
}

#[derive(Clone, Copy, Debug)]
enum Reader {
    Cursor,
    Counter,
    Ready,
}

impl Reader {
    fn read(self, ring: &PulseRing, position: u64) -> PositionRead {
        match self {
            Reader::Cursor => ring.read_position(position),
            Reader::Counter => ring.read_position_by_counter(position),
            Reader::Ready => ring.read_position_by_ready(position),
        }
    }
}

/// Race `path` against an in-order `reader` that the writer laps over and
/// over. The blocking paths free their own room first (`free_room`), so
/// they never wait while the in-order reader, which never reports, is
/// lapped like any other.
fn race(path: &str, reader_kind: Reader) {
    // Short: macOS caps a shared-memory name at 31 bytes.
    let index = CURSOR_PATHS
        .iter()
        .position(|p| *p == path)
        .expect("a listed path");
    let ring_name = name(&format!("{index}{}", reader_kind as u8));
    let mut ring = match reader_kind {
        Reader::Ready => PulseRing::create_exclusive_v2(&ring_name, CAPACITY),
        Reader::Cursor | Reader::Counter => PulseRing::create_exclusive(&ring_name, CAPACITY),
    }
    .expect("create ring");
    let reader = PulseRing::open_existing(&ring_name).expect("attach the reader");
    let stop = AtomicBool::new(false);
    let what = format!("{path} read by {reader_kind:?}");
    let (read, lost) = std::thread::scope(|s| {
        s.spawn(|| {
            let mut next = 0u64;
            while !stop.load(Ordering::Relaxed) {
                next = publish(&mut ring, path, next);
            }
        });
        let _stop = StopOnDrop(&stop);
        let (mut read, mut lost, mut position) = (0u64, 0u64, 0u64);
        let started = Instant::now();
        loop {
            let elapsed = started.elapsed();
            if (read > 0 && lost > 0 && elapsed >= Duration::from_millis(150))
                || elapsed >= Duration::from_secs(10)
            {
                break;
            }
            match reader_kind.read(&reader, position) {
                PositionRead::Pulse(pulse) => {
                    assert_eq!(
                        pulse.chain_step, position,
                        "{what}: a pulse read under another position"
                    );
                    read += 1;
                    position += 1;
                    // Fall behind now and then, so the writer laps the reader.
                    if position % 256 == 0 {
                        std::thread::sleep(Duration::from_micros(50));
                    }
                }
                PositionRead::Lost { next } => {
                    assert!(next > position, "{what}: lost must move the reader forward");
                    lost += next - position;
                    position = next;
                }
                PositionRead::NotWritten => std::hint::spin_loop(),
            }
        }
        (read, lost)
    });
    let _ = PulseRing::unlink(&ring_name);
    assert!(
        read > 0 && lost > 0,
        "{what}: the writer must lap the reader: {read} read, {lost} lost"
    );
}

#[test]
fn every_cursor_path_keeps_the_rule_for_read_position() {
    for path in CURSOR_PATHS {
        race(path, Reader::Cursor);
    }
}

#[test]
fn every_cursor_path_keeps_the_rule_for_the_counter_reader() {
    for path in CURSOR_PATHS {
        race(path, Reader::Counter);
    }
}

#[test]
fn every_cursor_path_keeps_the_rule_for_the_ready_line_reader() {
    for path in CURSOR_PATHS {
        race(path, Reader::Ready);
    }
}
