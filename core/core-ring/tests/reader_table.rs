// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The reader table (ADR-0019): readers registered beside a ring each see
//! every pulse a blocking publish writes, the slowest setting the writer's
//! pace; a reader whose process is gone is freed when it stalls the writer,
//! and one that is alive is named and can be evicted. The second process in
//! the cross-process tests is this test binary run again, with its role in
//! the environment.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use core_ring::{PositionRead, PulseRing, RingError, READERS_NAME_MAX, READERS_SUFFIX};
use pulse_canon::{Instruction, Pulse};

const ROLE: &str = "RT_TEST_ROLE";
const NAME: &str = "RT_TEST_NAME";
const COUNT: &str = "RT_TEST_COUNT";

/// A ring name private to this process and test, short enough for its
/// table's name.
fn name(tag: &str) -> String {
    let name = format!("/rt-{tag}-{:x}", std::process::id());
    assert!(name.len() + READERS_SUFFIX.len() <= READERS_NAME_MAX);
    name
}

fn step(n: u64) -> Pulse {
    let mut pulse = Pulse::zeroed();
    pulse.instruction = Instruction::Data as u16;
    pulse.chain_step = n;
    pulse
}

/// Read `count` pulses in order from `ring` through a reader registered in
/// its table, checking each is the next step and none is lost; sleep a
/// little every `pause_every` pulses, as a slow reader does.
fn read_all(ring: &PulseRing, count: u64, pause_every: Option<u64>, ready: Option<&Barrier>) {
    let reader = ring.register_reader().expect("register");
    let mut position = reader.position();
    let first = position;
    if let Some(ready) = ready {
        ready.wait();
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    while position < first + count {
        assert!(
            Instant::now() < deadline,
            "the reader stalled at {position}"
        );
        match ring.read_position(position) {
            PositionRead::Pulse(pulse) => {
                assert_eq!(pulse.chain_step, position, "out of order");
                position += 1;
                assert!(reader.advance(position), "the reader was evicted");
                if pause_every.is_some_and(|every| position.is_multiple_of(every)) {
                    std::thread::sleep(Duration::from_micros(200));
                }
            }
            PositionRead::NotWritten => std::hint::spin_loop(),
            PositionRead::Lost { next } => panic!("lost {position}..{next}"),
        }
    }
}

/// Run this binary's `role` in a process of its own on ring `name`.
fn child(role: &str, name: &str, count: u64) -> std::process::Child {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "child_role_entry",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ROLE, role)
        .env(NAME, name)
        .env(COUNT, count.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the child")
}

/// The child's half: `read` registers and reads every pulse; `vanish`
/// registers and exits without freeing its line, as a crashed reader does.
#[test]
fn child_role_entry() {
    let Ok(role) = std::env::var(ROLE) else {
        return;
    };
    let ring = PulseRing::open_existing(&std::env::var(NAME).unwrap()).unwrap();
    match role.as_str() {
        "read" => {
            let count = std::env::var(COUNT).unwrap().parse().unwrap();
            read_all(&ring, count, None, None);
            println!("read {count}");
        }
        "vanish" => {
            let reader = ring.register_reader().unwrap();
            println!("registered on line {}", reader.line());
            std::io::stdout().flush().unwrap();
            // No drop: the line stays claimed by a process that is gone.
            std::process::exit(0);
        }
        other => panic!("unknown role {other}"),
    }
    std::io::stdout().flush().unwrap();
}

#[test]
fn eight_readers_one_slowed_see_every_pulse() {
    const PULSES: u64 = 20_000;
    let name = name("eight");
    let mut writer = PulseRing::create_with_readers(&name, 64, 8).unwrap();
    let ready = Arc::new(Barrier::new(9));
    std::thread::scope(|s| {
        for r in 0..8 {
            let (name, ready) = (name.clone(), Arc::clone(&ready));
            s.spawn(move || {
                let ring = PulseRing::open_existing(&name).unwrap();
                let pause = (r == 3).then_some(500);
                read_all(&ring, PULSES, pause, Some(&ready));
            });
        }
        ready.wait();
        assert_eq!(writer.registered_readers(), 8);
        for n in 0..PULSES {
            writer
                .publish_blocking(&step(n), Duration::from_secs(20))
                .unwrap();
        }
    });
    assert_eq!(
        writer.registered_readers(),
        0,
        "every reader freed its line"
    );
}

#[test]
fn readers_in_other_processes_see_every_pulse() {
    const PULSES: u64 = 5_000;
    let name = name("procs");
    let mut writer = PulseRing::create_with_readers(&name, 32, 4).unwrap();
    let children: Vec<_> = (0..2).map(|_| child("read", &name, PULSES)).collect();
    let deadline = Instant::now() + Duration::from_secs(20);
    while writer.registered_readers() < 2 {
        assert!(Instant::now() < deadline, "the readers never registered");
        std::thread::sleep(Duration::from_millis(1));
    }
    for n in 0..PULSES {
        writer
            .publish_blocking(&step(n), Duration::from_secs(20))
            .unwrap();
    }
    for c in children {
        let out = c.wait_with_output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned()
            + &String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "a reader failed:\n{text}");
        assert!(text.contains(&format!("read {PULSES}")), "{text}");
    }
}

#[test]
fn a_dead_readers_line_is_freed_when_it_stalls_the_writer() {
    let name = name("dead");
    let mut writer = PulseRing::create_with_readers(&name, 8, 2).unwrap();
    let out = child("vanish", &name, 0).wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        writer.registered_readers(),
        1,
        "the dead reader's line is still claimed"
    );
    for n in 0..32 {
        writer
            .publish_blocking(&step(n), Duration::from_secs(5))
            .expect("the dead reader is evicted, not waited for");
    }
    assert_eq!(writer.registered_readers(), 0);
}

#[test]
fn a_live_reader_that_stalls_the_writer_is_named_and_can_be_evicted() {
    let name = name("stall");
    let mut writer = PulseRing::create_with_readers(&name, 8, 2).unwrap();
    let reader = writer.register_reader().unwrap();
    for n in 0..8 {
        writer.publish_blocking(&step(n), Duration::ZERO).unwrap();
    }
    let line = match writer.publish_blocking(&step(8), Duration::from_millis(10)) {
        Err(RingError::Stalled {
            in_flight: 8,
            slowest_reader: Some(line),
            ..
        }) => line,
        other => panic!("expected a stall naming the reader, got {other:?}"),
    };
    assert_eq!(line as usize, reader.line());
    assert!(writer.evict_reader(reader.line()));
    assert!(!reader.is_registered());
    assert!(!reader.advance(100), "an evicted reader moves nothing");
    writer.publish_blocking(&step(8), Duration::ZERO).unwrap();
}

#[test]
fn with_no_reader_registered_a_blocking_publish_does_not_wait() {
    let name = name("none");
    let mut writer = PulseRing::create_with_readers(&name, 8, 2).unwrap();
    for n in 0..100 {
        writer.publish_blocking(&step(n), Duration::ZERO).unwrap();
    }
}

#[test]
fn a_writer_that_opened_the_ring_attaches_to_its_table() {
    let name = name("attach");
    let _creator = PulseRing::create_with_readers(&name, 4, 2).unwrap();
    let mut writer = PulseRing::open_existing(&name).unwrap();
    let _reader = writer.register_reader().unwrap();
    assert!(writer.attach_readers().unwrap());
    for n in 0..4 {
        writer.publish_blocking(&step(n), Duration::ZERO).unwrap();
    }
    assert!(matches!(
        writer.publish_blocking(&step(4), Duration::from_millis(5)),
        Err(RingError::Stalled {
            slowest_reader: Some(_),
            ..
        })
    ));
}

#[test]
fn a_full_table_is_refused_and_a_dropped_reader_frees_its_line() {
    let name = name("full");
    let ring = PulseRing::create_with_readers(&name, 4, 2).unwrap();
    let first = ring.register_reader().unwrap();
    let _second = ring.register_reader().unwrap();
    assert!(matches!(
        ring.register_reader(),
        Err(RingError::ReadersFull { max: 2 })
    ));
    let line = first.line();
    drop(first);
    assert_eq!(ring.register_reader().unwrap().line(), line);
}

#[test]
fn a_ring_without_a_table_has_no_readers() {
    let ring = PulseRing::create_exclusive(&name("plain"), 4).unwrap();
    assert!(matches!(
        ring.register_reader(),
        Err(RingError::NoReaderTable)
    ));
    assert_eq!(ring.registered_readers(), 0);
}

#[test]
fn the_creator_unlinks_the_table_with_the_ring_and_a_stale_table_is_replaced() {
    let name = name("names");
    let table = format!("{name}{READERS_SUFFIX}");
    drop(PulseRing::create_with_readers(&name, 4, 2).unwrap());
    for gone in [&name, &table] {
        assert!(matches!(
            PulseRing::open_existing(gone),
            Err(RingError::Open(libc::ENOENT))
        ));
    }
    // A table left behind by a ring whose name is gone is replaced.
    let left = PulseRing::create_with_readers(&name, 4, 2).unwrap();
    PulseRing::unlink(&name).unwrap();
    std::mem::forget(left);
    let ring = PulseRing::create_with_readers(&name, 4, 3).unwrap();
    let readers: Vec<_> = (0..3).map(|_| ring.register_reader().unwrap()).collect();
    assert_eq!(readers.len(), 3, "the new table has the new ring's lines");
}

#[test]
fn bad_arguments_create_nothing() {
    let name = name("args");
    for max_readers in [0, core_ring::MAX_READERS + 1] {
        assert!(matches!(
            PulseRing::create_with_readers(&name, 4, max_readers),
            Err(RingError::InvalidReaders { max_readers: m }) if m == max_readers
        ));
    }
    let long = format!("/rt-{}", "x".repeat(READERS_NAME_MAX));
    assert!(matches!(
        PulseRing::create_with_readers(&long, 4, 2),
        Err(RingError::NameTooLong { .. })
    ));
    // Neither name was created; the long one cannot even be opened.
    assert!(matches!(
        PulseRing::open_existing(&name),
        Err(RingError::Open(libc::ENOENT))
    ));
    assert!(PulseRing::open_existing(&long).is_err());
}
