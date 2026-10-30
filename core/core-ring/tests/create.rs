// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `create` means the same thing on every platform.
//!
//! `create` makes a ring under a free name, or attaches to the ring already
//! there as `create_or_open` does, and never resizes, clears or reformats
//! one (macOS's `ftruncate` refuses an object that already has a size).
//! Every constructor that sizes or formats a region computes the size with
//! checked arithmetic, so an absurd capacity is an error rather than a
//! panic or a wrapped size.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_ring::{PulseRing, RingError, HEADER_SIZE, PULSE_SIZE};
use pulse_canon::{Instruction, Pulse};
use std::ffi::CString;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// Descriptor numbers are reused as soon as they are closed, and one test
/// here checks that a descriptor stayed open, so the tests run one at a
/// time.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A shared-memory name unique to this process and test, at most 30 bytes,
/// with nothing left under it by an earlier run.
fn shm_name(tag: &str) -> String {
    let name = format!("/crt-{tag}-{:x}", std::process::id());
    assert!(name.len() <= 30, "{name} is longer than macOS allows");
    PulseRing::unlink(&name).expect("clear the name");
    name
}

/// A new object under `name`, `len` bytes long, or never sized when `len`
/// is `None`: a creator that has not reached `ftruncate` yet.
fn object(name: &str, len: Option<usize>) -> libc::c_int {
    let cname = CString::new(name).unwrap();
    // SAFETY: `cname` is a valid NUL-terminated string for the call.
    let fd = unsafe {
        libc::shm_open(
            cname.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
            0o600,
        )
    };
    assert!(fd >= 0, "shm_open {name} failed");
    if let Some(len) = len {
        // SAFETY: sizes the descriptor opened above; touches no memory.
        let rc = unsafe { libc::ftruncate(fd, len as libc::off_t) };
        assert_eq!(rc, 0, "ftruncate {name} failed");
    }
    fd
}

fn close(fd: libc::c_int) {
    // SAFETY: closes a descriptor this test opened and no ring owns.
    unsafe {
        libc::close(fd);
    }
}

fn fd_is_open(fd: libc::c_int) -> bool {
    // SAFETY: fcntl with F_GETFD reads a flag and touches no memory.
    unsafe { libc::fcntl(fd, libc::F_GETFD) != -1 }
}

/// True when the first `HEADER_SIZE` bytes of the object behind `fd` are
/// all zero: nothing has formatted it.
fn header_is_blank(fd: libc::c_int) -> bool {
    // SAFETY: maps the first HEADER_SIZE bytes of an object this test sized
    // to at least that; the result is checked before use.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            HEADER_SIZE,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED, "mmap failed");
    let mut header = [0u8; HEADER_SIZE];
    // SAFETY: the mapping made above spans HEADER_SIZE readable bytes, and
    // the munmap releases exactly it.
    unsafe {
        std::ptr::copy_nonoverlapping(ptr as *const u8, header.as_mut_ptr(), HEADER_SIZE);
        libc::munmap(ptr, HEADER_SIZE);
    }
    header.iter().all(|&b| b == 0)
}

fn data_pulse(monotonic_nanos: u64) -> Pulse {
    let mut p = Pulse::zeroed();
    p.instruction = Instruction::Data as u16;
    p.monotonic_nanos = monotonic_nanos;
    p
}

fn expect_err(result: Result<PulseRing, RingError>, what: &str) -> RingError {
    match result {
        Err(e) => e,
        Ok(_) => panic!("{what} must be refused"),
    }
}

#[test]
fn create_over_a_live_ring_attaches_and_keeps_its_pulses() {
    let _serial = serial();
    let name = shm_name("live");
    let mut creator = PulseRing::create(&name, 8).expect("create");
    for n in 1..=3 {
        creator.publish(&data_pulse(n));
    }

    let mut second = PulseRing::create(&name, 8).expect("create over a live ring");
    assert_eq!(second.write_count(), 3, "the ring's counters were kept");
    assert_eq!(second.cursor_position(), 3);
    for slot in 0..3u64 {
        let seen = second.read_slot(slot).expect("a published pulse survives");
        assert_eq!(seen.monotonic_nanos, slot + 1);
    }
    // The two handles map one ring.
    second.publish(&data_pulse(4));
    assert_eq!(creator.write_count(), 4);
    assert_eq!(
        creator
            .read_slot(3)
            .expect("seen by the creator")
            .monotonic_nanos,
        4
    );

    // A create that asks for another geometry is refused, not resized.
    match expect_err(PulseRing::create(&name, 4), "a smaller capacity") {
        RingError::LayoutMismatch {
            field: "capacity",
            have: 8,
            need: 4,
        } => {}
        other => panic!("expected a capacity mismatch, got {other:?}"),
    }
    match expect_err(PulseRing::create(&name, 4096), "a larger capacity") {
        RingError::RegionTooSmall { have, need } => assert!(have < need, "{have} < {need}"),
        other => panic!("expected RegionTooSmall, got {other:?}"),
    }
    assert_eq!(
        creator.write_count(),
        4,
        "a refused create changed the ring"
    );
    assert_eq!(creator.read_slot(0).expect("slot 0").monotonic_nanos, 1);

    // The creator owns the name; a handle that attached does not.
    assert!(creator.is_creator(), "the handle that made the ring");
    assert!(!second.is_creator(), "a create that attached");
    assert!(
        !PulseRing::open(&name, 8).expect("open").is_creator(),
        "an open"
    );
    drop(second);
    assert!(
        PulseRing::open(&name, 8).is_ok(),
        "a handle that attached unlinked the name"
    );
    drop(creator);
    match expect_err(
        PulseRing::open(&name, 8),
        "an open after the creator dropped",
    ) {
        RingError::Open(e) => assert_eq!(e, libc::ENOENT),
        other => panic!("expected ENOENT, got {other:?}"),
    }
}

#[test]
fn an_absurd_capacity_is_an_error_not_a_panic_or_a_wrap() {
    let _serial = serial();
    let name = shm_name("absurd");
    let absurd = [
        // Past any usize multiplication.
        u64::MAX,
        // The first capacity whose slots wrap a 64-bit usize.
        (usize::MAX / PULSE_SIZE) as u64 + 1,
        // 2^63 + 64 bytes: a usize, but a negative off_t.
        1 << 56,
        // No slot at all.
        0,
    ];
    for capacity in absurd {
        let attempts = [
            ("create", PulseRing::create(&name, capacity)),
            (
                "create_exclusive",
                PulseRing::create_exclusive(&name, capacity),
            ),
            ("create_or_open", PulseRing::create_or_open(&name, capacity)),
        ];
        for (what, result) in attempts {
            match expect_err(result, what) {
                RingError::InvalidCapacity { capacity: c } => assert_eq!(c, capacity, "{what}"),
                other => panic!("{what}({capacity}): expected InvalidCapacity, got {other:?}"),
            }
        }
        assert!(
            !PulseRing::unlink(&name).unwrap(),
            "a refused create left an object under {name}"
        );
    }

    // The descriptor constructors check the same arithmetic before they
    // touch the descriptor, which stays open and the caller's.
    let fd = object(&name, Some(16 * 1024));
    for capacity in absurd {
        let attempts = [
            (
                "from_fd",
                PulseRing::from_fd(&name, fd, capacity, true, true),
            ),
            (
                "from_fd_v2",
                PulseRing::from_fd_v2(&name, fd, capacity, true, true),
            ),
        ];
        for (what, result) in attempts {
            match expect_err(result, what) {
                RingError::InvalidCapacity { capacity: c } => assert_eq!(c, capacity, "{what}"),
                other => panic!("{what}({capacity}): expected InvalidCapacity, got {other:?}"),
            }
            assert!(fd_is_open(fd), "{what} closed the caller's descriptor");
        }
    }
    assert!(header_is_blank(fd), "a refused from_fd wrote to the region");
    close(fd);
    PulseRing::unlink(&name).unwrap();
}

#[test]
fn create_waits_out_an_object_still_at_size_zero_before_refusing_it() {
    let _serial = serial();
    let name = shm_name("unsized");
    // Made but never sized: a creator that died, or has not yet reached
    // ftruncate, between its shm_open and its sizing.
    let fd = object(&name, None);
    let started = Instant::now();
    match expect_err(PulseRing::create(&name, 4), "an object at size zero") {
        RingError::RegionTooSmall { have: 0, need } => {
            assert_eq!(need, (HEADER_SIZE + 4 * PULSE_SIZE) as u64);
        }
        other => panic!("expected RegionTooSmall at size zero, got {other:?}"),
    }
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(40),
        "a size-zero object must be re-read before it is refused (gave up after {waited:?})"
    );
    close(fd);
    PulseRing::unlink(&name).unwrap();
}
