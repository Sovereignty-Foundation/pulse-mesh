// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `create` means the same thing on every platform.
//!
//! `create` makes a region under a free name, or attaches to the region
//! already there as `create_or_open` does. It never resizes or clears an
//! existing object (which would wipe a live region's pulse, and fails on
//! macOS, whose `ftruncate` refuses an object that already has a size),
//! and attaches only to an object whose header its creator has published.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_region::{PulseRegion, ShmError, LAYOUT_VERSION, REGION_SIZE};
use pulse_canon::Pulse;
use std::ffi::CString;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// A shared-memory name unique to this process and test, at most 30 bytes.
fn shm_name(tag: &str) -> String {
    let name = format!("/prc-{tag}-{:x}", std::process::id());
    assert!(name.len() <= 30, "{name} is longer than macOS allows");
    name
}

fn filled(fill: u8) -> Pulse {
    let mut bytes = [fill; 128];
    bytes[..8].copy_from_slice(&[0u8; 8]); // seq_lock word belongs to the region
    Pulse::from_array(&bytes)
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

/// The size of the object behind `fd`, from `fstat(2)`.
fn size_of(fd: libc::c_int) -> libc::off_t {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat writes one `stat` into the buffer, which is read only
    // when it returns 0.
    assert_eq!(unsafe { libc::fstat(fd, st.as_mut_ptr()) }, 0, "fstat");
    // SAFETY: fstat returned 0, so it initialised the buffer.
    unsafe { st.assume_init() }.st_size
}

/// Write a region's header into the object behind `fd`, as a creator
/// does once the object is sized: the layout version, then the magic
/// `PMRG` with release ordering, at bytes 128..136.
fn publish_header(fd: libc::c_int) {
    // SAFETY: maps REGION_SIZE bytes of an object this test sized to at
    // least that; the result is checked before use.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            REGION_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED, "mmap failed");
    let base = ptr as *mut u8;
    // SAFETY: bytes 128..136 lie inside the mapping made above and are
    // 4-byte aligned from its page-aligned start; the words are accessed
    // only as atomics, and the munmap releases exactly that mapping.
    unsafe {
        let version = &*(base.add(132) as *const AtomicU32);
        let magic = &*(base.add(128) as *const AtomicU32);
        version.store(LAYOUT_VERSION.to_le(), Ordering::Relaxed);
        magic.store(u32::from_le_bytes(*b"PMRG").to_le(), Ordering::Release);
        libc::munmap(ptr, REGION_SIZE);
    }
}

fn close_and_unlink(fd: libc::c_int, name: &str) {
    let cname = CString::new(name).unwrap();
    // SAFETY: closes a descriptor this test opened and no region owns, and
    // unlinks the name this test created.
    unsafe {
        libc::close(fd);
        libc::shm_unlink(cname.as_ptr());
    }
}

fn expect_err(result: Result<PulseRegion, ShmError>, what: &str) -> ShmError {
    match result {
        Err(e) => e,
        Ok(_) => panic!("{what} must be refused"),
    }
}

#[test]
fn create_over_a_live_region_attaches_and_keeps_its_pulse() {
    let name = shm_name("live");
    let mut first = PulseRegion::create(&name).expect("create");
    assert_eq!(first.seq_version(), 0, "a new region is never written");
    first.write(&filled(0x33));

    let mut second = PulseRegion::create(&name).expect("create over a live region");
    assert_eq!(second.seq_version(), 2, "the counter was kept");
    let p = second.read().expect("the live region's pulse survives");
    assert!(p.as_bytes()[8..].iter().all(|&b| b == 0x33));

    // The two handles map one region.
    second.write(&filled(0x44));
    let p = first.read().expect("seen through the first handle");
    assert!(p.as_bytes()[8..].iter().all(|&b| b == 0x44));

    // The creator owns the name; a handle that attached does not.
    drop(second);
    assert!(
        PulseRegion::open(&name).is_ok(),
        "a handle that attached unlinked the name"
    );
    drop(first);
    match expect_err(
        PulseRegion::open(&name),
        "an open after the creator dropped",
    ) {
        ShmError::Open(e) => assert_eq!(e, libc::ENOENT),
        other => panic!("expected ENOENT, got {other:?}"),
    }
}

#[test]
fn create_over_a_larger_object_attaches_without_resizing_it() {
    let name = shm_name("big");
    // Three pages' worth: larger than a region on every platform.
    let fd = object(&name, Some(3 * 16 * 1024));
    let before = size_of(fd);
    // Sized but with no header: a creator that has not published it, and
    // may not have reserved its page, is waited for and then refused,
    // without the object being resized or touched.
    let started = Instant::now();
    match expect_err(PulseRegion::create(&name), "an object with no header") {
        ShmError::LayoutMismatch {
            field: "magic",
            have: 0,
            need,
        } => assert_eq!(need, u64::from(u32::from_le_bytes(*b"PMRG"))),
        other => panic!("expected a magic mismatch, got {other:?}"),
    }
    assert!(
        started.elapsed() >= Duration::from_millis(40),
        "a zero magic must be read again before it is refused"
    );
    assert_eq!(size_of(fd), before, "create resized an existing object");

    publish_header(fd);
    let region = PulseRegion::create(&name).expect("create over a larger object");
    assert_eq!(size_of(fd), before, "create resized an existing object");
    assert_eq!(region.seq_version(), 0);
    drop(region);
    close_and_unlink(fd, &name);
}

#[test]
fn create_waits_out_an_object_still_at_size_zero_before_refusing_it() {
    let name = shm_name("unsized");
    // Made but never sized: a creator that died, or has not yet reached
    // ftruncate, between its shm_open and its sizing.
    let fd = object(&name, None);
    let started = Instant::now();
    match expect_err(PulseRegion::create(&name), "an object at size zero") {
        ShmError::RegionTooSmall { have: 0, need } => assert_eq!(need, REGION_SIZE as u64),
        other => panic!("expected RegionTooSmall at size zero, got {other:?}"),
    }
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(40),
        "a size-zero object must be re-read before it is refused (gave up after {waited:?})"
    );
    assert_eq!(size_of(fd), 0, "create sized an object it did not make");
    close_and_unlink(fd, &name);
}
