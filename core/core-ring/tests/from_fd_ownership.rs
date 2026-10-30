// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Descriptor ownership for rings built with `from_fd`.
//!
//! `owner=false` means the caller keeps the descriptor, so dropping the
//! ring must leave it open. A `from_fd` ring never `shm_unlink`s its
//! name, because that name is synthetic and may collide with a real
//! object. Rings from `create`/`open` still close the descriptor they
//! opened themselves. A descriptor `from_fd` refuses stays the caller's.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_ring::{PulseRing, RingError, HEADER_SIZE, PULSE_SIZE};
use std::ffi::CString;
use std::sync::Mutex;

/// Descriptor numbers are reused as soon as they are closed, so a test
/// that reasons about one must not run beside another that opens files.
static SERIAL: Mutex<()> = Mutex::new(());

fn fd_is_open(fd: libc::c_int) -> bool {
    // SAFETY: fcntl with F_GETFD reads a flag and touches no memory.
    unsafe { libc::fcntl(fd, libc::F_GETFD) != -1 }
}

fn dup(fd: libc::c_int) -> libc::c_int {
    // SAFETY: dup on a descriptor we own; the result is checked below.
    let d = unsafe { libc::dup(fd) };
    assert!(d >= 0, "dup failed");
    d
}

#[test]
fn owner_false_keeps_the_fd_open_and_never_unlinks() {
    let _serial = SERIAL.lock().unwrap();
    let name = format!("ffo-keep-{}", std::process::id());
    let creator = PulseRing::create(&name, 4).expect("create");
    let dupfd = dup(creator.raw_fd());
    let view = PulseRing::from_fd(&name, dupfd, 4, false, false).expect("from_fd");
    drop(view);
    assert!(
        fd_is_open(dupfd),
        "owner=false must leave the fd to the caller"
    );
    // SAFETY: closing the descriptor this test dup'd above.
    unsafe {
        libc::close(dupfd);
    }
    assert!(
        PulseRing::open(&name, 4).is_ok(),
        "a from_fd ring must not unlink the name"
    );
}

#[test]
fn owner_true_closes_the_fd_but_still_never_unlinks() {
    let _serial = SERIAL.lock().unwrap();
    let name = format!("ffo-own-{}", std::process::id());
    let creator = PulseRing::create(&name, 4).expect("create");
    let dupfd = dup(creator.raw_fd());
    let view = PulseRing::from_fd(&name, dupfd, 4, true, false).expect("from_fd");
    drop(view);
    assert!(!fd_is_open(dupfd), "owner=true must close the fd");
    assert!(
        PulseRing::open(&name, 4).is_ok(),
        "a from_fd ring must not unlink the name"
    );
}

/// A descriptor not open for writing cannot hold a ring, and the mapping
/// says so. On Linux `from_fd` reserves a fresh region's pages before it
/// maps it, which such a descriptor cannot do; that failure must not stand
/// in for the mapping's own refusal as a want of room.
#[test]
fn a_read_only_descriptor_is_refused_by_the_mapping_and_stays_open() {
    let _serial = SERIAL.lock().unwrap();
    let name = format!("ffo-ro-{}", std::process::id());
    let cname = CString::new(name.as_str()).unwrap();
    // SAFETY: plain libc calls on a name this test owns, each checked: a
    // fresh object sized for a ring of four slots, then a second descriptor
    // for it opened read-only.
    let (rw, ro) = unsafe {
        libc::shm_unlink(cname.as_ptr());
        let rw = libc::shm_open(
            cname.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
            0o600,
        );
        assert!(rw >= 0, "shm_open failed");
        let len = (HEADER_SIZE + 4 * PULSE_SIZE) as libc::off_t;
        assert_eq!(libc::ftruncate(rw, len), 0, "ftruncate failed");
        let ro = libc::shm_open(cname.as_ptr(), libc::O_RDONLY, 0);
        assert!(ro >= 0, "shm_open read-only failed");
        (rw, ro)
    };
    match PulseRing::from_fd(&name, ro, 4, true, false) {
        // Linux refuses a writable shared mapping of a read-only
        // descriptor with EACCES, macOS with EPERM.
        Err(RingError::Map(errno)) => assert!(
            errno == libc::EACCES || errno == libc::EPERM,
            "unexpected errno {errno}"
        ),
        Err(other) => panic!("expected the mapping's refusal, got {other:?}"),
        Ok(_) => panic!("a read-only descriptor held a ring"),
    }
    assert!(fd_is_open(ro), "a refused from_fd closed the descriptor");
    // SAFETY: closes the two descriptors this test opened and unlinks the
    // name it created.
    unsafe {
        libc::close(ro);
        libc::close(rw);
        libc::shm_unlink(cname.as_ptr());
    }
}

#[test]
fn open_still_closes_its_own_fd() {
    let _serial = SERIAL.lock().unwrap();
    let name = format!("ffo-open-{}", std::process::id());
    let _creator = PulseRing::create(&name, 4).expect("create");
    let first = PulseRing::open(&name, 4).expect("open").raw_fd();
    for _ in 0..64 {
        drop(PulseRing::open(&name, 4).expect("open"));
    }
    // A leaked descriptor per open would push the number up by 64; a
    // closed one is reused, so it stays where it started.
    let later = PulseRing::open(&name, 4).expect("open").raw_fd();
    assert!(
        later <= first + 8,
        "open leaks descriptors: first {first}, after 64 opens {later}"
    );
}
