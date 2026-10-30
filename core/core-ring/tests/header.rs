// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The ring header describes the ring.
//!
//! Bytes 24..44 of every ring record a magic, the layout version, the
//! capacity and the slot size. An open that asks for another capacity or
//! slot size is refused by the header instead of mapping the wrong slots,
//! `open_existing` needs no capacity at all, and `from_fd` formats a fresh
//! region and validates a populated one. Several objects here are sized
//! larger than the ring formatted in them, so that the size check, which
//! Linux applies to the exact object size and macOS to a whole page, passes
//! on both and only the header can refuse.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_ring::{PulseRing, RingError, HEADER_SIZE, LAYOUT_VERSION, PULSE_SIZE, PULSE_SIZE_V2};
use pulse_canon::{Instruction, Pulse};
use std::sync::atomic::Ordering;
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
    let name = format!("/hdr-{tag}-{:x}", std::process::id());
    assert!(name.len() <= 30, "{name} is longer than macOS allows");
    PulseRing::unlink(&name).expect("clear the name");
    name
}

/// Bytes a ring of `capacity` slots of `slot` bytes spans.
fn ring_len(capacity: usize, slot: usize) -> usize {
    HEADER_SIZE + capacity * slot
}

/// A zero-filled object of `len` bytes under `name`, as a creator has it
/// after sizing and before formatting.
fn fresh_object(name: &str, len: usize) -> libc::c_int {
    let cname = std::ffi::CString::new(name).unwrap();
    // SAFETY: `cname` is a valid NUL-terminated string for the call.
    let fd = unsafe {
        libc::shm_open(
            cname.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
            0o600,
        )
    };
    assert!(fd >= 0, "shm_open {name} failed");
    // SAFETY: sizes the descriptor opened above; touches no memory.
    let rc = unsafe { libc::ftruncate(fd, len as libc::off_t) };
    assert_eq!(rc, 0, "ftruncate {name} failed");
    fd
}

fn dup(fd: libc::c_int) -> libc::c_int {
    // SAFETY: dup on a descriptor this test holds; the result is checked.
    let d = unsafe { libc::dup(fd) };
    assert!(d >= 0, "dup failed");
    d
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

/// Fill every byte of the object but the magic word (24..28) with 0xAB:
/// a region that is still unformatted but whose bytes are not zero.
fn scribble(fd: libc::c_int, len: usize) {
    // SAFETY: maps `len` bytes of an object this test sized to `len`; the
    // result is checked before use.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED, "mmap failed");
    let base = ptr as *mut u8;
    // SAFETY: both ranges lie inside the `len`-byte mapping made above,
    // which nothing else uses yet, and the munmap releases exactly it.
    unsafe {
        std::ptr::write_bytes(base, 0xAB, 24);
        std::ptr::write_bytes(base.add(28), 0xAB, len - 28);
        libc::munmap(ptr, len);
    }
}

/// Every byte of the ring's mapping, header first, copied out.
fn mapped_bytes(ring: &PulseRing) -> Vec<u8> {
    let len = ring.mmap_total_size();
    let mut out = vec![0u8; len];
    // SAFETY: `mmap_addr` is the start of the ring's live mapping of
    // `mmap_total_size` bytes, and nothing writes to it during the copy.
    unsafe {
        std::ptr::copy_nonoverlapping(ring.mmap_addr(), out.as_mut_ptr(), len);
    }
    out
}

/// The ring's 64-byte header, copied out of the mapping.
fn header_bytes(ring: &PulseRing) -> Vec<u8> {
    let mut bytes = mapped_bytes(ring);
    bytes.truncate(HEADER_SIZE);
    bytes
}

fn data_pulse(monotonic_nanos: u64) -> Pulse {
    let mut p = Pulse::zeroed();
    p.instruction = Instruction::Data as u16;
    p.monotonic_nanos = monotonic_nanos;
    p
}

/// One way of opening a ring by name.
type OpenByName = fn(&str) -> Result<PulseRing, RingError>;

fn expect_mismatch(result: Result<PulseRing, RingError>, field: &str, have: u64, need: u64) {
    match result {
        Err(RingError::LayoutMismatch {
            field: f,
            have: h,
            need: n,
        }) => assert_eq!((f, h, n), (field, have, need)),
        Err(other) => panic!("expected a {field} mismatch, got {other:?}"),
        Ok(_) => panic!("a {field} mismatch must be refused"),
    }
}

#[test]
fn open_with_another_capacity_is_refused_naming_capacity() {
    let _serial = serial();

    // Created by name: a smaller request fits the object on every platform.
    let name = shm_name("cap");
    let creator = PulseRing::create_exclusive(&name, 8).expect("create");
    expect_mismatch(PulseRing::open(&name, 4), "capacity", 8, 4);
    let err = PulseRing::open(&name, 4).err().expect("refused");
    assert_eq!(
        err.to_string(),
        "ring header capacity mismatch: the region has 8, the caller expects 4"
    );
    assert_eq!(
        PulseRing::open(&name, 8).expect("same capacity").capacity(),
        8
    );
    drop(creator);

    // Formatted inside an object sized for 32 slots: a larger request fits
    // the object too, on Linux as on macOS, and the header refuses it.
    let name = shm_name("capfd");
    let fd = fresh_object(&name, ring_len(32, PULSE_SIZE));
    let creator = PulseRing::from_fd(&name, fd, 8, true, true).expect("format");
    expect_mismatch(PulseRing::open(&name, 4), "capacity", 8, 4);
    expect_mismatch(PulseRing::open(&name, 16), "capacity", 8, 16);
    assert!(PulseRing::open(&name, 8).is_ok(), "same capacity opens");
    drop(creator);
    PulseRing::unlink(&name).unwrap();
}

#[test]
fn open_existing_takes_the_creators_capacity_and_reads_a_pulse() {
    let _serial = serial();
    let name = shm_name("exist");
    let mut creator = PulseRing::create_exclusive(&name, 12).expect("create");
    let mut pulse = data_pulse(42);
    pulse.envelope_ref = [7; 16];
    assert_eq!(creator.publish(&pulse), 1);

    let reader = PulseRing::open_existing(&name).expect("open by name alone");
    assert_eq!(reader.capacity(), 12);
    assert!(!reader.is_v2());
    assert_eq!(reader.write_count(), 1);
    let seen = reader
        .read_slot(reader.cursor_position() - 1)
        .expect("the published pulse");
    assert_eq!(seen.instruction, Instruction::Data as u16);
    assert_eq!(seen.monotonic_nanos, 42);
    assert_eq!(seen.envelope_ref, [7; 16]);

    // The header holds what the module docs describe, byte for byte.
    let header = header_bytes(&reader);
    assert_eq!(&header[24..28], b"PMSR");
    assert_eq!(header[28..32], LAYOUT_VERSION.to_le_bytes());
    assert_eq!(header[32..40], 12u64.to_le_bytes());
    assert_eq!(header[40..44], (PULSE_SIZE as u32).to_le_bytes());
    assert!(header[44..].iter().all(|&b| b == 0), "44..64 stay zero");
}

#[test]
fn a_version_2_ring_records_its_slot_size_and_a_128_byte_open_is_refused() {
    let _serial = serial();
    let name = shm_name("v2");
    let fd = fresh_object(&name, ring_len(8, PULSE_SIZE_V2));
    let mut creator = PulseRing::from_fd_v2(&name, fd, 8, true, true).expect("format v2");
    assert_eq!(
        header_bytes(&creator)[40..44],
        (PULSE_SIZE_V2 as u32).to_le_bytes()
    );
    // The object also holds eight 128-byte slots, so only the header
    // stands between `open` and a mis-indexed mapping.
    expect_mismatch(
        PulseRing::open(&name, 8),
        "slot_size",
        PULSE_SIZE_V2 as u64,
        PULSE_SIZE as u64,
    );

    creator.publish(&data_pulse(5));
    let reader = PulseRing::open_existing(&name).expect("open as version 2");
    assert!(reader.is_v2());
    assert_eq!(reader.capacity(), 8);
    let ready = reader.ready_line_atomic(0).expect("a version-2 ready line");
    assert_eq!(ready.load(Ordering::Acquire), 1);
    assert_eq!(reader.read_slot(0).expect("the pulse").monotonic_nanos, 5);
    drop(reader);
    drop(creator);
    PulseRing::unlink(&name).unwrap();
}

#[test]
fn from_fd_formats_a_fresh_region_and_validates_a_populated_one() {
    let _serial = serial();
    let name = shm_name("fromfd");
    // Room for four slots of either size, so the size check passes for
    // every view below and the header decides.
    let len = ring_len(4, PULSE_SIZE_V2);
    let fd = fresh_object(&name, len);
    // Dirty bytes around a zero magic: still a fresh region, which the
    // first view formats, clearing the rest of the ring because of `init`.
    scribble(fd, len);
    let mut first = PulseRing::from_fd(&name, fd, 4, false, true).expect("format");
    let header = header_bytes(&first);
    assert_eq!(&header[24..28], b"PMSR");
    assert_eq!(header[28..32], LAYOUT_VERSION.to_le_bytes());
    assert_eq!(header[32..40], 4u64.to_le_bytes());
    assert_eq!(header[40..44], (PULSE_SIZE as u32).to_le_bytes());
    assert!(header[..24].iter().all(|&b| b == 0), "cursors cleared");
    assert!(header[44..].iter().all(|&b| b == 0), "44..64 cleared");
    let slots = &mapped_bytes(&first)[HEADER_SIZE..];
    assert!(slots.iter().all(|&b| b == 0), "slots cleared");
    assert_eq!(first.publish(&data_pulse(9)), 1);

    // A second view validates the header and leaves the ring alone, even
    // when it asks for a zero-fill.
    let second = PulseRing::from_fd(&name, dup(fd), 4, true, true).expect("validate");
    assert_eq!(second.write_count(), 1);
    assert_eq!(
        second
            .read_slot(0)
            .expect("the first view's pulse")
            .monotonic_nanos,
        9
    );

    // A view with another capacity or slot size is refused and leaves its
    // descriptor open, even one it was told to own.
    let other = dup(fd);
    expect_mismatch(
        PulseRing::from_fd(&name, other, 2, true, false),
        "capacity",
        4,
        2,
    );
    assert!(fd_is_open(other), "a refused from_fd closed the descriptor");
    expect_mismatch(
        PulseRing::from_fd_v2(&name, other, 4, true, false),
        "slot_size",
        PULSE_SIZE as u64,
        PULSE_SIZE_V2 as u64,
    );
    assert!(
        fd_is_open(other),
        "a refused from_fd_v2 closed the descriptor"
    );
    close(other);

    drop(second);
    drop(first);
    close(fd);
    PulseRing::unlink(&name).unwrap();
}

#[test]
fn a_region_with_no_magic_is_refused_after_the_wait() {
    let _serial = serial();
    let name = shm_name("nomagic");
    // Sized for a ring but never formatted: a creator that died before
    // publishing its header, or a ring from before this layout.
    let fd = fresh_object(&name, ring_len(4, PULSE_SIZE));
    let opens: [OpenByName; 2] = [|n| PulseRing::open(n, 4), PulseRing::open_existing];
    let magic = u64::from(u32::from_le_bytes(*b"PMSR"));
    for open in opens {
        let started = Instant::now();
        expect_mismatch(open(&name), "magic", 0, magic);
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(40),
            "a zero magic must be re-read before it is refused (gave up after {waited:?})"
        );
    }
    close(fd);
    PulseRing::unlink(&name).unwrap();
}

/// A ring of no slots would divide by its capacity on every read and
/// publish: `open` refuses a capacity of zero before it opens the name,
/// and `open_existing` refuses a header, made by hand, that records one.
#[test]
fn a_ring_of_no_slots_is_never_opened() {
    let _serial = serial();
    let name = shm_name("zero");
    let expect_refused = |result: Result<PulseRing, RingError>| match result {
        Err(RingError::InvalidCapacity { capacity: 0 }) => {}
        Err(other) => panic!("expected InvalidCapacity, got {other:?}"),
        Ok(ring) => panic!("a ring of {} slots opened", ring.capacity()),
    };
    // Nothing under the name yet: the refusal comes before the open.
    expect_refused(PulseRing::open(&name, 0));

    let len = ring_len(4, PULSE_SIZE);
    let fd = fresh_object(&name, len);
    // SAFETY: maps the header of the object just sized to `len` bytes; the
    // result is checked before use.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            HEADER_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED, "mmap failed");
    let base = ptr as *mut u8;
    let fields: [(usize, &[u8]); 4] = [
        (28, &LAYOUT_VERSION.to_le_bytes()),
        (32, &0u64.to_le_bytes()),
        (40, &(PULSE_SIZE as u32).to_le_bytes()),
        (24, b"PMSR"),
    ];
    for (offset, bytes) in fields {
        // SAFETY: each field lies inside the 64-byte header mapped above,
        // which nothing else uses; the magic goes last, as a creator's does.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), base.add(offset), bytes.len()) };
    }
    // SAFETY: unmaps exactly the mapping made above.
    unsafe { libc::munmap(ptr, HEADER_SIZE) };

    expect_refused(PulseRing::open(&name, 0));
    expect_mismatch(PulseRing::open_existing(&name), "capacity", 0, 1);
    close(fd);
    PulseRing::unlink(&name).unwrap();
}
