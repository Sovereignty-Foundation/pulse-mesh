// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `open_existing` opens a store by name alone.
//!
//! The capacity comes from the store's header, so a process that did not
//! create the store needs no size to open it: it reads and writes the
//! creator's slots through the handle and leaves the name to the creator. A
//! header this build cannot map is refused naming the field, and an object
//! whose creator has not finished making it is waited for, briefly, before
//! it is refused. The raw objects here are formatted by hand from the byte
//! layout in the crate's documentation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_store::{
    default_index_buckets, EnvelopeStore, EnvelopeStoreError, LAYOUT_VERSION, MAX_ENTRY_SIZE,
};
use pulse_canon::PulseEnvelope;
use std::ffi::CString;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// Header bytes, and each slot's 64-byte prefix, per the crate's layout.
const HEADER: usize = 64;
const SLOT: usize = 64 + MAX_ENTRY_SIZE;
const MAGIC: u32 = u32::from_le_bytes(*b"PMES");
const H_MAGIC: usize = 8;
const H_VERSION: usize = 12;
const H_CAPACITY: usize = 16;
const H_MAX_ENTRY: usize = 20;
const H_INDEX_BUCKETS: usize = 40;
/// Bytes per index bucket.
const BUCKET: usize = 32;

/// Bytes a store of `capacity` slots with its default index spans.
fn store_size(capacity: usize) -> usize {
    HEADER + capacity * SLOT + default_index_buckets(capacity) * BUCKET
}
/// `ENOENT` on every platform this crate builds for.
const ENOENT: i32 = 2;

/// A shared-memory name unique to this process and test, at most 30 bytes,
/// with nothing left under it by an earlier run.
fn shm_name(tag: &str) -> String {
    let name = format!("/sto-{tag}-{:x}", std::process::id());
    assert!(name.len() <= 30, "{name} is longer than macOS allows");
    EnvelopeStore::unlink(&name).expect("clear the name");
    name
}

fn envelope(i: u8) -> PulseEnvelope {
    PulseEnvelope::new(1, vec![i; 8])
}

/// A shared-memory object made by hand, as a creator holds it between
/// making the object and publishing its header. Dropping it unmaps,
/// closes and unlinks it.
struct RawObject {
    cname: CString,
    fd: libc::c_int,
    ptr: *mut u8,
    len: usize,
}

impl RawObject {
    /// An object under `name` sized to `len` bytes (none when `len` is
    /// zero, as a creator has it before sizing) and, when sized, mapped.
    fn new(name: &str, len: usize) -> Self {
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
        let mut ptr = std::ptr::null_mut();
        if len > 0 {
            // SAFETY: sizes the object opened above; touches no memory.
            let rc = unsafe { libc::ftruncate(fd, len as libc::off_t) };
            assert_eq!(rc, 0, "ftruncate {name} failed");
            // SAFETY: maps `len` bytes of the object just sized to `len`;
            // the result is checked before use.
            let mapped = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd,
                    0,
                )
            };
            assert_ne!(mapped, libc::MAP_FAILED, "mmap {name} failed");
            ptr = mapped as *mut u8;
        }
        Self {
            cname,
            fd,
            ptr,
            len,
        }
    }

    /// Write one 32-bit header field, little-endian.
    fn set(&self, offset: usize, value: u32) {
        assert!(offset + 4 <= HEADER && self.len >= HEADER);
        // SAFETY: `offset` is a 4-byte-aligned field inside the header,
        // which lies inside this object's live mapping.
        unsafe { (self.ptr.add(offset) as *mut u32).write(value.to_le()) }
    }

    /// Write the version, capacity and entry size, then publish the magic
    /// with release ordering, as a creator does.
    fn format(&self, version: u32, capacity: u32, max_entry: u32) {
        self.set(H_VERSION, version);
        self.set(H_CAPACITY, capacity);
        self.set(H_MAX_ENTRY, max_entry);
        self.set(
            H_INDEX_BUCKETS,
            default_index_buckets(capacity as usize) as u32,
        );
        // SAFETY: bytes 8..12 of the header lie inside the live mapping and
        // are 4-byte aligned from its page-aligned start.
        let magic = unsafe { &*(self.ptr.add(H_MAGIC) as *const AtomicU32) };
        magic.store(MAGIC.to_le(), Ordering::Release);
    }
}

impl Drop for RawObject {
    fn drop(&mut self) {
        // SAFETY: unmaps the mapping `new` made, if any, closes the
        // descriptor it opened and unlinks the name it created; nothing
        // else uses them.
        unsafe {
            if self.len > 0 {
                libc::munmap(self.ptr as *mut libc::c_void, self.len);
            }
            libc::close(self.fd);
            libc::shm_unlink(self.cname.as_ptr());
        }
    }
}

// SAFETY: the mapping and the descriptor are owned by the object and stay
// valid until it drops; the one test that sends it to another thread uses
// it only there until it joins.
unsafe impl Send for RawObject {}

fn expect_mismatch(result: Result<EnvelopeStore, EnvelopeStoreError>, want: (&str, u64, u64)) {
    match result {
        Err(EnvelopeStoreError::LayoutMismatch { field, have, need }) => {
            assert_eq!((field, have, need), want);
        }
        Err(other) => panic!("expected a {} mismatch, got {other:?}", want.0),
        Ok(_) => panic!("a {} mismatch must be refused", want.0),
    }
}

fn expect_too_small(result: Result<EnvelopeStore, EnvelopeStoreError>, need_bytes: u64) {
    match result {
        Err(EnvelopeStoreError::RegionTooSmall { have, need }) => {
            assert_eq!(need, need_bytes);
            assert!(have < need, "{have} >= {need}");
        }
        Err(other) => panic!("expected RegionTooSmall, got {other:?}"),
        Ok(_) => panic!("an object smaller than its store must be refused"),
    }
}

#[test]
fn open_existing_takes_the_creators_capacity_and_shares_its_slots() {
    let name = shm_name("share");
    let creator = EnvelopeStore::create_exclusive(&name, 3).expect("create");
    for i in 0..4 {
        creator.store(&envelope(i)).expect("store");
    }

    let reader = EnvelopeStore::open_existing(&name).expect("open by name alone");
    assert_eq!(reader.capacity(), 3);
    assert_eq!(reader.name(), name);
    assert_eq!(reader.write_cursor(), 4);
    // Four stores into three slots: the first is gone, the rest are there.
    assert!(reader.fetch(&envelope(0).id()).is_none());
    let (got, next) = reader.read_since(0);
    assert_eq!(next, 4);
    let ids: Vec<_> = got.iter().map(|e| e.id()).collect();
    assert_eq!(ids, [1, 2, 3].map(|i| envelope(i).id()));
    // A store through the opened handle lands in the creator's slots.
    assert_eq!(reader.store(&envelope(9)).expect("store through it"), 4);
    assert_eq!(
        creator.fetch(&envelope(9).id()).map(|e| e.id()),
        Some(envelope(9).id())
    );

    // The header holds what the crate's documentation describes.
    let cname = CString::new(name.as_str()).unwrap();
    // SAFETY: `cname` is a valid NUL-terminated string for the call.
    let fd = unsafe { libc::shm_open(cname.as_ptr(), libc::O_RDONLY, 0) };
    assert!(fd >= 0);
    // SAFETY: maps the header of the live store read-only; checked below.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            HEADER,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED);
    let mut header = [0u8; HEADER];
    // SAFETY: copies the HEADER bytes of the mapping made above, then
    // unmaps it and closes the descriptor, which nothing else holds.
    unsafe {
        std::ptr::copy_nonoverlapping(ptr as *const u8, header.as_mut_ptr(), HEADER);
        libc::munmap(ptr, HEADER);
        libc::close(fd);
    }
    assert_eq!(&header[8..12], b"PMES");
    assert_eq!(header[12..16], LAYOUT_VERSION.to_le_bytes());
    assert_eq!(header[16..20], 3u32.to_le_bytes());
    assert_eq!(header[20..24], (MAX_ENTRY_SIZE as u32).to_le_bytes());

    // The opened handle does not own the name: dropping it leaves the
    // store to its creator.
    drop(reader);
    assert_eq!(
        EnvelopeStore::open_existing(&name)
            .expect("still there")
            .capacity(),
        3
    );
    drop(creator);
    assert!(matches!(
        EnvelopeStore::open_existing(&name),
        Err(EnvelopeStoreError::Open(ENOENT))
    ));
}

#[test]
fn open_existing_refuses_a_header_this_build_cannot_map() {
    let name = shm_name("refuse");
    let object = RawObject::new(&name, store_size(1));
    let max_entry = MAX_ENTRY_SIZE as u32;

    object.format(LAYOUT_VERSION, 1, max_entry);
    assert_eq!(
        EnvelopeStore::open_existing(&name)
            .expect("a one-slot store")
            .capacity(),
        1
    );

    object.format(1, 1, max_entry);
    expect_mismatch(
        EnvelopeStore::open_existing(&name),
        ("version", 1, u64::from(LAYOUT_VERSION)),
    );
    object.format(LAYOUT_VERSION, 1, 1024);
    expect_mismatch(
        EnvelopeStore::open_existing(&name),
        ("max_entry", 1024, u64::from(max_entry)),
    );
    object.format(LAYOUT_VERSION, 1, max_entry);
    object.set(H_INDEX_BUCKETS, 3);
    expect_mismatch(EnvelopeStore::open_existing(&name), ("index_buckets", 3, 1));
    object.format(LAYOUT_VERSION, 0, max_entry);
    expect_mismatch(EnvelopeStore::open_existing(&name), ("capacity", 0, 1));
    object.set(H_MAGIC, 0xDEAD_BEEF);
    expect_mismatch(
        EnvelopeStore::open_existing(&name),
        ("magic", 0xDEAD_BEEF, u64::from(MAGIC)),
    );

    // A header that describes more slots than the object holds is refused
    // by the size check, before anything past the object is mapped.
    object.format(LAYOUT_VERSION, 64, max_entry);
    expect_too_small(EnvelopeStore::open_existing(&name), store_size(64) as u64);
}

#[test]
fn open_existing_refuses_what_is_not_a_store_name() {
    let name = shm_name("none");
    assert!(matches!(
        EnvelopeStore::open_existing(&name),
        Err(EnvelopeStoreError::Open(ENOENT))
    ));
    assert!(matches!(
        EnvelopeStore::open_existing("/sto-nul\0x"),
        Err(EnvelopeStoreError::InvalidName)
    ));
}

#[test]
fn an_unfinished_store_is_waited_for_before_it_is_refused() {
    // Made but not yet sized, then sized but not yet formatted: a creator
    // that died there, or one that has not got further yet.
    let name = shm_name("unsized");
    let unsized_object = RawObject::new(&name, 0);
    let started = Instant::now();
    expect_too_small(EnvelopeStore::open_existing(&name), HEADER as u64);
    assert!(
        started.elapsed() >= Duration::from_millis(40),
        "a zero size must be looked at again before it is refused ({:?})",
        started.elapsed()
    );
    drop(unsized_object);

    let name = shm_name("nomagic");
    let blank = RawObject::new(&name, store_size(1));
    let started = Instant::now();
    expect_mismatch(
        EnvelopeStore::open_existing(&name),
        ("magic", 0, u64::from(MAGIC)),
    );
    assert!(
        started.elapsed() >= Duration::from_millis(40),
        "a zero magic must be looked at again before it is refused ({:?})",
        started.elapsed()
    );

    // A creator that publishes the header during the wait is not refused.
    let creator = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(10));
        blank.format(LAYOUT_VERSION, 1, MAX_ENTRY_SIZE as u32);
        blank
    });
    let store = EnvelopeStore::open_existing(&name).expect("the header arrives within the wait");
    assert_eq!(store.capacity(), 1);
    drop(store);
    drop(creator.join().unwrap());
}
